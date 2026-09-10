//! Bounded-cardinality operational metrics. No peer, URL, session or message labels.
use crate::protocol::{Error, Result};
use std::{
    fmt::Write,
    sync::{
        Mutex,
        atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering},
    },
};
use tokio::time::Instant;

const FAILURE_KINDS: [&str; 14] = [
    "timeout",
    "connect",
    "request",
    "body",
    "decode",
    "transport",
    "http_status",
    "io",
    "invalid",
    "limit",
    "protocol",
    "capability",
    "upstream",
    "cancelled",
];
const BUCKETS: [f64; 12] = [
    0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1., 5., 20., 60.,
];

#[derive(Default)]
pub struct Stats {
    pub ready: AtomicBool,
    pub active: AtomicU64,
    pub connections: AtomicU64,
    pub overload: AtomicU64,
    pub messages: AtomicU64,
    /// SMFIR_PROGRESS keepalives sent while callbacks were pending.
    pub progress: AtomicU64,
    pub errors: AtomicU64,
    pub policy_errors: AtomicU64,
    /// Hook requests repeated after a transient scanner failure.
    pub hook_retries: AtomicU64,
    pub policy: OperationStats,
    pub registration: OperationStats,
    pub hook: OperationStats,
    pub registration_wait: OperationStats,
    pub deregistration: OperationStats,
    pub drain_graceful: AtomicU64,
    pub drain_forced: AtomicU64,
    pub(crate) listener: AtomicU8,
    connection_failures: FailureCounts,
}

#[derive(Default)]
struct FailureCounts(Mutex<[u64; FAILURE_KINDS.len()]>);
impl FailureCounts {
    fn record(&self, kind: &str) {
        let mut counts = self.0.lock().unwrap_or_else(|e| e.into_inner());
        counts[kind_index(kind)] += 1;
    }
}
fn kind_index(kind: &str) -> usize {
    FAILURE_KINDS
        .iter()
        .position(|&v| v == kind)
        .expect("fixed error category")
}

#[derive(Default)]
struct Measurements {
    buckets: [u64; BUCKETS.len()],
    count: u64,
    sum: f64,
    success: u64,
    failures: [u64; FAILURE_KINDS.len()],
}

#[derive(Default)]
pub struct OperationStats {
    active: AtomicU64,
    values: Mutex<Measurements>,
}
impl OperationStats {
    pub fn begin(&self) -> Observation<'_> {
        self.active.fetch_add(1, Ordering::Relaxed);
        Observation {
            stats: self,
            started: Instant::now(),
            outcome: "cancelled",
        }
    }
    pub fn active(&self) -> u64 {
        self.active.load(Ordering::Relaxed)
    }

    fn render(&self, operation: &str, output: &mut String) {
        let values = self.values.lock().unwrap_or_else(|e| e.into_inner());
        let _ = writeln!(
            output,
            "milter_operations_active{{operation=\"{operation}\"}} {}",
            self.active()
        );
        let _ = writeln!(
            output,
            "milter_operations_total{{operation=\"{operation}\",outcome=\"success\"}} {}",
            values.success
        );
        for (kind, count) in FAILURE_KINDS.iter().zip(values.failures) {
            let _ = writeln!(
                output,
                "milter_operations_total{{operation=\"{operation}\",outcome=\"{kind}\"}} {count}"
            );
        }
        for (bound, count) in BUCKETS.iter().zip(values.buckets) {
            let _ = writeln!(
                output,
                "milter_operation_duration_seconds_bucket{{operation=\"{operation}\",le=\"{bound}\"}} {count}"
            );
        }
        let _ = writeln!(
            output,
            "milter_operation_duration_seconds_bucket{{operation=\"{operation}\",le=\"+Inf\"}} {}",
            values.count
        );
        let _ = writeln!(
            output,
            "milter_operation_duration_seconds_count{{operation=\"{operation}\"}} {}",
            values.count
        );
        let _ = writeln!(
            output,
            "milter_operation_duration_seconds_sum{{operation=\"{operation}\"}} {}",
            values.sum
        );
    }
}

/// Dropped futures still release their gauge and record a cancelled observation.
pub struct Observation<'a> {
    stats: &'a OperationStats,
    started: Instant,
    outcome: &'static str,
}
impl Observation<'_> {
    pub fn finish<T>(self, result: &Result<T>) {
        self.finish_error(result.as_ref().err());
    }
    pub fn finish_error(mut self, error: Option<&Error>) {
        self.outcome = error.map_or("success", Error::kind);
    }
}
impl Drop for Observation<'_> {
    fn drop(&mut self) {
        let elapsed = self.started.elapsed().as_secs_f64();
        let mut values = self.stats.values.lock().unwrap_or_else(|e| e.into_inner());
        values.count += 1;
        values.sum += elapsed;
        for (bound, count) in BUCKETS.iter().zip(&mut values.buckets) {
            if elapsed <= *bound {
                *count += 1;
            }
        }
        if self.outcome == "success" {
            values.success += 1;
        } else {
            values.failures[kind_index(self.outcome)] += 1;
        }
        self.stats.active.fetch_sub(1, Ordering::Relaxed);
    }
}

impl Stats {
    pub(crate) fn connection_error(&self, error: &Error) {
        self.errors.fetch_add(1, Ordering::Relaxed);
        self.connection_failures.record(error.kind());
    }

    pub fn render(&self) -> String {
        let mut output = String::new();
        for (name, kind, value) in [
            (
                "connections_active",
                "gauge",
                self.active.load(Ordering::Relaxed),
            ),
            (
                "connections_total",
                "counter",
                self.connections.load(Ordering::Relaxed),
            ),
            (
                "overload_total",
                "counter",
                self.overload.load(Ordering::Relaxed),
            ),
            (
                "messages_total",
                "counter",
                self.messages.load(Ordering::Relaxed),
            ),
            (
                "progress_total",
                "counter",
                self.progress.load(Ordering::Relaxed),
            ),
            // Retained for compatibility: all connection-driver errors, not only syntax.
            (
                "protocol_errors_total",
                "counter",
                self.errors.load(Ordering::Relaxed),
            ),
            (
                "policy_errors_total",
                "counter",
                self.policy_errors.load(Ordering::Relaxed),
            ),
            (
                "hook_retries_total",
                "counter",
                self.hook_retries.load(Ordering::Relaxed),
            ),
            (
                "ready",
                "gauge",
                u64::from(self.ready.load(Ordering::Relaxed)),
            ),
        ] {
            let _ = writeln!(output, "# TYPE milter_{name} {kind}\nmilter_{name} {value}");
        }
        output.push_str("# TYPE milter_listener_up gauge\n");
        let listener = self.listener.load(Ordering::Relaxed);
        for (transport, id) in [("tcp", 1), ("unix", 2)] {
            let _ = writeln!(
                output,
                "milter_listener_up{{transport=\"{transport}\"}} {}",
                u8::from(listener == id)
            );
        }
        output.push_str("# TYPE milter_drain_total counter\n");
        for (outcome, value) in [
            ("graceful", &self.drain_graceful),
            ("forced", &self.drain_forced),
        ] {
            let _ = writeln!(
                output,
                "milter_drain_total{{outcome=\"{outcome}\"}} {}",
                value.load(Ordering::Relaxed)
            );
        }
        output.push_str("# TYPE milter_connection_failures_total counter\n");
        let failures = self
            .connection_failures
            .0
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        for (kind, value) in FAILURE_KINDS.iter().zip(failures.iter()) {
            let _ = writeln!(
                output,
                "milter_connection_failures_total{{kind=\"{kind}\"}} {value}"
            );
        }
        output.push_str("# TYPE milter_operations_active gauge\n# TYPE milter_operations_total counter\n# TYPE milter_operation_duration_seconds histogram\n");
        for (name, op) in [
            ("policy", &self.policy),
            ("registration", &self.registration),
            ("hook", &self.hook),
            ("registration_wait", &self.registration_wait),
            ("deregistration", &self.deregistration),
        ] {
            op.render(name, &mut output);
        }
        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn histogram_buckets_failures_and_cancellation_are_consistent() {
        let stats = Stats::default();
        let observation = stats.hook.begin();
        assert_eq!(stats.hook.active(), 1);
        tokio::time::advance(std::time::Duration::from_millis(50)).await;
        observation.finish(&Ok(()));
        let observation = stats.hook.begin();
        tokio::time::advance(std::time::Duration::from_millis(200)).await;
        observation.finish::<()>(&Err(Error::Timeout));
        drop(stats.hook.begin());
        assert_eq!(stats.hook.active(), 0);
        let text = stats.render();
        for line in [
            "milter_operation_duration_seconds_bucket{operation=\"hook\",le=\"0.01\"} 1\n",
            "milter_operation_duration_seconds_bucket{operation=\"hook\",le=\"0.05\"} 2\n",
            "milter_operation_duration_seconds_bucket{operation=\"hook\",le=\"0.25\"} 3\n",
            "milter_operation_duration_seconds_bucket{operation=\"hook\",le=\"+Inf\"} 3\n",
            "milter_operation_duration_seconds_count{operation=\"hook\"} 3\n",
            "milter_operation_duration_seconds_sum{operation=\"hook\"} 0.25\n",
            "milter_operations_total{operation=\"hook\",outcome=\"success\"} 1\n",
            "milter_operations_total{operation=\"hook\",outcome=\"timeout\"} 1\n",
            "milter_operations_total{operation=\"hook\",outcome=\"cancelled\"} 1\n",
        ] {
            assert!(text.contains(line), "missing {line}");
        }
        for kind in FAILURE_KINDS {
            assert!(kind_index(kind) < FAILURE_KINDS.len());
        }
    }
}
