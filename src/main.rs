use clap::Parser;
use mta_hooks_milter::{
    hooks::HooksClient,
    http,
    server::{self, Config, Listener, Passthrough, Policy, Stats},
};
use std::{
    path::PathBuf,
    sync::{Arc, atomic::Ordering},
    time::Duration,
};
use tokio::net::{TcpListener, UnixListener};
use tokio_util::sync::CancellationToken;

#[derive(Parser)]
#[command(version,about,group(clap::ArgGroup::new("mode").required(true).args(["scanner","passthrough"])))]
struct Args {
    /// Postfix connects to this TCP milter listener.
    #[arg(long, default_value = "127.0.0.1:11332")]
    milter_listen: String,
    /// Unix milter socket instead of TCP. Existing paths are never removed.
    #[arg(long)]
    milter_unix: Option<PathBuf>,
    /// Read-only Axum health/readiness/Prometheus HTTP listener.
    #[arg(long, default_value = "127.0.0.1:8080")]
    http_listen: String,
    /// MTA Hooks registration URL (manual endpoint configuration).
    #[arg(long, requires = "scanner_token")]
    scanner: Option<reqwest::Url>,
    #[arg(long, env = "MTA_HOOKS_TOKEN", hide_env_values = true)]
    scanner_token: Option<String>,
    /// Explicit development mode: accept mail without an HTTP scanner.
    #[arg(long)]
    passthrough: bool,
    /// Permit HTTP to a literal loopback IP for local scanner tests only.
    #[arg(long)]
    insecure_loopback: bool,
    #[arg(long, default_value = "postfix-mta-hooks")]
    name: String,
    #[arg(long,default_value_t=128,value_parser=clap::value_parser!(u32).range(1..))]
    max_connections: u32,
    #[arg(long,default_value_t=25_000_000,value_parser=clap::value_parser!(u32).range(1..))]
    max_message_bytes: u32,
    #[arg(long,default_value_t=20_000,value_parser=clap::value_parser!(u64).range(1..))]
    policy_timeout_ms: u64,
    /// Idle time before the next milter frame starts; 0 leaves it to Postfix.
    #[arg(long, default_value_t = 0)]
    milter_idle_timeout_ms: u64,
    /// Absolute deadline to finish a milter frame once its first byte arrives.
    #[arg(long,default_value_t=60_000,value_parser=clap::value_parser!(u64).range(1..))]
    milter_frame_timeout_ms: u64,
    /// Continue filtering on scanner failure; default is temporary SMTP failure.
    #[arg(long)]
    fail_open: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let args = Args::parse();
    let mut config = Config {
        max_connections: args.max_connections as usize,
        policy_timeout: Duration::from_millis(args.policy_timeout_ms),
        idle_timeout: (args.milter_idle_timeout_ms != 0)
            .then(|| Duration::from_millis(args.milter_idle_timeout_ms)),
        frame_timeout: Duration::from_millis(args.milter_frame_timeout_ms),
        fail_open: args.fail_open,
        ..Config::default()
    };
    config.limits.message_bytes = args.max_message_bytes as usize;
    let policy: Arc<dyn Policy> = if let Some(url) = args.scanner {
        Arc::new(
            HooksClient::new(
                url,
                args.scanner_token.expect("clap requires token"),
                args.name,
                config.policy_timeout,
                args.insecure_loopback,
            )
            .await?,
        )
    } else {
        tracing::warn!("explicit passthrough mode: mail is not scanned");
        Arc::new(Passthrough)
    };
    let listener = if let Some(path) = args.milter_unix.as_ref() {
        Listener::Unix(UnixListener::bind(path)?)
    } else {
        Listener::Tcp(TcpListener::bind(&args.milter_listen).await?)
    };
    let http_listener = TcpListener::bind(&args.http_listen).await?;
    let stats = Arc::new(Stats::default());
    stats.ready.store(true, Ordering::Relaxed);
    let stop = CancellationToken::new();
    let http_stop = stop.clone();
    let mut http_task = tokio::spawn(
        axum::serve(http_listener, http::router(stats.clone()))
            .with_graceful_shutdown(async move { http_stop.cancelled().await })
            .into_future(),
    );
    let mut milter_task = tokio::spawn(server::serve(
        listener,
        policy,
        config,
        stats.clone(),
        stop.clone(),
    ));
    tracing::info!(http=%args.http_listen,"milter and HTTP listeners ready");
    let result = tokio::select! {
        signal=shutdown_signal()=>signal.map_err(|e|e.to_string()),
        r=&mut http_task=>match r {Ok(Ok(()))=>Err("HTTP server stopped".into()),other=>Err(format!("HTTP server: {other:?}"))},
        r=&mut milter_task=>match r {Ok(Ok(()))=>Err("milter server stopped".into()),other=>Err(format!("milter server: {other:?}"))},
    };
    stats.ready.store(false, Ordering::Relaxed);
    stop.cancel();
    if !milter_task.is_finished() {
        milter_task.await??;
    }
    if !http_task.is_finished()
        && tokio::time::timeout(Duration::from_secs(5), &mut http_task)
            .await
            .is_err()
    {
        http_task.abort();
    }
    // Unix paths remain for the service manager to clean up explicitly.
    result.map_err(Into::into)
}
async fn shutdown_signal() -> std::io::Result<()> {
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {r=tokio::signal::ctrl_c()=>r,_=term.recv()=>Ok(())}
}

#[cfg(test)]
mod tests {
    use super::Args;
    use clap::Parser;

    #[test]
    fn milter_deadline_cli_defaults_and_overrides() {
        let defaults = Args::try_parse_from(["bridge", "--passthrough"]).unwrap();
        assert_eq!(defaults.milter_idle_timeout_ms, 0);
        assert_eq!(defaults.milter_frame_timeout_ms, 60_000);
        let args = Args::try_parse_from([
            "bridge",
            "--passthrough",
            "--milter-idle-timeout-ms",
            "600000",
            "--milter-frame-timeout-ms",
            "5000",
        ])
        .unwrap();
        assert_eq!(args.milter_idle_timeout_ms, 600_000);
        assert_eq!(args.milter_frame_timeout_ms, 5_000);
        assert!(
            Args::try_parse_from(["bridge", "--passthrough", "--milter-frame-timeout-ms", "0",])
                .is_err()
        );
    }
}
