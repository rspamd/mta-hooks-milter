//! Axum operational HTTP server. Deliberately separate from the milter socket.
use crate::server::Stats;
use axum::{Json, Router, extract::State, http::StatusCode, routing::get};
use serde_json::{Value, json};
use std::sync::{Arc, atomic::Ordering};

pub fn router(stats: Arc<Stats>) -> Router {
    Router::new()
        .route("/healthz", get(|| async { Json(json!({"status":"ok"})) }))
        .route("/readyz", get(ready))
        .route("/metrics", get(metrics))
        .with_state(stats)
}
async fn ready(State(stats): State<Arc<Stats>>) -> (StatusCode, Json<Value>) {
    let ready = stats.ready.load(Ordering::Relaxed);
    (
        if ready {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        },
        Json(json!({"ready":ready})),
    )
}
async fn metrics(State(stats): State<Arc<Stats>>) -> ([(&'static str, &'static str); 1], String) {
    let mut output = String::new();
    for (name, kind, value) in [
        (
            "connections_active",
            "gauge",
            stats.active.load(Ordering::Relaxed),
        ),
        (
            "connections_total",
            "counter",
            stats.connections.load(Ordering::Relaxed),
        ),
        (
            "overload_total",
            "counter",
            stats.overload.load(Ordering::Relaxed),
        ),
        (
            "messages_total",
            "counter",
            stats.messages.load(Ordering::Relaxed),
        ),
        (
            "protocol_errors_total",
            "counter",
            stats.errors.load(Ordering::Relaxed),
        ),
        (
            "policy_errors_total",
            "counter",
            stats.policy_errors.load(Ordering::Relaxed),
        ),
    ] {
        output.push_str(&format!(
            "# TYPE milter_{name} {kind}\nmilter_{name} {value}\n"
        ));
    }
    (
        [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
        output,
    )
}
