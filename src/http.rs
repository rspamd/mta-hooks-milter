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
    (
        [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
        stats.render(),
    )
}
