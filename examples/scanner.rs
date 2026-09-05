//! Local Axum MTA Hooks scanner fixture; never use this accept-all policy in production.
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, StatusCode},
    routing::post,
};
use serde_json::{Value, json};
use std::sync::Arc;

#[tokio::main]
async fn main() {
    let token = Arc::new(std::env::var("MTA_HOOKS_TOKEN").expect("set MTA_HOOKS_TOKEN"));
    let app = Router::new()
        .route("/register", post(register))
        .route("/hook", post(hook))
        .layer(DefaultBodyLimit::max(40 * 1024 * 1024))
        .with_state(token);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:18080")
        .await
        .unwrap();
    eprintln!("development scanner at http://127.0.0.1:18080/register");
    axum::serve(listener, app).await.unwrap();
}
fn authorized(headers: &HeaderMap, token: &str) -> bool {
    headers.get("authorization").and_then(|h| h.to_str().ok())
        == Some(format!("Bearer {token}").as_str())
}
async fn register(
    State(token): State<Arc<String>>,
    headers: HeaderMap,
    Json(request): Json<Value>,
) -> (StatusCode, Json<Value>) {
    if !authorized(&headers, &token) {
        return (StatusCode::UNAUTHORIZED, Json(json!({})));
    }
    (
        StatusCode::CREATED,
        Json(json!({"registrationId":"development","status":"active",
        "createdAt":chrono::Utc::now().to_rfc3339(),"expiresAt":null,"hookEndpoint":"/hook",
        "negotiated":{"serialization":"json","inbound":request["inbound"]}})),
    )
}
async fn hook(
    State(token): State<Arc<String>>,
    headers: HeaderMap,
    Json(_request): Json<Value>,
) -> (StatusCode, Json<Value>) {
    if !authorized(&headers, &token) {
        return (StatusCode::UNAUTHORIZED, Json(json!({})));
    }
    if headers
        .get("x-mta-hooks-registration")
        .and_then(|h| h.to_str().ok())
        != Some("development")
        || !headers.contains_key("x-mta-hooks-request-id")
    {
        return (StatusCode::BAD_REQUEST, Json(json!({})));
    }
    (
        StatusCode::OK,
        Json(
            json!({"add":[{"path":"/message/headers","value":{"name":"X-MTA-Hooks","value":"scanned"}}]}),
        ),
    )
}
