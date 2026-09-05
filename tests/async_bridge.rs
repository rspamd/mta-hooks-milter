use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::post,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use bytes::Bytes;
use mta_hooks_milter::{
    hooks::HooksClient,
    http,
    protocol::*,
    server::{self, Config, Policy, PolicyFuture, Stats},
    session::*,
};
use serde_json::{Value, json};
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, DuplexStream, duplex},
    net::{TcpListener, TcpStream, UnixListener, UnixStream},
    sync::{Mutex, Notify},
    time::timeout,
};
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;

async fn send<S: AsyncWrite + Unpin>(s: &mut S, cmd: u8, p: &[u8]) {
    write_frame(s, &Frame::new(cmd, Bytes::copy_from_slice(p)))
        .await
        .unwrap();
}
async fn recv<S: AsyncRead + Unpin>(s: &mut S) -> Frame {
    timeout(Duration::from_secs(3), read_frame(s, 131073))
        .await
        .unwrap()
        .unwrap()
        .unwrap()
}
async fn negotiate<S: AsyncWrite + AsyncRead + Unpin>(s: &mut S, protocol: u32) {
    write_frame(
        s,
        &Options {
            version: 6,
            actions: SUPPORTED_ACTIONS,
            protocol,
        }
        .frame(),
    )
    .await
    .unwrap();
    assert_eq!(recv(s).await.command, b'O');
}
async fn message<S: AsyncWrite + AsyncRead + Unpin>(s: &mut S) {
    for (cmd, p) in [
        (b'M', &b"<>\0"[..]),
        (b'R', &b"<b@example.com>\0"[..]),
        (b'T', &b""[..]),
        (b'L', &b"Subject\0test\0"[..]),
        (b'N', &b""[..]),
        (b'B', &b"hello\r\n"[..]),
    ] {
        send(s, cmd, p).await;
        assert_eq!(recv(s).await.command, b'c');
    }
    send(s, b'D', b"Ei\0queue-1\0").await;
    send(s, b'E', b"").await;
}
struct SlowPolicy {
    started: Arc<Notify>,
}
impl Policy for SlowPolicy {
    fn stages(&self) -> Vec<Stage> {
        vec![Stage::EndMessage]
    }
    fn actions(&self) -> u32 {
        0
    }
    fn evaluate<'a>(&'a self, _: Stage, _: &'a Session) -> PolicyFuture<'a> {
        Box::pin(async move {
            self.started.notify_one();
            std::future::pending().await
        })
    }
}
async fn driver(
    policy: Arc<dyn Policy>,
    config: Config,
) -> (
    DuplexStream,
    tokio::task::JoinHandle<Result<()>>,
    Arc<Stats>,
    CancellationToken,
) {
    let (client, server) = duplex(4096);
    let stats = Arc::new(Stats::default());
    let stop = CancellationToken::new();
    let (s, t) = (stats.clone(), stop.clone());
    let task = tokio::spawn(async move {
        server::handle_connection(server, policy.as_ref(), &config, &s, t).await
    });
    (client, task, stats, stop)
}
#[tokio::test]
async fn policy_timeouts_tempfail_or_continue_and_connection_is_reusable() {
    for fail_open in [false, true] {
        let config = Config {
            policy_timeout: Duration::from_millis(20),
            fail_open,
            ..Default::default()
        };
        let (mut client, task, stats, _) = driver(
            Arc::new(SlowPolicy {
                started: Arc::new(Notify::new()),
            }),
            config,
        )
        .await;
        negotiate(&mut client, 0).await;
        send(&mut client, b'C', b"unknown\0U").await;
        recv(&mut client).await;
        for _ in 0..2 {
            message(&mut client).await;
            assert_eq!(
                recv(&mut client).await.command,
                if fail_open { b'c' } else { b't' }
            );
        }
        assert_eq!(stats.policy_errors.load(Ordering::Relaxed), 2);
        send(&mut client, b'Q', b"").await;
        task.await.unwrap().unwrap();
    }
}
#[tokio::test]
async fn no_reply_negotiation_sends_only_eom_reply() {
    let (mut client, task, _, _) = driver(Arc::new(server::Passthrough), Config::default()).await;
    negotiate(&mut client, u32::MAX).await;
    for (cmd, p) in [
        (b'C', &b"unknown\0U"[..]),
        (b'M', &b"<>\0"[..]),
        (b'R', &b"<a@b>\0"[..]),
        (b'T', &b""[..]),
        (b'N', &b""[..]),
    ] {
        send(&mut client, cmd, p).await;
    }
    assert!(
        timeout(Duration::from_millis(20), read_frame(&mut client, 100))
            .await
            .is_err()
    );
    send(&mut client, b'E', b"").await;
    assert_eq!(recv(&mut client).await, Frame::empty(b'c'));
    send(&mut client, b'Q', b"").await;
    task.await.unwrap().unwrap();
}
#[tokio::test]
async fn stalled_frame_has_absolute_deadline() {
    let (mut client, task, _, _) = driver(
        Arc::new(server::Passthrough),
        Config {
            frame_timeout: Duration::from_millis(20),
            ..Default::default()
        },
    )
    .await;
    use tokio::io::AsyncWriteExt;
    client.write_all(&[0, 0]).await.unwrap();
    assert!(matches!(
        timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap(),
        Err(Error::Timeout)
    ));
}
#[tokio::test]
async fn shutdown_completes_inflight_callback_before_closing() {
    let started = Arc::new(Notify::new());
    let (mut client, task, _, stop) = driver(
        Arc::new(SlowPolicy {
            started: started.clone(),
        }),
        Config {
            policy_timeout: Duration::from_millis(30),
            ..Default::default()
        },
    )
    .await;
    negotiate(&mut client, 0).await;
    send(&mut client, b'C', b"unknown\0U").await;
    recv(&mut client).await;
    message(&mut client).await;
    started.notified().await;
    stop.cancel();
    assert_eq!(recv(&mut client).await, Frame::empty(b't'));
    task.await.unwrap().unwrap();
}

#[derive(Clone)]
struct Mock {
    registrations: Arc<AtomicUsize>,
    requests: Arc<Mutex<Vec<(HeaderMap, Value)>>>,
    response: Value,
    reregister: bool,
}
async fn register(
    State(mock): State<Mock>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    assert_eq!(headers["authorization"], "Bearer test-token");
    assert_eq!(body["inbound"]["stages"], json!(["data"]));
    let n = mock.registrations.fetch_add(1, Ordering::Relaxed);
    (
        StatusCode::CREATED,
        Json(
            json!({"registrationId":format!("reg-{n}"),"status":"active","expiresAt":null,
        "hookEndpoint":"/hook","negotiated":{"serialization":"json","inbound":body["inbound"]}}),
        ),
    )
}
async fn hook(
    State(mock): State<Mock>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    assert_eq!(headers["authorization"], "Bearer test-token");
    let mut requests = mock.requests.lock().await;
    requests.push((headers, body));
    if mock.reregister && requests.len() == 1 {
        return (StatusCode::NOT_FOUND, Json(json!({})));
    }
    (StatusCode::OK, Json(mock.response))
}
async fn scanner(
    response: Value,
    reregister: bool,
) -> (reqwest::Url, Mock, tokio::task::JoinHandle<()>) {
    let mock = Mock {
        registrations: Arc::new(AtomicUsize::new(0)),
        requests: Arc::new(Mutex::new(vec![])),
        response,
        reregister,
    };
    let app = Router::new()
        .route("/register", post(register))
        .route("/hook", post(hook))
        .with_state(mock.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/register", listener.local_addr().unwrap())
        .parse()
        .unwrap();
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (url, mock, task)
}
#[tokio::test]
async fn tcp_milter_to_axum_scanner_to_header_reply_with_registration_recovery() {
    let (url, mock, scanner_task) = scanner(
        json!({"add":[{"path":"/message/headers","value":{"name":"X-Scanned","value":"yes"}}]}),
        true,
    )
    .await;
    let policy = Arc::new(
        HooksClient::new(
            url,
            "test-token".into(),
            "test".into(),
            Duration::from_secs(2),
            true,
        )
        .await
        .unwrap(),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let stats = Arc::new(Stats::default());
    let stop = CancellationToken::new();
    let task = tokio::spawn(server::serve(
        server::Listener::Tcp(listener),
        policy,
        Config::default(),
        stats.clone(),
        stop.clone(),
    ));
    let mut client = TcpStream::connect(address).await.unwrap();
    negotiate(&mut client, 0).await;
    send(&mut client, b'C', b"mx\0\x34\x00\x19\x31\x39\x32.0.2.1\0").await;
    recv(&mut client).await;
    send(&mut client, b'H', b"client.example\0").await;
    recv(&mut client).await;
    message(&mut client).await;
    assert_eq!(
        recv(&mut client).await,
        Frame::new(b'h', Bytes::from_static(b"X-Scanned\0yes\0"))
    );
    assert_eq!(recv(&mut client).await, Frame::empty(b'c'));
    let requests = mock.requests.lock().await;
    assert_eq!(requests.len(), 2);
    assert_eq!(mock.registrations.load(Ordering::Relaxed), 2);
    assert_eq!(
        requests[0].0["x-mta-hooks-request-id"],
        requests[1].0["x-mta-hooks-request-id"]
    );
    assert_ne!(
        requests[0].0["x-mta-hooks-registration"],
        requests[1].0["x-mta-hooks-registration"]
    );
    let req = &requests[1].1;
    assert_eq!(req["queue"]["id"], "queue-1");
    assert!(req["envelope"]["from"]["address"].is_null());
    assert_eq!(
        STANDARD
            .decode(req["rawMessage"].as_str().unwrap())
            .unwrap(),
        b"Subject: test\r\n\r\nhello\r\n"
    );
    drop(requests);
    send(&mut client, b'Q', b"").await;
    stop.cancel();
    task.await.unwrap().unwrap();
    scanner_task.abort();
    assert_eq!(stats.messages.load(Ordering::Relaxed), 1);
    assert_eq!(stats.active.load(Ordering::Relaxed), 0);
}
#[tokio::test]
async fn malformed_hook_response_cannot_partially_mutate_message() {
    let (url, _, scanner_task) = scanner(
        json!({"add":[{"path":"/message/headers","value":{"name":"X-Good","value":"yes"}}],
        "set":[{"path":"/rawMessage","value":"unsupported"}]}),
        false,
    )
    .await;
    let policy = Arc::new(
        HooksClient::new(
            url,
            "test-token".into(),
            "test".into(),
            Duration::from_secs(2),
            true,
        )
        .await
        .unwrap(),
    );
    let (mut client, task, stats, _) = driver(policy, Config::default()).await;
    negotiate(&mut client, 0).await;
    send(&mut client, b'C', b"unknown\0U").await;
    recv(&mut client).await;
    message(&mut client).await;
    assert_eq!(recv(&mut client).await, Frame::empty(b't'));
    assert_eq!(stats.policy_errors.load(Ordering::Relaxed), 1);
    send(&mut client, b'Q', b"").await;
    task.await.unwrap().unwrap();
    scanner_task.abort();
}
#[tokio::test]
async fn refuses_insecure_remote_urls_before_connecting() {
    for url in [
        "http://192.0.2.1/register",
        "http://localhost/register",
        "https://user:password@example.com/register",
    ] {
        assert!(
            HooksClient::new(
                url.parse().unwrap(),
                "test".into(),
                "test".into(),
                Duration::from_secs(1),
                true
            )
            .await
            .is_err()
        );
    }
}
#[tokio::test]
async fn axum_readiness_and_prometheus_routes() {
    let stats = Arc::new(Stats::default());
    let app = http::router(stats.clone());
    let get = |path| {
        axum::http::Request::builder()
            .uri(path)
            .body(axum::body::Body::empty())
            .unwrap()
    };
    assert_eq!(
        app.clone().oneshot(get("/healthz")).await.unwrap().status(),
        200
    );
    assert_eq!(
        app.clone().oneshot(get("/readyz")).await.unwrap().status(),
        503
    );
    stats.ready.store(true, Ordering::Relaxed);
    assert_eq!(
        app.clone().oneshot(get("/readyz")).await.unwrap().status(),
        200
    );
    let response = app.oneshot(get("/metrics")).await.unwrap();
    let body = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    assert!(
        std::str::from_utf8(&body)
            .unwrap()
            .contains("milter_messages_total 0")
    );
}
#[tokio::test]
async fn unix_socket_and_concurrent_connections() {
    let path = std::env::temp_dir().join(format!("milter-{}.sock", uuid::Uuid::new_v4()));
    let listener = UnixListener::bind(&path).unwrap();
    let stats = Arc::new(Stats::default());
    let stop = CancellationToken::new();
    let task = tokio::spawn(server::serve(
        server::Listener::Unix(listener),
        Arc::new(server::Passthrough),
        Config::default(),
        stats.clone(),
        stop.clone(),
    ));
    let mut first = UnixStream::connect(&path).await.unwrap();
    let mut second = UnixStream::connect(&path).await.unwrap();
    negotiate(&mut first, 0).await;
    negotiate(&mut second, 0).await;
    assert_eq!(stats.active.load(Ordering::Relaxed), 2);
    stop.cancel();
    task.await.unwrap().unwrap();
    assert_eq!(stats.active.load(Ordering::Relaxed), 0);
    std::fs::remove_file(&path).unwrap();
}
