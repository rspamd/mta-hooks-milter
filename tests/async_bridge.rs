use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::post,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use bytes::Bytes;
use mta_hooks_milter::{
    hooks::{HooksClient, HooksOptions},
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
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, DuplexStream, duplex},
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
        assert_eq!(stats.policy.active(), 0);
        assert!(
            stats
                .render()
                .contains("milter_operations_total{operation=\"policy\",outcome=\"timeout\"} 2\n")
        );
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
    client.write_all(&[0, 0]).await.unwrap();
    assert!(matches!(
        timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap(),
        Err(Error::Timeout)
    ));
}
#[tokio::test(start_paused = true)]
async fn smtp_idle_gap_does_not_use_the_frame_deadline() {
    let (mut client, task, _, _) = driver(Arc::new(server::Passthrough), Config::default()).await;
    negotiate(&mut client, 0).await;
    send(&mut client, b'C', b"unknown\0U").await;
    assert_eq!(recv(&mut client).await.command, b'c');
    tokio::time::advance(Duration::from_secs(61)).await;
    tokio::task::yield_now().await;
    assert!(
        !task.is_finished(),
        "an SMTP pause must not expire the milter frame deadline"
    );
    message(&mut client).await;
    assert_eq!(recv(&mut client).await.command, b'c');
    send(&mut client, b'Q', b"").await;
    task.await.unwrap().unwrap();
}
#[tokio::test(start_paused = true)]
async fn initial_idle_wait_is_unlimited_by_default() {
    let (mut client, task, _, _) = driver(Arc::new(server::Passthrough), Config::default()).await;
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(600)).await;
    tokio::task::yield_now().await;
    assert!(!task.is_finished());
    negotiate(&mut client, 0).await;
    send(&mut client, b'Q', b"").await;
    task.await.unwrap().unwrap();
}
#[tokio::test(start_paused = true)]
async fn configured_idle_timeout_resets_between_commands() {
    let (mut client, task, _, _) = driver(
        Arc::new(server::Passthrough),
        Config {
            idle_timeout: Some(Duration::from_secs(90)),
            ..Default::default()
        },
    )
    .await;
    negotiate(&mut client, 0).await;
    send(&mut client, b'C', b"unknown\0U").await;
    recv(&mut client).await;
    for _ in 0..2 {
        tokio::time::advance(Duration::from_secs(61)).await;
        tokio::task::yield_now().await;
        assert!(!task.is_finished());
        send(&mut client, b'H', b"client.example\0").await;
        assert_eq!(recv(&mut client).await.command, b'c');
    }
    tokio::time::advance(Duration::from_secs(91)).await;
    assert!(matches!(task.await.unwrap(), Err(Error::Timeout)));
}
#[tokio::test(start_paused = true)]
async fn partial_frame_gets_its_full_budget_after_idle() {
    let (mut client, task, _, _) = driver(
        Arc::new(server::Passthrough),
        Config {
            idle_timeout: Some(Duration::from_secs(120)),
            frame_timeout: Duration::from_secs(10),
            ..Default::default()
        },
    )
    .await;
    let wire = Options {
        version: 6,
        actions: 0,
        protocol: 0,
    }
    .frame()
    .encode()
    .unwrap();
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(119)).await;
    client.write_all(&wire[..1]).await.unwrap();
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(9)).await;
    client.write_all(&wire[1..]).await.unwrap();
    assert_eq!(recv(&mut client).await.command, b'O');
    send(&mut client, b'Q', b"").await;
    task.await.unwrap().unwrap();
}
#[tokio::test(start_paused = true)]
async fn partial_frame_deadline_covers_header_and_body_without_drip_resets() {
    let wire = Options {
        version: 6,
        actions: 0,
        protocol: 0,
    }
    .frame()
    .encode()
    .unwrap();
    for split in [1, 4, 8] {
        let (mut client, task, _, _) = driver(
            Arc::new(server::Passthrough),
            Config {
                frame_timeout: Duration::from_secs(10),
                ..Default::default()
            },
        )
        .await;
        client.write_all(&wire[..split]).await.unwrap();
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(5)).await;
        client.write_all(&wire[split..split + 1]).await.unwrap();
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(6)).await;
        assert!(matches!(task.await.unwrap(), Err(Error::Timeout)));
    }
}
#[tokio::test(start_paused = true)]
async fn shutdown_cancels_idle_and_partial_frame_waits() {
    for prefix in [&b""[..], &b"\0"[..]] {
        let (mut client, task, _, stop) =
            driver(Arc::new(server::Passthrough), Config::default()).await;
        client.write_all(prefix).await.unwrap();
        tokio::task::yield_now().await;
        stop.cancel();
        task.await.unwrap().unwrap();
    }
}
#[tokio::test]
async fn eof_is_clean_only_before_a_frame_starts() {
    for partial in [false, true] {
        let (mut client, task, _, _) =
            driver(Arc::new(server::Passthrough), Config::default()).await;
        if partial {
            client.write_all(&[0]).await.unwrap();
        }
        client.shutdown().await.unwrap();
        let result = task.await.unwrap();
        if partial {
            assert!(
                matches!(result, Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof)
            );
        } else {
            result.unwrap();
        }
    }
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
    let stats = Arc::new(Stats::default());
    let policy = Arc::new(
        HooksClient::with_options(
            url,
            mta_hooks_milter::transport::Authentication::bearer("test-token").unwrap(),
            "test".into(),
            Duration::from_secs(2),
            true,
            mta_hooks_milter::transport::TransportOptions::default(),
            HooksOptions::default(),
            stats.clone(),
        )
        .await
        .unwrap(),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
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
    assert!(
        stats.render().contains(
            "milter_operations_total{operation=\"registration\",outcome=\"success\"} 2\n"
        )
    );
    assert!(
        stats
            .render()
            .contains("milter_operations_total{operation=\"hook\",outcome=\"http_status\"} 1\n")
    );
    assert!(
        stats
            .render()
            .contains("milter_operations_total{operation=\"hook\",outcome=\"success\"} 1\n")
    );
    assert_eq!(stats.drain_graceful.load(Ordering::Relaxed), 1);
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
    let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
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
    assert!(
        stats
            .render()
            .contains("milter_listener_up{transport=\"unix\"} 1\n")
    );
    stop.cancel();
    task.await.unwrap().unwrap();
    assert_eq!(stats.active.load(Ordering::Relaxed), 0);
    assert_eq!(stats.drain_graceful.load(Ordering::Relaxed), 1);
    assert_eq!(stats.drain_forced.load(Ordering::Relaxed), 0);
    assert!(
        stats
            .render()
            .contains("milter_listener_up{transport=\"unix\"} 0\n")
    );
    std::fs::remove_file(&path).unwrap();
}

#[tokio::test]
async fn forced_drain_releases_policy_and_connection_gauges() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let stats = Arc::new(Stats::default());
    let stop = CancellationToken::new();
    let started = Arc::new(Notify::new());
    let task = tokio::spawn(server::serve(
        server::Listener::Tcp(listener),
        Arc::new(SlowPolicy {
            started: started.clone(),
        }),
        Config {
            shutdown_timeout: Duration::from_millis(20),
            ..Default::default()
        },
        stats.clone(),
        stop.clone(),
    ));
    let mut client = TcpStream::connect(address).await.unwrap();
    negotiate(&mut client, 0).await;
    send(&mut client, b'C', b"unknown\0U").await;
    recv(&mut client).await;
    message(&mut client).await;
    started.notified().await;
    assert_eq!(stats.policy.active(), 1);
    stop.cancel();
    task.await.unwrap().unwrap();
    assert_eq!(stats.active.load(Ordering::Relaxed), 0);
    assert_eq!(stats.policy.active(), 0);
    assert_eq!(stats.drain_forced.load(Ordering::Relaxed), 1);
    assert_eq!(stats.drain_graceful.load(Ordering::Relaxed), 0);
    assert!(
        stats
            .render()
            .contains("milter_operations_total{operation=\"policy\",outcome=\"cancelled\"} 1\n")
    );
}

#[tokio::test(start_paused = true)]
async fn progress_keepalives_are_sent_while_a_callback_is_pending() {
    for interval in [Some(Duration::from_secs(1)), None] {
        let config = Config {
            policy_timeout: Duration::from_millis(2500),
            progress_interval: interval,
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
        message(&mut client).await;
        let expected = if interval.is_some() { 2 } else { 0 };
        for _ in 0..expected {
            assert_eq!(recv(&mut client).await, Frame::empty(PROGRESS));
        }
        assert_eq!(recv(&mut client).await, Frame::empty(b't'));
        assert_eq!(stats.progress.load(Ordering::Relaxed), expected);
        assert!(
            stats
                .render()
                .contains(&format!("milter_progress_total {expected}\n"))
        );
        // The connection stays usable after keepalives.
        message(&mut client).await;
        for _ in 0..expected {
            assert_eq!(recv(&mut client).await, Frame::empty(PROGRESS));
        }
        assert_eq!(recv(&mut client).await, Frame::empty(b't'));
        send(&mut client, b'Q', b"").await;
        task.await.unwrap().unwrap();
    }
}

#[derive(Clone)]
struct StageMock {
    requests: Arc<Mutex<Vec<(HeaderMap, Value)>>>,
    properties: Vec<&'static str>,
    failures: Arc<AtomicUsize>,
    deregistrations: Arc<Mutex<Vec<HeaderMap>>>,
}
async fn stage_register(
    State(mock): State<StageMock>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    assert_eq!(
        body["inbound"]["properties"],
        json!(mta_hooks_milter::hooks::OFFERED_PROPERTIES)
    );
    (
        StatusCode::CREATED,
        Json(json!({
            "registrationId":"stages","status":"active","expiresAt":null,"hookEndpoint":"/hook",
            "endpoints":{"deregistration":"/register/stages","status":"/register/stages/status"},
            "negotiated":{"serialization":"json","inbound":{
                "stages":["data","rcpt","connect"],"properties":mock.properties}}
        })),
    )
}
async fn stage_hook(
    State(mock): State<StageMock>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, [(&'static str, &'static str); 1], Json<Value>) {
    let mut requests = mock.requests.lock().await;
    let keys: Vec<_> = body.as_object().unwrap().keys().cloned().collect();
    let mut expected: Vec<String> = mock.properties.iter().map(|p| p[1..].to_owned()).collect();
    expected.sort();
    let mut keys = keys;
    keys.sort();
    assert_eq!(keys, expected);
    requests.push((headers, body.clone()));
    let retry = [("retry-after", "0")];
    match body["stage"].as_str().unwrap() {
        "connect" => (StatusCode::NO_CONTENT, retry, Json(Value::Null)),
        "rcpt" if body["envelope"]["to"][0]["address"] == "bad@example.com" => (
            StatusCode::OK,
            retry,
            Json(json!({"set":[{"path":"/action","value":"reject"},
                {"path":"/response","value":{"code":550,"enhancedCode":"5.1.1","message":"No such user"}}]})),
        ),
        "rcpt" => (StatusCode::OK, retry, Json(json!({}))),
        _ if mock.failures.fetch_sub(1, Ordering::Relaxed) > 0 => {
            (StatusCode::SERVICE_UNAVAILABLE, retry, Json(json!({})))
        }
        _ => (
            StatusCode::OK,
            retry,
            Json(
                json!({"add":[{"path":"/message/headers","value":{"name":"X-Scanned","value":"yes"}}],
                "set":[{"path":"/envelope/from","value":{"address":"rewritten@example.com"}}]}),
            ),
        ),
    }
}
async fn stage_deregister(
    State(mock): State<StageMock>,
    headers: HeaderMap,
) -> (StatusCode, Json<Value>) {
    mock.deregistrations.lock().await.push(headers);
    (
        StatusCode::OK,
        Json(json!({"registrationId":"stages","status":"deregistered"})),
    )
}
async fn stage_scanner(
    properties: Vec<&'static str>,
    failures: usize,
) -> (reqwest::Url, StageMock, tokio::task::JoinHandle<()>) {
    let mock = StageMock {
        requests: Arc::new(Mutex::new(vec![])),
        properties,
        failures: Arc::new(AtomicUsize::new(failures)),
        deregistrations: Arc::new(Mutex::new(vec![])),
    };
    let app = Router::new()
        .route("/register", post(stage_register))
        .route("/register/stages", axum::routing::delete(stage_deregister))
        .route("/hook", post(stage_hook))
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
async fn stage_client(url: reqwest::Url, stats: Arc<Stats>, retries: u32) -> HooksClient {
    HooksClient::with_options(
        url,
        mta_hooks_milter::transport::Authentication::bearer("test-token").unwrap(),
        "test".into(),
        Duration::from_secs(2),
        true,
        mta_hooks_milter::transport::TransportOptions::default(),
        HooksOptions {
            stages: vec![Stage::Connect, Stage::Recipient, Stage::EndMessage],
            retries,
            ..HooksOptions::default()
        },
        stats,
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn early_stages_negotiated_properties_macros_retries_and_deregistration() {
    let properties = vec![
        "/stage",
        "/action",
        "/envelope",
        "/client",
        "/rawMessage",
        "/tls",
        "/auth",
        "/server",
        "/queue",
    ];
    let (url, mock, scanner_task) = stage_scanner(properties, 2).await;
    let stats = Arc::new(Stats::default());
    let policy = Arc::new(stage_client(url, stats.clone(), 2).await);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let stop = CancellationToken::new();
    let task = tokio::spawn(server::serve(
        server::Listener::Tcp(listener),
        policy.clone(),
        Config::default(),
        stats.clone(),
        stop.clone(),
    ));
    let mut client = TcpStream::connect(address).await.unwrap();
    write_frame(
        &mut client,
        &Options {
            version: 6,
            actions: SUPPORTED_ACTIONS,
            protocol: 0,
        }
        .frame(),
    )
    .await
    .unwrap();
    let reply = recv(&mut client).await;
    assert_eq!(reply.command, b'O');
    let actions = u32::from_be_bytes(reply.payload[4..8].try_into().unwrap());
    assert_eq!(
        actions & (CHANGE_FROM | CHANGE_HEADERS | DELETE_RECIPIENT),
        CHANGE_FROM | CHANGE_HEADERS | DELETE_RECIPIENT
    );
    assert!(
        reply.payload[12..]
            .windows(13)
            .any(|w| w == b"{client_addr}")
    );
    send(
        &mut client,
        b'D',
        b"Cj\0mx.example\0{daemon_addr}\x00192.0.2.9\0{daemon_port}\x0025\0{client_connections}\x003\0",
    )
    .await;
    send(&mut client, b'C', b"mx\0\x34\x00\x19\x31\x39\x32.0.2.1\0").await;
    assert_eq!(recv(&mut client).await, Frame::empty(b'c'));
    send(
        &mut client,
        b'D',
        b"H{tls_version}\0TLSv1.3\0{cipher}\0TLS_AES_256_GCM_SHA384\0{cipher_bits}\x00256\0",
    )
    .await;
    send(&mut client, b'H', b"client.example\0").await;
    assert_eq!(recv(&mut client).await, Frame::empty(b'c'));
    send(
        &mut client,
        b'D',
        b"Mi\0queue-2\0{auth_authen}\0alice\0{auth_type}\0PLAIN\0",
    )
    .await;
    send(&mut client, b'M', b"<alice@example.com>\0").await;
    assert_eq!(recv(&mut client).await, Frame::empty(b'c'));
    send(&mut client, b'R', b"<bad@example.com>\0").await;
    assert_eq!(
        recv(&mut client).await,
        string_frame(b'y', &[b"550 5.1.1 No such user"]).unwrap()
    );
    send(&mut client, b'R', b"<good@example.com>\0").await;
    assert_eq!(recv(&mut client).await, Frame::empty(b'c'));
    for (cmd, p) in [
        (b'T', &b""[..]),
        (b'L', &b"Subject\0test\0"[..]),
        (b'N', &b""[..]),
        (b'B', &b"hello\r\n"[..]),
    ] {
        send(&mut client, cmd, p).await;
        assert_eq!(recv(&mut client).await.command, b'c');
    }
    send(&mut client, b'E', b"").await;
    assert_eq!(
        recv(&mut client).await,
        Frame::new(b'h', Bytes::from_static(b"X-Scanned\0yes\0"))
    );
    assert_eq!(
        recv(&mut client).await,
        Frame::new(b'e', Bytes::from_static(b"<rewritten@example.com>\0"))
    );
    assert_eq!(recv(&mut client).await, Frame::empty(b'c'));
    let requests = mock.requests.lock().await;
    let stages: Vec<_> = requests
        .iter()
        .map(|(_, b)| b["stage"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(stages, ["connect", "rcpt", "rcpt", "data", "data", "data"]);
    let connect = &requests[0].1;
    assert!(
        connect["envelope"].is_null()
            && connect["rawMessage"].is_null()
            && connect["tls"].is_null()
    );
    assert_eq!(connect["client"]["ip"], "192.0.2.1");
    assert_eq!(connect["client"]["activeConnections"], 3);
    assert_eq!(
        connect["server"],
        json!({"name":"mx.example","ip":"192.0.2.9","port":25})
    );
    assert!(connect["auth"].is_null() && connect["queue"].is_null());
    let rcpt = &requests[1].1;
    assert_eq!(
        rcpt["envelope"]["to"],
        json!([{"address":"bad@example.com","parameters":{}}])
    );
    assert_eq!(rcpt["tls"]["version"], "TLSv1.3");
    assert_eq!(rcpt["tls"]["cipherBits"], 256);
    assert_eq!(rcpt["auth"], json!({"login":"alice","method":"PLAIN"}));
    assert_eq!(rcpt["queue"]["id"], "queue-2");
    assert!(rcpt["rawMessage"].is_null());
    let data = &requests[3].1;
    assert_eq!(
        data["envelope"]["to"],
        json!([{"address":"good@example.com","parameters":{}}])
    );
    assert!(data["rawMessage"].is_string());
    // Two 503 responses were retried with the same request identifier.
    assert_eq!(
        requests[3].0["x-mta-hooks-request-id"],
        requests[5].0["x-mta-hooks-request-id"]
    );
    assert_eq!(
        requests[3].0["x-mta-hooks-request-id"],
        requests[4].0["x-mta-hooks-request-id"]
    );
    assert_ne!(
        requests[1].0["x-mta-hooks-request-id"],
        requests[2].0["x-mta-hooks-request-id"]
    );
    drop(requests);
    send(&mut client, b'Q', b"").await;
    stop.cancel();
    task.await.unwrap().unwrap();
    assert_eq!(stats.hook_retries.load(Ordering::Relaxed), 2);
    assert!(stats.render().contains("milter_hook_retries_total 2\n"));
    assert!(
        stats
            .render()
            .contains("milter_operations_total{operation=\"hook\",outcome=\"http_status\"} 2\n")
    );
    policy.deregister().await.unwrap();
    policy.deregister().await.unwrap();
    let deregistrations = mock.deregistrations.lock().await;
    assert_eq!(deregistrations.len(), 1);
    assert_eq!(deregistrations[0]["x-mta-hooks-registration"], "stages");
    assert_eq!(deregistrations[0]["authorization"], "Bearer test-token");
    assert!(
        stats.render().contains(
            "milter_operations_total{operation=\"deregistration\",outcome=\"success\"} 1\n"
        )
    );
    scanner_task.abort();
}

#[tokio::test]
async fn retries_are_opt_out_and_registration_refuses_unconfirmed_stages_or_properties() {
    let (url, mock, scanner_task) = stage_scanner(vec!["/stage", "/action", "/envelope"], 1).await;
    let stats = Arc::new(Stats::default());
    let policy = stage_client(url.clone(), stats.clone(), 0).await;
    let mut session = Session::new(Limits::default(), Stage::ALL.to_vec(), 0);
    session
        .receive(
            Options {
                version: 6,
                actions: 0,
                protocol: 0,
            }
            .frame(),
        )
        .unwrap();
    session.connection = Some(Connection {
        hostname: Bytes::from_static(b"fixture"),
        family: b'U',
        port: None,
        address: None,
    });
    session.message.sender = Some(EnvelopeAddress {
        address: Bytes::from_static(b"<>"),
        parameters: vec![],
    });
    let error = policy
        .evaluate(Stage::EndMessage, &session)
        .await
        .err()
        .unwrap();
    assert_eq!(error.kind(), "http_status");
    assert_eq!(mock.requests.lock().await.len(), 1);
    assert_eq!(stats.hook_retries.load(Ordering::Relaxed), 0);
    scanner_task.abort();
    for (stages, properties) in [
        (vec![Stage::EndMessage], vec!["/stage", "/action"]),
        (
            vec![Stage::Connect, Stage::Recipient, Stage::EndMessage],
            vec!["/stage"],
        ),
        (
            vec![Stage::Connect, Stage::Recipient, Stage::EndMessage],
            vec!["/stage", "/action", "/senderAuth"],
        ),
    ] {
        let (url, _, scanner_task) = stage_scanner(properties, 0).await;
        let result = HooksClient::with_options(
            url,
            mta_hooks_milter::transport::Authentication::bearer("test-token").unwrap(),
            "test".into(),
            Duration::from_secs(2),
            true,
            mta_hooks_milter::transport::TransportOptions::default(),
            HooksOptions {
                stages,
                ..HooksOptions::default()
            },
            Arc::new(Stats::default()),
        )
        .await;
        assert_eq!(result.err().unwrap().kind(), "invalid");
        scanner_task.abort();
    }
}

#[tokio::test]
async fn startup_registration_waits_for_a_late_scanner() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let url: reqwest::Url = format!("http://{address}/register").parse().unwrap();
    let late = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(300)).await;
        let mock = Mock {
            registrations: Arc::new(AtomicUsize::new(0)),
            requests: Arc::new(Mutex::new(vec![])),
            response: json!({}),
            reregister: false,
        };
        let app = Router::new()
            .route("/register", post(register))
            .with_state(mock);
        let listener = TcpListener::bind(address).await.unwrap();
        axum::serve(listener, app).await.unwrap();
    });
    let stats = Arc::new(Stats::default());
    for (wait, ok) in [(Duration::ZERO, false), (Duration::from_secs(10), true)] {
        let result = HooksClient::with_options(
            url.clone(),
            mta_hooks_milter::transport::Authentication::bearer("test-token").unwrap(),
            "test".into(),
            Duration::from_secs(2),
            true,
            mta_hooks_milter::transport::TransportOptions::default(),
            HooksOptions {
                startup_wait: wait,
                ..HooksOptions::default()
            },
            stats.clone(),
        )
        .await;
        assert_eq!(result.is_ok(), ok, "wait {wait:?}");
        if !ok {
            assert_eq!(result.err().unwrap().kind(), "connect");
        }
    }
    let metrics = stats.render();
    let failures: u64 = metrics
        .lines()
        .find_map(|l| {
            l.strip_prefix(
                "milter_operations_total{operation=\"registration\",outcome=\"connect\"} ",
            )
        })
        .unwrap()
        .parse()
        .unwrap();
    assert!(failures >= 2, "{failures}");
    late.abort();
}
