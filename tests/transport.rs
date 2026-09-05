//! Real HTTP/TLS fixtures using ephemeral certificates and synthetic credentials.
use mta_hooks_milter::{
    hooks::HooksClient,
    protocol::{Error, Result},
    server::{Policy, Stats},
    session::{EnvelopeAddress, Limits, Session, Stage},
    transport::{Authentication, ProxyMode, TransportOptions, read_secret_file},
};
use rcgen::{BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    io::Write,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader},
    net::TcpListener,
    task::{JoinHandle, JoinSet},
};
use tokio_rustls::{
    TlsAcceptor,
    rustls::{self, pki_types::PrivatePkcs8KeyDer},
};

type Seen = Arc<Mutex<Vec<(String, BTreeMap<String, String>, Value)>>>;
struct Fixture {
    url: reqwest::Url,
    seen: Seen,
    connections: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn connection<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    seen: Seen,
    gzip: bool,
    response_size: usize,
) {
    let mut stream = BufReader::new(stream);
    loop {
        let mut request_line = String::new();
        if stream.read_line(&mut request_line).await.unwrap_or(0) == 0 {
            return;
        }
        let mut headers = BTreeMap::new();
        loop {
            let mut line = String::new();
            if stream.read_line(&mut line).await.unwrap_or(0) == 0 {
                return;
            }
            if line == "\r\n" {
                break;
            }
            let (key, value) = line.split_once(':').unwrap();
            headers.insert(key.to_ascii_lowercase(), value.trim().to_owned());
        }
        let len: usize = headers["content-length"].parse().unwrap();
        assert!(len < 100_000);
        let mut data = vec![0; len];
        if stream.read_exact(&mut data).await.is_err() {
            return;
        }
        let body: Value = serde_json::from_slice(&data).unwrap();
        let register = request_line
            .split_whitespace()
            .nth(1)
            .unwrap()
            .ends_with("/register");
        seen.lock()
            .unwrap()
            .push((request_line, headers, body.clone()));
        let (status, mut body) = if register {
            (201, serde_json::to_vec(&json!({"registrationId":"fixture", "status":"active",
                "hookEndpoint":"/hook", "negotiated":{"serialization":"json", "inbound":body["inbound"]},
                "padding":"x".repeat(response_size)})).unwrap())
        } else {
            (200, b"{}".to_vec())
        };
        if gzip {
            let mut encoder =
                flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            encoder.write_all(&body).unwrap();
            body = encoder.finish().unwrap();
        }
        let head = format!(
            "HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{}\r\n",
            body.len(),
            if gzip {
                "Content-Encoding: gzip\r\n"
            } else {
                ""
            }
        );
        if stream.write_all(head.as_bytes()).await.is_err()
            || stream.write_all(&body).await.is_err()
        {
            return;
        }
        if stream.flush().await.is_err() {
            return;
        }
    }
}

async fn fixture(
    tls: Option<Arc<rustls::ServerConfig>>,
    gzip: bool,
    response_size: usize,
) -> Fixture {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let scheme = if tls.is_some() { "https" } else { "http" };
    let url = format!("{scheme}://{}/register", listener.local_addr().unwrap())
        .parse()
        .unwrap();
    let seen: Seen = Arc::default();
    let connections = Arc::new(AtomicUsize::new(0));
    let (requests, accepted) = (seen.clone(), connections.clone());
    let task = tokio::spawn(async move {
        let mut tasks = JoinSet::new();
        loop {
            tokio::select! {
                Some(_) = tasks.join_next(), if !tasks.is_empty() => {},
                result = listener.accept() => {
                    let (stream, _) = result.unwrap();
                    accepted.fetch_add(1, Ordering::Relaxed);
                    let (tls, seen) = (tls.clone(), requests.clone());
                    tasks.spawn(async move {
                        if let Some(config) = tls {
                            if let Ok(stream) = TlsAcceptor::from(config).accept(stream).await {
                                connection(stream, seen, gzip, response_size).await;
                            }
                        } else { connection(stream, seen, gzip, response_size).await; }
                    });
                }
            }
        }
    });
    Fixture {
        url,
        seen,
        connections,
        task,
    }
}

struct Certificates {
    ca: reqwest::Certificate,
    identity: reqwest::Identity,
    server: Arc<rustls::ServerConfig>,
}
fn certificates(mtls: bool, hostname: &str) -> Certificates {
    let mut ca_params = CertificateParams::new(vec![]).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_key = KeyPair::generate().unwrap();
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let issuer = Issuer::new(ca_params, ca_key);
    let server_key = KeyPair::generate().unwrap();
    let mut server_params = CertificateParams::new(vec![hostname.to_owned()]).unwrap();
    server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let server_cert = server_params.signed_by(&server_key, &issuer).unwrap();
    let client_key = KeyPair::generate().unwrap();
    let mut client_params = CertificateParams::new(vec![]).unwrap();
    client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let client_cert = client_params.signed_by(&client_key, &issuer).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca.der().clone()).unwrap();
    let builder = rustls::ServerConfig::builder();
    let builder = if mtls {
        builder.with_client_cert_verifier(
            rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
                .build()
                .unwrap(),
        )
    } else {
        builder.with_no_client_auth()
    };
    let server = builder
        .with_single_cert(
            vec![server_cert.der().clone()],
            PrivatePkcs8KeyDer::from(server_key.serialize_der()).into(),
        )
        .unwrap();
    Certificates {
        ca: reqwest::Certificate::from_pem(ca.pem().as_bytes()).unwrap(),
        identity: reqwest::Identity::from_pem(
            format!("{}{}", client_cert.pem(), client_key.serialize_pem()).as_bytes(),
        )
        .unwrap(),
        server: Arc::new(server),
    }
}
fn direct() -> TransportOptions {
    TransportOptions {
        proxy: ProxyMode::Disabled,
        ..Default::default()
    }
}
async fn client(
    url: reqwest::Url,
    options: TransportOptions,
    auth: Authentication,
    stats: Arc<Stats>,
) -> Result<HooksClient> {
    HooksClient::with_options(
        url,
        auth,
        "fixture".into(),
        Duration::from_secs(2),
        true,
        options,
        stats,
    )
    .await
}
fn bearer() -> Authentication {
    Authentication::bearer("synthetic-test-token").unwrap()
}
fn message() -> Session {
    let mut session = Session::new(Limits::default(), vec![Stage::EndMessage], 0);
    session.connection = Some(mta_hooks_milter::protocol::Connection {
        hostname: bytes::Bytes::from_static(b"fixture"),
        family: b'U',
        port: None,
        address: None,
    });
    session.message.sender = Some(EnvelopeAddress {
        address: b"<>".to_vec().into(),
        parameters: vec![],
    });
    session
}

#[tokio::test]
async fn custom_ca_and_mutual_tls_require_valid_trust_identity_and_hostname() {
    for mtls in [false, true] {
        let certs = certificates(mtls, "127.0.0.1");
        let fixture = fixture(Some(certs.server), false, 0).await;
        let stats = Arc::new(Stats::default());
        let error = client(fixture.url.clone(), direct(), bearer(), stats.clone())
            .await
            .err()
            .unwrap();
        assert_eq!(error.kind(), "connect");
        assert!(fixture.seen.lock().unwrap().is_empty());
        let mut options = direct();
        options.built_in_roots = false;
        options.root_certificates.push(certs.ca.clone());
        if mtls {
            assert!(
                client(fixture.url.clone(), options, bearer(), stats.clone())
                    .await
                    .is_err()
            );
            assert!(fixture.seen.lock().unwrap().is_empty());
            options = direct();
            options.built_in_roots = false;
            options.root_certificates.push(certs.ca);
            options.identity = Some(certs.identity);
        }
        let client = client(fixture.url.clone(), options, bearer(), stats.clone())
            .await
            .unwrap();
        client
            .evaluate(Stage::EndMessage, &message())
            .await
            .unwrap();
        let seen = fixture.seen.lock().unwrap();
        assert_eq!(seen.len(), 2);
        assert!(
            seen.iter()
                .all(|(_, h, _)| h["authorization"] == "Bearer synthetic-test-token")
        );
        assert_eq!(stats.hook.active(), 0);
    }
    let certs = certificates(false, "wrong.example.test");
    let fixture = fixture(Some(certs.server), false, 0).await;
    let mut options = direct();
    options.root_certificates.push(certs.ca);
    let error = client(fixture.url.clone(), options, bearer(), Arc::default())
        .await
        .err()
        .unwrap();
    assert_eq!(error.kind(), "connect");
    assert!(fixture.seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn basic_auth_and_pool_disable_apply_to_registration_and_hooks() {
    for max_idle in [0, 1] {
        let fixture = fixture(None, false, 0).await;
        let mut options = direct();
        options.pool_max_idle_per_host = max_idle;
        let auth = Authentication::basic("fixture", "password").unwrap();
        let client = client(fixture.url.clone(), options, auth, Arc::default())
            .await
            .unwrap();
        for _ in 0..2 {
            client
                .evaluate(Stage::EndMessage, &message())
                .await
                .unwrap();
        }
        assert_eq!(
            fixture.connections.load(Ordering::Relaxed),
            if max_idle == 0 { 3 } else { 1 }
        );
        assert!(
            fixture
                .seen
                .lock()
                .unwrap()
                .iter()
                .all(|(_, h, _)| h["authorization"] == "Basic Zml4dHVyZTpwYXNzd29yZA==")
        );
    }
}

#[tokio::test]
async fn explicit_proxy_receives_both_requests() {
    let proxy = fixture(None, false, 0).await;
    // A held but unserved port: a direct request would time out, not pass this test.
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url: reqwest::Url = format!("http://{}/register", target.local_addr().unwrap())
        .parse()
        .unwrap();
    let mut proxy_url = proxy.url.clone();
    proxy_url.set_path("/");
    let options = TransportOptions {
        proxy: ProxyMode::Explicit(proxy_url),
        ..Default::default()
    };
    let client = client(url.clone(), options, bearer(), Arc::default())
        .await
        .unwrap();
    client
        .evaluate(Stage::EndMessage, &message())
        .await
        .unwrap();
    let seen = proxy.seen.lock().unwrap();
    assert_eq!(seen.len(), 2);
    assert!(seen[0].0.starts_with(&format!("POST {url} ")));
    assert!(
        seen[1]
            .0
            .contains(&format!("http://{}/hook", target.local_addr().unwrap()))
    );
}

#[tokio::test]
async fn configured_pool_idle_expiry_opens_a_new_connection() {
    let fixture = fixture(None, false, 0).await;
    let options = TransportOptions {
        pool_idle_timeout: Duration::from_millis(10),
        ..direct()
    };
    let client = client(fixture.url.clone(), options, bearer(), Arc::default())
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(40)).await;
    client
        .evaluate(Stage::EndMessage, &message())
        .await
        .unwrap();
    assert_eq!(fixture.connections.load(Ordering::Relaxed), 2);
}

#[tokio::test]
async fn registration_status_and_timeout_are_classified_without_leaking_urls() {
    for status in [Some(503), None] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!(
            "http://{}/register?private-value",
            listener.local_addr().unwrap()
        )
        .parse()
        .unwrap();
        let stats = Arc::new(Stats::default());
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = BufReader::new(stream);
            let mut length = 0;
            loop {
                let mut line = String::new();
                assert!(stream.read_line(&mut line).await.unwrap() > 0);
                if line == "\r\n" {
                    break;
                }
                if let Some((name, value)) = line.split_once(':')
                    && name.eq_ignore_ascii_case("content-length")
                {
                    length = value.trim().parse::<usize>().unwrap();
                }
            }
            assert!(length < 4096);
            stream.read_exact(&mut vec![0; length]).await.unwrap();
            if let Some(status) = status {
                stream
                    .write_all(
                        format!("HTTP/1.1 {status} Unavailable\r\nContent-Length: 0\r\n\r\n")
                            .as_bytes(),
                    )
                    .await
                    .unwrap();
            } else {
                std::future::pending::<()>().await;
            }
        });
        let result = HooksClient::with_options(
            url,
            bearer(),
            "fixture".into(),
            Duration::from_millis(100),
            true,
            direct(),
            stats.clone(),
        )
        .await;
        task.abort();
        let error = result.err().unwrap();
        assert_eq!(
            error.kind(),
            if status.is_some() {
                "http_status"
            } else {
                "timeout"
            }
        );
        assert!(!format!("{error:?} {error}").contains("private-value"));
        assert_eq!(stats.registration.active(), 0);
        let metrics = stats.render();
        assert!(
            metrics.contains(
                "milter_operation_duration_seconds_count{operation=\"registration\"} 1\n"
            )
        );
        assert!(!metrics.contains("private-value"));
    }
}

#[tokio::test]
async fn invalid_proxy_and_trust_configuration_fail_before_connecting() {
    for proxy in [
        "socks5://127.0.0.1:1",
        "http://user:secret@127.0.0.1:1",
        "http://127.0.0.1:1/path",
    ] {
        let options = TransportOptions {
            proxy: ProxyMode::Explicit(proxy.parse().unwrap()),
            ..Default::default()
        };
        let error = client(
            "https://unused.example.test/register".parse().unwrap(),
            options,
            bearer(),
            Arc::default(),
        )
        .await
        .err()
        .unwrap();
        assert!(matches!(error, Error::Invalid(_)));
        assert!(!format!("{error:?}").contains("secret"));
    }
    let options = TransportOptions {
        built_in_roots: false,
        ..direct()
    };
    assert!(
        client(
            "https://unused.example.test/register".parse().unwrap(),
            options,
            bearer(),
            Arc::default()
        )
        .await
        .is_err()
    );
}

#[tokio::test]
async fn gzip_responses_are_opt_in_and_decompressed_size_is_bounded() {
    for (enabled, size, expected) in [
        (false, 0, Some("invalid")),
        (true, 0, None),
        (true, 1024 * 1024, Some("limit")),
    ] {
        let fixture = fixture(None, true, size).await;
        let mut options = direct();
        options.gzip = enabled;
        let result = client(fixture.url.clone(), options, bearer(), Arc::default()).await;
        assert_eq!(result.as_ref().err().map(Error::kind), expected);
        if let Ok(client) = result {
            client
                .evaluate(Stage::EndMessage, &message())
                .await
                .unwrap();
        }
        for (_, headers, _) in fixture.seen.lock().unwrap().iter() {
            assert_eq!(
                headers.get("accept-encoding").map(String::as_str),
                enabled.then_some("gzip")
            );
            assert!(!headers.contains_key("content-encoding"));
        }
    }
}

#[test]
fn credentials_are_validated_and_debug_redacted() {
    for token in ["", "a\nb", "a b", "a\rb"] {
        assert!(Authentication::bearer(token).is_err());
    }
    for (user, password) in [("", "p"), ("a:b", "p"), ("a", ""), ("a", "p\n")] {
        assert!(Authentication::basic(user, password).is_err());
    }
    assert!(!format!("{:?}", bearer()).contains("synthetic-test-token"));
    assert!(
        !format!(
            "{:?}",
            Authentication::basic("fixture", "password").unwrap()
        )
        .contains("Zml4dHVyZTpwYXNzd29yZA==")
    );
    let path = std::env::temp_dir().join(format!("mta-hooks-secret-{}", uuid::Uuid::new_v4()));
    // Synthetic test data only; remove the exact temporary file afterwards.
    for (bytes, expected) in [
        (&b"synthetic\n"[..], Some("synthetic")),
        (&b" spaced \r\n"[..], Some(" spaced ")),
        (&b"\n"[..], None),
        (&b"a\nb"[..], None),
        (&b"\xff"[..], None),
    ] {
        std::fs::write(&path, bytes).unwrap();
        assert_eq!(read_secret_file(&path).ok().as_deref(), expected);
    }
    std::fs::write(&path, vec![b'x'; 8193]).unwrap();
    assert!(matches!(read_secret_file(&path), Err(Error::Limit(_))));
    std::fs::remove_file(path).unwrap();
}

struct ChildGuard(Option<std::process::Child>);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[tokio::test]
async fn daemon_proxy_environment_override_and_json_correlation() {
    use mta_hooks_milter::protocol::{Frame, Options, SUPPORTED_ACTIONS, read_frame, write_frame};
    // Environment is scoped to each child, never mutated in the concurrent test process.
    for mode in ["environment", "disabled", "no_proxy"] {
        let origin = fixture(None, false, 0).await;
        let proxy = fixture(None, false, 0).await;
        let reservation = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let milter_address = reservation.local_addr().unwrap();
        drop(reservation);
        let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_mta-hooks-milter"));
        command
            .env_clear()
            .env("MTA_HOOKS_TOKEN", "synthetic-test-token")
            .env("HTTP_PROXY", proxy.url.origin().ascii_serialization())
            .env("RUST_LOG", "mta_hooks_milter=debug")
            .args([
                "--scanner",
                origin.url.as_str(),
                "--insecure-loopback",
                "--log-format",
                "json",
                "--milter-listen",
                &milter_address.to_string(),
                "--http-listen",
                "127.0.0.1:0",
            ])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        if mode == "disabled" {
            command.arg("--scanner-no-proxy");
        }
        if mode == "no_proxy" {
            command.env("NO_PROXY", "127.0.0.1");
        }
        let mut child = ChildGuard(Some(command.spawn().unwrap()));
        let mut stream = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Ok(stream) = tokio::net::TcpStream::connect(milter_address).await {
                    break stream;
                }
                assert!(
                    child.0.as_mut().unwrap().try_wait().unwrap().is_none(),
                    "daemon exited before ready"
                );
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        tokio::time::timeout(Duration::from_secs(3), async {
            write_frame(
                &mut stream,
                &Options {
                    version: 6,
                    actions: SUPPORTED_ACTIONS,
                    protocol: 0,
                }
                .frame(),
            )
            .await
            .unwrap();
            assert_eq!(
                read_frame(&mut stream, 1024)
                    .await
                    .unwrap()
                    .unwrap()
                    .command,
                b'O'
            );
            for (cmd, body) in [
                (b'C', &b"fixture\0U"[..]),
                (b'M', &b"<>\0"[..]),
                (b'R', &b"<synthetic@example.test>\0"[..]),
                (b'T', &b""[..]),
                (b'N', &b""[..]),
                (b'E', &b""[..]),
            ] {
                write_frame(
                    &mut stream,
                    &Frame::new(cmd, bytes::Bytes::copy_from_slice(body)),
                )
                .await
                .unwrap();
                assert_eq!(
                    read_frame(&mut stream, 1024)
                        .await
                        .unwrap()
                        .unwrap()
                        .command,
                    b'c'
                );
            }
            write_frame(&mut stream, &Frame::empty(b'Q')).await.unwrap();
        })
        .await
        .unwrap();
        assert_eq!(
            proxy.seen.lock().unwrap().len(),
            if mode == "environment" { 2 } else { 0 }
        );
        assert_eq!(
            origin.seen.lock().unwrap().len(),
            if mode == "environment" { 0 } else { 2 }
        );
        let mut process = child.0.take().unwrap();
        process.kill().unwrap();
        let output = process.wait_with_output().unwrap();
        let logs = String::from_utf8(output.stdout).unwrap();
        let events: Vec<Value> = logs
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        let completed = events
            .iter()
            .find(|v| v["fields"]["message"] == "scanner invocation completed")
            .expect("request completion log");
        let spans = completed["spans"].as_array().unwrap();
        assert!(spans.iter().any(|v| v["session_id"].as_str().is_some()));
        let request_id = spans.iter().find_map(|v| v["request_id"].as_str()).unwrap();
        let seen = if mode == "environment" {
            &proxy.seen
        } else {
            &origin.seen
        };
        assert_eq!(
            seen.lock().unwrap()[1].1["x-mta-hooks-request-id"],
            request_id
        );
        assert!(!logs.contains("synthetic-test-token"));
        assert!(!logs.contains("synthetic@example.test"));
        assert!(!logs.contains(origin.url.as_str()));
        assert!(output.stderr.is_empty());
    }
}
