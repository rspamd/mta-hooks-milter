//! MTA Hooks draft-01 HTTP client: one scanner, JSON, configurable inbound stages.
//! The registration schema in -01 does not actually negotiate updateProperties;
//! this implementation enforces its documented local update allowlist.
use crate::{
    protocol::{
        ADD_HEADERS, ADD_RECIPIENT, ADD_RECIPIENT_PAR, CHANGE_FROM, CHANGE_HEADERS,
        DELETE_RECIPIENT, Error, HttpErrorKind, MacroLists, MacroStage, Modification, QUARANTINE,
        Result,
    },
    server::{Policy, PolicyFuture, Stats},
    session::{Decision, EnvelopeAddress, Session, Stage, Verdict},
    transport::{Authentication, TransportOptions, http_error},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use bytes::Bytes;
use chrono::{DateTime, Utc};
use reqwest::{Client, Response, StatusCode, Url};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{sync::Arc, time::Duration};
use tokio::{
    sync::{Mutex, MutexGuard},
    time::Instant,
};
use tracing::Instrument;
use uuid::Uuid;

/// Everything this adapter can project. The scanner confirms a subset.
pub const OFFERED_PROPERTIES: &[&str] = &[
    "/stage",
    "/action",
    "/timestamp",
    "/protocol",
    "/rawMessage",
    "/envelope",
    "/queue",
    "/client",
    "/tls",
    "/auth",
    "/server",
];
const REQUIRED_PROPERTIES: &[&str] = &["/stage", "/action"];
const RETRY_BASE: Duration = Duration::from_millis(100);
const RETRY_MAX: Duration = Duration::from_secs(5);
const RETRY_JITTER_MS: u128 = 100;

/// Adapter behavior beyond transport settings.
#[derive(Clone, Debug)]
pub struct HooksOptions {
    /// Inbound stages to subscribe; the scanner must confirm exactly these.
    pub stages: Vec<Stage>,
    /// Additional attempts per hook invocation after a transient failure
    /// (connect errors, HTTP 5xx or 429). Timeouts are never retried.
    pub retries: u32,
    /// Total time to keep retrying transient startup registration failures.
    pub startup_wait: Duration,
    /// Send DELETE to the scanner's deregistration endpoint on shutdown.
    pub deregister: bool,
    /// Ask the MTA for the macros the projection uses instead of its defaults.
    pub request_macros: bool,
}
impl Default for HooksOptions {
    fn default() -> Self {
        Self {
            stages: vec![Stage::EndMessage],
            retries: 2,
            startup_wait: Duration::ZERO,
            deregister: true,
            request_macros: true,
        }
    }
}

#[derive(Clone)]
struct Registration {
    id: String,
    endpoint: Url,
    deregistration: Option<Url>,
    expires: Option<DateTime<Utc>>,
    properties: Vec<String>,
}
pub struct HooksClient {
    client: Client,
    registration_url: Url,
    authentication: Authentication,
    name: String,
    timeout: Duration,
    response_limit: usize,
    insecure_loopback: bool,
    options: HooksOptions,
    registration: Mutex<Option<Arc<Registration>>>,
    stats: Arc<Stats>,
}
impl HooksClient {
    pub async fn new(
        url: Url,
        token: String,
        name: String,
        timeout: Duration,
        insecure_loopback: bool,
    ) -> Result<Self> {
        Self::with_options(
            url,
            Authentication::bearer(&token)?,
            name,
            timeout,
            insecure_loopback,
            TransportOptions::default(),
            HooksOptions::default(),
            Arc::new(Stats::default()),
        )
        .await
    }

    /// Configure scanner authentication/transport and share metrics with the server.
    #[allow(clippy::too_many_arguments)]
    pub async fn with_options(
        url: Url,
        authentication: Authentication,
        name: String,
        timeout: Duration,
        insecure_loopback: bool,
        transport: TransportOptions,
        options: HooksOptions,
        stats: Arc<Stats>,
    ) -> Result<Self> {
        validate_url(&url, insecure_loopback)?;
        if options.stages.is_empty() {
            return Err(Error::Invalid("at least one hook stage is required"));
        }
        let client = transport.build(timeout)?;
        let this = Self {
            client,
            registration_url: url,
            authentication,
            name,
            timeout,
            response_limit: 1024 * 1024,
            insecure_loopback,
            options,
            registration: Mutex::new(None),
            stats,
        };
        // Fail startup visibly if the endpoint/credentials/registration are invalid.
        // Transient failures are retried within the configured startup window.
        let deadline = Instant::now() + this.options.startup_wait;
        let mut attempt = 0u32;
        loop {
            let result = tokio::time::timeout(timeout, this.registered())
                .await
                .map_err(|_| Error::Timeout)
                .and_then(|r| r);
            match result {
                Ok(_) => return Ok(this),
                Err(error) if startup_transient(&error) => {
                    attempt += 1;
                    let delay = backoff(attempt, None);
                    if Instant::now() + delay >= deadline {
                        return Err(error);
                    }
                    tracing::warn!(
                        kind = error.kind(),
                        attempt,
                        delay_ms = delay.as_millis() as u64,
                        "startup registration failed; retrying"
                    );
                    tokio::time::sleep(delay).await;
                }
                Err(error) => return Err(error),
            }
        }
    }
    async fn registration_lock(&self) -> MutexGuard<'_, Option<Arc<Registration>>> {
        if let Ok(guard) = self.registration.try_lock() {
            return guard;
        }
        let observation = self.stats.registration_wait.begin();
        let guard = self.registration.lock().await;
        observation.finish(&Ok(()));
        guard
    }
    async fn registered(&self) -> Result<Arc<Registration>> {
        let mut guard = self.registration_lock().await;
        if let Some(reg) = guard.as_ref()
            && reg
                .expires
                .is_none_or(|e| e > Utc::now() + chrono::Duration::seconds(5))
        {
            return Ok(reg.clone());
        }
        let observation = self.stats.registration.begin();
        let result = self.register().await;
        observation.finish(&result);
        match &result {
            Ok(reg) => {
                *guard = Some(reg.clone());
                tracing::info!(
                    stages = self.options.stages.len(),
                    properties = reg.properties.len(),
                    "scanner registration active"
                );
            }
            Err(error) => tracing::warn!(kind = error.kind(), "scanner registration failed"),
        }
        result
    }
    fn stage_names(&self) -> Vec<&'static str> {
        self.options.stages.iter().map(|s| s.hook_name()).collect()
    }
    async fn register(&self) -> Result<Arc<Registration>> {
        let response=self.client.post(self.registration_url.clone()).header(reqwest::header::AUTHORIZATION, self.authentication.value()).json(&json!({
            "name":self.name,"version":env!("CARGO_PKG_VERSION"),"timeoutMs":self.timeout.as_millis() as u64,
            "serialization":"json","inbound":{"stages":self.stage_names(),"properties":OFFERED_PROPERTIES},"outbound":null,
        })).send().await.map_err(http_error)?;
        if response.status() != StatusCode::CREATED {
            tracing::warn!(
                status = response.status().as_u16(),
                "unexpected registration status"
            );
            return Err(Error::HttpStatus(response.status().as_u16()));
        }
        let value = bounded_json(response, self.response_limit).await?;
        let id = value["registrationId"]
            .as_str()
            .ok_or(Error::Invalid("registration id"))?;
        if id.is_empty()
            || id.len() > 255
            || !id
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b':'))
        {
            return Err(Error::Invalid("registration id"));
        }
        if value["status"] != "active" || value["negotiated"]["serialization"] != "json" {
            return Err(Error::Invalid("incompatible registration"));
        }
        let stages = value["negotiated"]["inbound"]["stages"]
            .as_array()
            .ok_or(Error::Invalid("registration stages"))?;
        let wanted = self.stage_names();
        if stages.len() != wanted.len() || wanted.iter().any(|s| !stages.contains(&json!(s))) {
            return Err(Error::Invalid(
                "scanner did not confirm the configured stages",
            ));
        }
        let props = value["negotiated"]["inbound"]["properties"]
            .as_array()
            .ok_or(Error::Invalid("registration properties"))?;
        let mut properties = Vec::new();
        for prop in props {
            let prop = prop
                .as_str()
                .filter(|p| OFFERED_PROPERTIES.contains(p))
                .ok_or(Error::Invalid(
                    "scanner confirmed a property outside the offered profile",
                ))?;
            if !properties.iter().any(|p| p == prop) {
                properties.push(prop.to_owned());
            }
        }
        if REQUIRED_PROPERTIES
            .iter()
            .any(|p| !properties.iter().any(|q| q == p))
        {
            return Err(Error::Invalid(
                "scanner did not confirm the required properties",
            ));
        }
        let endpoint = self.same_origin(
            value["hookEndpoint"]
                .as_str()
                .ok_or(Error::Invalid("hook endpoint"))?,
        )?;
        let deregistration = match value["endpoints"].get("deregistration") {
            Some(Value::String(path)) => Some(self.same_origin(path)?),
            Some(Value::Null) | None => None,
            Some(_) => return Err(Error::Invalid("deregistration endpoint")),
        };
        let expires = match value.get("expiresAt").filter(|v| !v.is_null()) {
            Some(v) => Some(
                DateTime::parse_from_rfc3339(
                    v.as_str().ok_or(Error::Invalid("registration expiry"))?,
                )
                .map_err(|_| Error::Invalid("registration expiry"))?
                .with_timezone(&Utc),
            ),
            None => None,
        };
        if expires.is_some_and(|e| e <= Utc::now()) {
            return Err(Error::Invalid("expired registration"));
        }
        Ok(Arc::new(Registration {
            id: id.to_owned(),
            endpoint,
            deregistration,
            expires,
            properties,
        }))
    }
    /// Resolve a scanner-supplied path against the registration URL; credentials
    /// are only ever sent to the registration origin.
    fn same_origin(&self, path: &str) -> Result<Url> {
        let url = self
            .registration_url
            .join(path)
            .map_err(|_| Error::Invalid("scanner endpoint URL"))?;
        validate_url(&url, self.insecure_loopback)?;
        if url.origin() != self.registration_url.origin() {
            return Err(Error::Invalid("cross-origin scanner endpoint"));
        }
        Ok(url)
    }
    /// Deregister from the scanner. Call after milter connections have drained;
    /// no hook is sent afterwards. Failures are reported, never fatal.
    pub async fn deregister(&self) -> Result<()> {
        let Some(reg) = self.registration_lock().await.take() else {
            return Ok(());
        };
        let Some(url) = reg.deregistration.clone() else {
            tracing::info!("scanner offered no deregistration endpoint");
            return Ok(());
        };
        if !self.options.deregister {
            return Ok(());
        }
        let observation = self.stats.deregistration.begin();
        let result = tokio::time::timeout(self.timeout, async {
            let response = self
                .client
                .delete(url)
                .header(reqwest::header::AUTHORIZATION, self.authentication.value())
                .header("X-MTA-Hooks-Registration", &reg.id)
                .send()
                .await
                .map_err(http_error)?;
            match response.status() {
                StatusCode::OK
                | StatusCode::NO_CONTENT
                | StatusCode::NOT_FOUND
                | StatusCode::GONE => Ok(()),
                status => Err(Error::HttpStatus(status.as_u16())),
            }
        })
        .await
        .map_err(|_| Error::Timeout)
        .and_then(|r| r);
        observation.finish(&result);
        match &result {
            Ok(()) => tracing::info!("scanner registration released"),
            Err(error) => tracing::warn!(kind = error.kind(), "scanner deregistration failed"),
        }
        result
    }
    async fn invoke(&self, session: &Session, stage: Stage, request_id: &str) -> Result<Decision> {
        let deadline = Instant::now() + self.timeout;
        let mut reg = self.registered().await?;
        let mut body = request(session, stage, &reg.properties)?;
        let mut recovered = false;
        let mut retries = 0u32;
        loop {
            let observation = self.stats.hook.begin();
            let response_limit =
                session.limits.message_bytes.saturating_add(2) / 3 * 4 + self.response_limit;
            let result = self.hook(&reg, request_id, &body, response_limit).await;
            observation.finish_error(result.as_ref().err().map(|f| &f.error));
            match result {
                Ok(Some(value)) => return translate(value, session, stage),
                Ok(None) => return Ok(Decision::default()),
                Err(HookFailure {
                    error: Error::HttpStatus(status @ (404 | 410)),
                    ..
                }) if !recovered => {
                    // One recovery attempt, sharing the invocation's deadline and ID.
                    recovered = true;
                    tracing::info!(status, "recovering scanner registration");
                    let mut guard = self.registration_lock().await;
                    if guard.as_ref().is_some_and(|r| r.id == reg.id) {
                        *guard = None;
                    }
                    drop(guard);
                    reg = self.registered().await?;
                    body = request(session, stage, &reg.properties)?;
                }
                Err(failure) if failure.transient() && retries < self.options.retries => {
                    retries += 1;
                    let delay = backoff(retries, failure.retry_after);
                    if Instant::now() + delay >= deadline {
                        return Err(failure.error);
                    }
                    self.stats
                        .hook_retries
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    tracing::info!(
                        kind = failure.error.kind(),
                        attempt = retries,
                        delay_ms = delay.as_millis() as u64,
                        "retrying scanner invocation"
                    );
                    tokio::time::sleep(delay).await;
                }
                Err(failure) => return Err(failure.error),
            }
        }
    }
    async fn hook(
        &self,
        reg: &Registration,
        request_id: &str,
        body: &Value,
        response_limit: usize,
    ) -> std::result::Result<Option<Value>, HookFailure> {
        let response = self
            .client
            .post(reg.endpoint.clone())
            .header(reqwest::header::AUTHORIZATION, self.authentication.value())
            .header("X-MTA-Hooks-Registration", &reg.id)
            .header("X-MTA-Hooks-Request-Id", request_id)
            .json(body)
            .send()
            .await
            .map_err(|e| HookFailure::from(http_error(e)))?;
        let status = response.status();
        tracing::debug!(status = status.as_u16(), "scanner HTTP response");
        match status {
            StatusCode::NO_CONTENT => Ok(None),
            StatusCode::OK => Ok(Some(
                bounded_json(response, response_limit)
                    .await
                    .map_err(HookFailure::from)?,
            )),
            _ => Err(HookFailure {
                error: Error::HttpStatus(status.as_u16()),
                retry_after: response
                    .headers()
                    .get(reqwest::header::RETRY_AFTER)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.trim().parse::<u64>().ok())
                    .map(Duration::from_secs),
            }),
        }
    }
}
struct HookFailure {
    error: Error,
    retry_after: Option<Duration>,
}
impl From<Error> for HookFailure {
    fn from(error: Error) -> Self {
        Self {
            error,
            retry_after: None,
        }
    }
}
impl HookFailure {
    /// Draft 7.5.3 transient classes. Timeouts are excluded: the budget is shared
    /// and the scanner may still be processing the first attempt.
    fn transient(&self) -> bool {
        match self.error {
            Error::HttpTransport(HttpErrorKind::Connect) => true,
            Error::HttpStatus(status) => status == 429 || (500..600).contains(&status),
            _ => false,
        }
    }
}
fn startup_transient(error: &Error) -> bool {
    match error {
        Error::Timeout
        | Error::HttpTransport(
            HttpErrorKind::Connect | HttpErrorKind::Timeout | HttpErrorKind::Other,
        ) => true,
        Error::HttpStatus(status) => *status == 429 || (500..600).contains(status),
        _ => false,
    }
}
/// Exponential backoff with jitter, honoring Retry-After up to the same cap.
fn backoff(attempt: u32, retry_after: Option<Duration>) -> Duration {
    let exponential = RETRY_BASE.saturating_mul(1u32 << attempt.saturating_sub(1).min(16));
    let jitter = Duration::from_millis((Uuid::new_v4().as_u128() % RETRY_JITTER_MS) as u64);
    exponential
        .max(retry_after.unwrap_or(Duration::ZERO))
        .min(RETRY_MAX)
        + jitter
}
impl Policy for HooksClient {
    fn stages(&self) -> Vec<Stage> {
        self.options.stages.clone()
    }
    fn actions(&self) -> u32 {
        ADD_HEADERS
            | crate::protocol::CHANGE_BODY
            | CHANGE_HEADERS
            | QUARANTINE
            | CHANGE_FROM
            | ADD_RECIPIENT
            | ADD_RECIPIENT_PAR
            | DELETE_RECIPIENT
    }
    fn macros(&self) -> MacroLists {
        if !self.options.request_macros {
            return MacroLists::default();
        }
        projection_macros()
    }
    fn evaluate<'a>(&'a self, stage: Stage, session: &'a Session) -> PolicyFuture<'a> {
        let request_id = Uuid::new_v4().to_string();
        let span = tracing::info_span!("hooks_request", %request_id, stage = stage.hook_name());
        Box::pin(
            async move {
                let started = tokio::time::Instant::now();
                tracing::debug!("scanner invocation started");
                let result =
                    tokio::time::timeout(self.timeout, self.invoke(session, stage, &request_id))
                        .await
                        .map_err(|_| Error::Timeout)
                        .and_then(|r| r);
                tracing::debug!(
                    outcome = result.as_ref().err().map_or("success", Error::kind),
                    elapsed_ms = started.elapsed().as_millis() as u64,
                    "scanner invocation completed"
                );
                result
            }
            .instrument(span),
        )
    }
}
/// Macro names behind the `/queue`, `/client`, `/tls`, `/auth` and `/server`
/// projections (Postfix names; Sendmail shares most of them).
pub fn projection_macros() -> MacroLists {
    let list = |names: &[&str]| names.iter().map(|n| (*n).to_owned()).collect();
    MacroLists(vec![
        (
            MacroStage::Connect,
            list(&[
                "j",
                "{daemon_name}",
                "{daemon_addr}",
                "{daemon_port}",
                "{client_addr}",
                "{client_port}",
                "{client_name}",
                "{client_ptr}",
                "{client_connections}",
            ]),
        ),
        (
            MacroStage::Helo,
            list(&[
                "{tls_version}",
                "{cipher}",
                "{cipher_bits}",
                "{cert_subject}",
                "{cert_issuer}",
            ]),
        ),
        (
            MacroStage::Mail,
            list(&["i", "{auth_type}", "{auth_authen}", "{auth_author}"]),
        ),
        (MacroStage::Recipient, list(&["i", "{rcpt_addr}"])),
        (MacroStage::Data, list(&["i"])),
        (MacroStage::EndHeaders, list(&["i"])),
        (MacroStage::EndMessage, list(&["i"])),
    ])
}
fn validate_url(url: &Url, insecure_loopback: bool) -> Result<()> {
    let local = url.host_str().is_some_and(|s| {
        s.trim_matches(['[', ']'])
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
    });
    if url.scheme() != "https" && !(insecure_loopback && url.scheme() == "http" && local) {
        return Err(Error::Invalid(
            "HTTPS required (development HTTP needs a literal loopback IP)",
        ));
    }
    if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
        return Err(Error::Invalid("URL credentials or fragment"));
    }
    Ok(())
}

#[cfg(test)]
mod instrumentation_tests {
    use super::*;

    #[tokio::test]
    async fn registration_waiters_release_gauge_on_completion_and_cancellation() {
        let url: Url = "https://unused.example.test/register".parse().unwrap();
        let stats = Arc::new(Stats::default());
        let client = HooksClient {
            client: Client::new(),
            registration_url: url.clone(),
            authentication: Authentication::bearer("synthetic").unwrap(),
            name: "fixture".into(),
            timeout: Duration::from_secs(1),
            response_limit: 1024,
            insecure_loopback: false,
            options: HooksOptions::default(),
            registration: Mutex::new(Some(Arc::new(Registration {
                id: "fixture".into(),
                endpoint: url,
                deregistration: None,
                expires: None,
                properties: vec![],
            }))),
            stats: stats.clone(),
        };
        for cancelled in [true, false] {
            let guard = client.registration.lock().await;
            let mut waiter = Box::pin(client.registered());
            tokio::select! {
                biased;
                _ = &mut waiter => panic!("must wait for held lock"),
                _ = tokio::task::yield_now() => {},
            }
            assert_eq!(stats.registration_wait.active(), 1);
            if cancelled {
                drop(waiter);
                drop(guard);
            } else {
                drop(guard);
                assert_eq!(waiter.await.unwrap().id, "fixture");
            }
            assert_eq!(stats.registration_wait.active(), 0);
        }
        let metrics = stats.render();
        assert!(metrics.contains(
            "milter_operations_total{operation=\"registration_wait\",outcome=\"cancelled\"} 1\n"
        ));
        assert!(metrics.contains(
            "milter_operations_total{operation=\"registration_wait\",outcome=\"success\"} 1\n"
        ));
    }

    #[test]
    fn backoff_is_capped_and_honours_retry_after() {
        for attempt in 1..=20 {
            let delay = backoff(attempt, None);
            assert!(delay >= RETRY_BASE && delay <= RETRY_MAX + Duration::from_millis(100));
        }
        let delay = backoff(1, Some(Duration::from_secs(2)));
        assert!(delay >= Duration::from_secs(2) && delay < Duration::from_millis(2100));
        assert!(
            backoff(1, Some(Duration::from_secs(3600))) <= RETRY_MAX + Duration::from_millis(100)
        );
        assert!(projection_macros().encode().unwrap().len() > 7 * 5);
    }
}

async fn bounded_json(mut response: Response, max: usize) -> Result<Value> {
    let ct = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !ct
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .eq_ignore_ascii_case("application/json")
    {
        return Err(Error::Invalid("expected application/json"));
    }
    if response.content_length().is_some_and(|l| l > max as u64) {
        return Err(Error::Limit("HTTP response"));
    }
    let mut data = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(http_error)? {
        if chunk.len() > max.saturating_sub(data.len()) {
            return Err(Error::Limit("HTTP response"));
        }
        data.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&data).map_err(|_| Error::Invalid("HTTP JSON"))
}
fn text(bytes: &[u8]) -> Result<&str> {
    std::str::from_utf8(bytes).map_err(|_| Error::Invalid("non-UTF8 envelope or metadata"))
}
fn address(a: &EnvelopeAddress, sender: bool) -> Result<Value> {
    let s = text(&a.address)?;
    let s = s
        .strip_prefix('<')
        .and_then(|s| s.strip_suffix('>'))
        .unwrap_or(s);
    let address = if sender && s.is_empty() {
        Value::Null
    } else {
        json!(s)
    };
    let mut parameters = serde_json::Map::new();
    for p in &a.parameters {
        let p = text(p)?;
        let (k, v) = p.split_once('=').unwrap_or((p, ""));
        parameters.insert(k.to_owned(), json!(v));
    }
    Ok(json!({"address":address,"parameters":parameters}))
}
/// A macro value that is present and non-empty, as UTF-8.
fn macro_text<'a>(session: &'a Session, name: &str) -> Result<Option<&'a str>> {
    session
        .macro_value(name)
        .filter(|v| !v.is_empty())
        .map(text)
        .transpose()
}
fn macro_number(session: &Session, name: &str) -> Result<Value> {
    Ok(macro_text(session, name)?
        .and_then(|v| v.parse::<u64>().ok())
        .map_or(Value::Null, Value::from))
}
/// Build the hook request for a stage using only the negotiated properties.
pub fn request(session: &Session, stage: Stage, properties: &[String]) -> Result<Value> {
    let connection = session
        .connection
        .as_ref()
        .ok_or(Error::Invalid("missing connection"))?;
    let mut body = serde_json::Map::new();
    for property in properties {
        let value = match property.as_str() {
            "/stage" => json!(stage.hook_name()),
            "/action" => json!("accept"),
            "/timestamp" => json!(Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)),
            "/protocol" => json!({"version":"1.0"}),
            "/rawMessage" => {
                if stage == Stage::EndMessage {
                    json!(STANDARD.encode(session.raw_message()))
                } else {
                    Value::Null
                }
            }
            "/envelope" => match &session.message.sender {
                Some(sender) if !matches!(stage, Stage::Connect | Stage::Helo) => {
                    let recipients = session
                        .message
                        .recipients
                        .iter()
                        .map(|r| address(r, false))
                        .collect::<Result<Vec<_>>>()?;
                    json!({"from":address(sender,true)?,"to":recipients})
                }
                Some(_) => Value::Null,
                None if stage == Stage::EndMessage => {
                    return Err(Error::Invalid("missing sender"));
                }
                None => Value::Null,
            },
            "/queue" => macro_text(session, "i")?.map_or(Value::Null, |id| json!({"id":id})),
            "/client" => {
                let ip = macro_text(session, "client_addr")?
                    .map(Some)
                    .unwrap_or(connection.address.as_deref().map(text).transpose()?);
                let ehlo = session.helo.as_deref().map(text).transpose()?;
                let mut client = json!({"ip":ip,"port":connection.port,"ehlo":ehlo});
                if let Some(ptr) = macro_text(session, "client_ptr")? {
                    client["ptr"] = json!(ptr);
                }
                if let Value::Number(n) = macro_number(session, "client_connections")? {
                    client["activeConnections"] = Value::Number(n);
                }
                client
            }
            "/tls" => match macro_text(session, "tls_version")? {
                Some(version) => json!({
                    "version": version,
                    "cipher": macro_text(session, "cipher")?,
                    "cipherBits": macro_number(session, "cipher_bits")?,
                    "certSubject": macro_text(session, "cert_subject")?,
                    "certIssuer": macro_text(session, "cert_issuer")?,
                }),
                None => Value::Null,
            },
            "/auth" => match macro_text(session, "auth_authen")? {
                Some(login) => json!({"login": login, "method": macro_text(session, "auth_type")?}),
                None => Value::Null,
            },
            "/server" => {
                let name = macro_text(session, "j")?;
                let ip = macro_text(session, "daemon_addr")?;
                if name.is_none() && ip.is_none() {
                    Value::Null
                } else {
                    json!({"name": name, "ip": ip, "port": macro_number(session, "daemon_port")?})
                }
            }
            _ => return Err(Error::Invalid("unknown negotiated property")),
        };
        body.insert(property[1..].to_owned(), value);
    }
    Ok(Value::Object(body))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Operations {
    set: Option<Vec<Set>>,
    add: Option<Vec<Add>>,
    delete: Option<Vec<Delete>>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Set {
    path: String,
    value: Value,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Add {
    path: String,
    value: Value,
    index: Option<u32>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Delete {
    path: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    name: String,
    value: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Address {
    address: Option<String>,
    #[serde(default)]
    parameters: serde_json::Map<String, Value>,
}
impl Address {
    /// Milter envelope form: angle brackets, then ESMTP parameters as "KEY=VALUE".
    fn milter(self, allow_null: bool) -> Result<(String, Option<String>)> {
        let address = match self.address {
            Some(a) if !a.is_empty() => {
                if a.starts_with('<') && a.ends_with('>') {
                    a
                } else {
                    format!("<{a}>")
                }
            }
            Some(_) | None if allow_null => "<>".to_owned(),
            _ => return Err(Error::Invalid("recipient address")),
        };
        let mut parameters = Vec::new();
        for (key, value) in self.parameters {
            let value = match value {
                Value::String(s) => s,
                Value::Null => String::new(),
                _ => return Err(Error::Invalid("ESMTP parameter value")),
            };
            if key.is_empty() || key.contains(['=', ' ']) || value.contains(' ') {
                return Err(Error::Invalid("ESMTP parameter"));
            }
            parameters.push(if value.is_empty() {
                key
            } else {
                format!("{key}={value}")
            });
        }
        Ok((
            address,
            (!parameters.is_empty()).then(|| parameters.join(" ")),
        ))
    }
}
/// Array element path such as `/message/headers/3`.
fn array_index<'a>(path: &'a str, prefix: &str) -> Option<(usize, &'a str)> {
    let rest = path.strip_prefix(prefix)?.strip_prefix('/')?;
    let (index, tail) = rest.split_once('/').unwrap_or((rest, ""));
    if index.is_empty() || index.len() > 9 || !index.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    Some((index.parse().ok()?, tail))
}
#[derive(Clone, Copy)]
enum Slot {
    Original(usize),
    Added(usize),
}
/// Message edits accumulated from a data-stage response, resolved to milter
/// modifications only after every operation validated.
#[derive(Default)]
struct Edits {
    header_changes: Vec<(usize, String)>,
    header_deletes: Vec<usize>,
    added_headers: Vec<Option<Header>>,
    headers: Vec<Slot>,
    from: Option<Address>,
    recipient_deletes: Vec<usize>,
    added_recipients: Vec<Option<Address>>,
    recipients: Vec<Slot>,
}
impl Edits {
    fn new(session: &Session) -> Self {
        Self {
            headers: (0..session.message.headers.len())
                .map(Slot::Original)
                .collect(),
            recipients: (0..session.message.recipients.len())
                .map(Slot::Original)
                .collect(),
            ..Self::default()
        }
    }
    fn is_empty(&self) -> bool {
        self.header_changes.is_empty()
            && self.header_deletes.is_empty()
            && self.added_headers.is_empty()
            && self.from.is_none()
            && self.recipient_deletes.is_empty()
            && self.added_recipients.is_empty()
    }
    fn set(&mut self, session: &Session, path: &str, value: Value) -> Result<()> {
        if let Some((index, tail)) = array_index(path, "/message/headers") {
            let (name, _) = session
                .message
                .headers
                .get(index)
                .ok_or(Error::Invalid("header index"))?;
            let new_value = match tail {
                "" => {
                    let header: Header = serde_json::from_value(value)
                        .map_err(|_| Error::Invalid("header object"))?;
                    if !header.name.eq_ignore_ascii_case(text(name)?) {
                        return Err(Error::Invalid("milter cannot rename a header"));
                    }
                    header.value
                }
                "value" => match value {
                    Value::String(s) => s,
                    _ => return Err(Error::Invalid("header value")),
                },
                _ => return Err(Error::Invalid("set outside supported update profile")),
            };
            self.header_changes.push((index, new_value));
            Ok(())
        } else if path == "/envelope/from" {
            self.from = Some(
                serde_json::from_value(value).map_err(|_| Error::Invalid("envelope address"))?,
            );
            Ok(())
        } else {
            Err(Error::Invalid("set outside supported update profile"))
        }
    }
    fn add(&mut self, session: &Session, add: Add) -> Result<()> {
        match add.path.as_str() {
            "/message/headers" => {
                if self.headers.len() >= session.limits.headers {
                    return Err(Error::Limit("headers after modifications"));
                }
                let header: Header = serde_json::from_value(add.value)
                    .map_err(|_| Error::Invalid("header object"))?;
                self.added_headers.push(Some(header));
                let slot = Slot::Added(self.added_headers.len() - 1);
                insert_slot(&mut self.headers, add.index, slot, "header insertion index")
            }
            "/envelope/to" => {
                if self.recipients.len() >= session.limits.recipients {
                    return Err(Error::Limit("recipients after modifications"));
                }
                let address: Address = serde_json::from_value(add.value)
                    .map_err(|_| Error::Invalid("envelope address"))?;
                self.added_recipients.push(Some(address));
                let slot = Slot::Added(self.added_recipients.len() - 1);
                insert_slot(&mut self.recipients, add.index, slot, "recipient index")
            }
            _ => Err(Error::Invalid("add outside supported update profile")),
        }
    }
    fn delete(&mut self, path: &str) -> Result<()> {
        if let Some((index, "")) = array_index(path, "/message/headers") {
            if index >= self.headers.len() {
                return Err(Error::Invalid("header index"));
            }
            match self.headers.remove(index) {
                Slot::Original(i) => self.header_deletes.push(i),
                Slot::Added(i) => self.added_headers[i] = None,
            }
            Ok(())
        } else if let Some((index, "")) = array_index(path, "/envelope/to") {
            if index >= self.recipients.len() {
                return Err(Error::Invalid("recipient index"));
            }
            match self.recipients.remove(index) {
                Slot::Original(i) => self.recipient_deletes.push(i),
                Slot::Added(i) => self.added_recipients[i] = None,
            }
            Ok(())
        } else {
            Err(Error::Invalid("delete outside supported update profile"))
        }
    }
    /// Emit milter frames in an order whose indexes stay valid as the MTA applies
    /// them: header deletes/changes by descending original position (per-name
    /// occurrences of earlier headers never shift), then inserts by final position.
    fn modifications(mut self, session: &Session) -> Result<Vec<Modification>> {
        let headers = &session.message.headers;
        let occurrence = |index: usize| -> Result<(String, u32)> {
            let name = text(&headers[index].0)?;
            let count = headers[..index]
                .iter()
                .filter(|(n, _)| n.eq_ignore_ascii_case(name.as_bytes()))
                .count();
            Ok((name.to_owned(), count as u32 + 1))
        };
        let mut edits: Vec<(usize, Option<String>)> = self
            .header_changes
            .into_iter()
            .map(|(i, v)| (i, Some(v)))
            .chain(self.header_deletes.into_iter().map(|i| (i, None)))
            .collect();
        edits.sort_by(|a, b| b.0.cmp(&a.0));
        let mut modifications = Vec::new();
        let mut seen = std::collections::BTreeSet::new();
        for (index, value) in edits {
            if !seen.insert(index) {
                return Err(Error::Invalid("conflicting header operations"));
            }
            let (name, occurrence) = occurrence(index)?;
            modifications.push(Modification::ChangeHeader {
                occurrence,
                name,
                value: value.unwrap_or_default(),
            });
        }
        for (position, slot) in self.headers.iter().enumerate() {
            let Slot::Added(i) = slot else { continue };
            let Header { name, value } = self.added_headers[*i]
                .take()
                .expect("added header is emitted once");
            modifications.push(if position == self.headers.len() - 1 {
                Modification::AddHeader { name, value }
            } else {
                Modification::InsertHeader {
                    index: position as u32,
                    name,
                    value,
                }
            });
        }
        if let Some(from) = self.from {
            let (address, parameters) = from.milter(true)?;
            modifications.push(Modification::ChangeFrom {
                address,
                parameters,
            });
        }
        for index in self.recipient_deletes {
            let recipient = &session.message.recipients[index];
            modifications.push(Modification::DeleteRecipient(
                text(&recipient.address)?.to_owned(),
            ));
        }
        for added in self.added_recipients.into_iter().flatten() {
            let (address, parameters) = added.milter(false)?;
            modifications.push(Modification::AddRecipient {
                address,
                parameters,
            });
        }
        Ok(modifications)
    }
}
fn insert_slot(
    list: &mut Vec<Slot>,
    index: Option<u32>,
    slot: Slot,
    what: &'static str,
) -> Result<()> {
    match index {
        Some(index) if (index as usize) <= list.len() => list.insert(index as usize, slot),
        Some(_) => return Err(Error::Invalid(what)),
        None => list.push(slot),
    }
    Ok(())
}

/// Replace the milter-visible message. Keep an ordered subsequence of identical
/// original fields untouched, preserving their bytes (including signed fields).
fn raw_replacement(value: &Value, session: &Session) -> Result<Vec<Modification>> {
    let encoded = value.as_str().ok_or(Error::Invalid("raw message type"))?;
    if encoded.len() > session.limits.message_bytes.saturating_add(2) / 3 * 4 {
        return Err(Error::Limit("replacement message"));
    }
    let raw = STANDARD
        .decode(encoded)
        .map_err(|_| Error::Invalid("raw message base64"))?;
    if raw.len() > session.limits.message_bytes {
        return Err(Error::Limit("replacement message"));
    }
    let mut fields: Vec<(&[u8], &[u8])> = Vec::new();
    let mut offset = 0;
    let body_start = loop {
        let end = raw[offset..]
            .iter()
            .position(|&c| c == b'\n')
            .map(|n| offset + n)
            .ok_or(Error::Invalid("raw message headers"))?;
        let content_end = if end > offset && raw[end - 1] == b'\r' {
            end - 1
        } else {
            end
        };
        let line = &raw[offset..content_end];
        if line.is_empty() {
            break end + 1;
        }
        if matches!(line.first(), Some(b' ' | b'\t')) {
            let (_, value) = fields
                .last_mut()
                .ok_or(Error::Invalid("orphan continuation"))?;
            let start = value.as_ptr() as usize - raw.as_ptr() as usize;
            *value = &raw[start..content_end];
        } else {
            let colon = line
                .iter()
                .position(|&c| c == b':')
                .ok_or(Error::Invalid("raw header"))?;
            let name = &line[..colon];
            if name.is_empty() || !name.iter().all(|c| (33..=126).contains(c) && *c != b':') {
                return Err(Error::Invalid("raw header name"));
            }
            if fields.len() >= session.limits.headers {
                return Err(Error::Limit("replacement headers"));
            }
            fields.push((name, &raw[offset + colon + 1..content_end]));
        }
        offset = end + 1;
    };
    let original = &session.message.headers;
    let mut candidates: std::collections::BTreeMap<(&[u8], &[u8]), Vec<usize>> =
        std::collections::BTreeMap::new();
    let mut counts = std::collections::BTreeMap::new();
    let mut occurrences = Vec::with_capacity(original.len());
    for (i, (name, value)) in original.iter().enumerate() {
        candidates
            .entry((name.as_ref(), value.as_ref()))
            .or_default()
            .push(i);
        let count = counts.entry(name.to_ascii_lowercase()).or_insert(0u32);
        *count += 1;
        occurrences.push(*count);
    }
    let mut retained = vec![false; original.len()];
    let mut cursor = 0;
    let mut inserted = Vec::new();
    for (position, (name, value)) in fields.into_iter().enumerate() {
        let lookup = if session.leading_space() || matches!(value.first(), Some(b'\r' | b'\n')) {
            Some(value)
        } else {
            value.strip_prefix(b" ")
        };
        let matched = lookup
            .and_then(|value| candidates.get(&(name, value)))
            .and_then(|indices| indices.get(indices.partition_point(|&i| i < cursor)))
            .copied();
        if let Some(index) = matched {
            retained[index] = true;
            cursor = index + 1;
        } else {
            inserted.push(Modification::InsertRawHeader {
                index: position as u32,
                name: text(name)?.to_owned(),
                value: text(value)?.to_owned(),
            });
        }
    }
    let mut result = Vec::new();
    for i in (0..original.len()).rev() {
        if !retained[i] {
            let name = text(&original[i].0)?;
            result.push(Modification::ChangeHeader {
                occurrence: occurrences[i],
                name: name.to_owned(),
                value: String::new(),
            });
        }
    }
    result.extend(inserted);
    if raw[body_start..] != session.message.body {
        result.push(Modification::ReplaceBody(Bytes::copy_from_slice(
            &raw[body_start..],
        )));
    }
    if result.len() > session.limits.modifications {
        return Err(Error::Limit("replacement modifications"));
    }
    Ok(result)
}

/// No modification is emitted until the whole response is checked.
pub fn translate(value: Value, session: &Session, stage: Stage) -> Result<Decision> {
    let ops: Operations =
        serde_json::from_value(value).map_err(|_| Error::Invalid("hook response schema"))?;
    let count = ops.set.as_ref().map_or(0, Vec::len)
        + ops.add.as_ref().map_or(0, Vec::len)
        + ops.delete.as_ref().map_or(0, Vec::len);
    if count > session.limits.modifications {
        return Err(Error::Limit("hook operations"));
    }
    let mut action = "accept".to_owned();
    let mut response = Value::Null;
    let mut edits = Edits::new(session);
    let mut raw = None;
    let has_raw = ops
        .set
        .as_ref()
        .is_some_and(|sets| sets.iter().any(|s| s.path == "/rawMessage"));
    for set in ops.set.unwrap_or_default() {
        match set.path.as_str() {
            "/rawMessage" => {
                if raw.is_some() {
                    return Err(Error::Invalid("duplicate raw message replacement"));
                }
                raw = Some(raw_replacement(&set.value, session)?);
            }
            path if has_raw && (path == "/message" || path.starts_with("/message/")) => {}
            "/action" => {
                action = set
                    .value
                    .as_str()
                    .ok_or(Error::Invalid("action type"))?
                    .to_owned();
            }
            "/response" => {
                response = set.value;
            }
            "/response/code" | "/response/enhancedCode" | "/response/message" => {
                if response.is_null() {
                    response = json!({});
                }
                if !response.is_object() {
                    return Err(Error::Invalid("SMTP response object"));
                }
                response[set.path.rsplit('/').next().expect("path")] = set.value;
            }
            path => edits.set(session, path, set.value)?,
        }
    }
    for add in ops.add.unwrap_or_default() {
        if has_raw && (add.path == "/message" || add.path.starts_with("/message/")) {
            continue;
        }
        edits.add(session, add)?;
    }
    for delete in ops.delete.unwrap_or_default() {
        if has_raw && (delete.path == "/message" || delete.path.starts_with("/message/")) {
            continue;
        }
        edits.delete(&delete.path)?;
    }
    if stage != Stage::EndMessage && (!edits.is_empty() || raw.is_some()) {
        return Err(Error::Invalid(
            "message and envelope edits require the data stage",
        ));
    }
    let mut modifications = edits.modifications(session)?;
    if let Some(raw) = raw {
        modifications.extend(raw);
    }
    for m in &modifications {
        m.frames(session.leading_space())?;
    }
    let verdict = match action.as_str() {
        "accept" if response.is_null() => Verdict::Continue,
        "reject" => {
            if !response.is_null() && !response.is_object() {
                return Err(Error::Invalid("SMTP response object"));
            }
            let code = match response.get("code") {
                Some(c) => c
                    .as_u64()
                    .and_then(|c| u16::try_from(c).ok())
                    .ok_or(Error::Invalid("SMTP code"))?,
                None => 550,
            };
            let enhanced = match response.get("enhancedCode") {
                Some(v) if !v.is_null() => Some(
                    v.as_str()
                        .ok_or(Error::Invalid("enhanced SMTP code"))?
                        .to_owned(),
                ),
                _ => None,
            };
            let message = match response.get("message") {
                Some(v) => v.as_str().ok_or(Error::Invalid("SMTP response text"))?,
                None => "Rejected by policy",
            }
            .to_owned();
            Verdict::Reply {
                code,
                enhanced,
                message,
            }
        }
        // The milter protocol has no discard before MAIL; Postfix ignores it.
        "discard" if response.is_null() && !matches!(stage, Stage::Connect | Stage::Helo) => {
            Verdict::Discard
        }
        "quarantine" if response.is_null() && stage == Stage::EndMessage => {
            modifications.push(Modification::Quarantine("MTA Hooks policy".into()));
            Verdict::Continue
        }
        // Postfix replies "421 4.7.0 Server closing connection" itself.
        "disconnect" if response.is_null() => Verdict::Shutdown,
        _ => {
            return Err(Error::Invalid(
                "unsupported action, stage or SMTP response combination",
            ));
        }
    };
    Ok(Decision {
        verdict,
        modifications,
    })
}
