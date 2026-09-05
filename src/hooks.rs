//! MTA Hooks draft-01 HTTP client: one scanner, JSON, data stage.
//! The registration schema in -01 does not actually negotiate updateProperties;
//! this implementation enforces its documented local update allowlist.
use crate::{
    protocol::{ADD_HEADERS, Error, Modification, QUARANTINE, Result},
    server::{Policy, PolicyFuture},
    session::{Decision, EnvelopeAddress, Session, Stage, Verdict},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::{DateTime, Utc};
use reqwest::{Client, Response, StatusCode, Url};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{sync::Arc, time::Duration};
use tokio::sync::Mutex;
use uuid::Uuid;

const PROPERTIES: &[&str] = &[
    "/stage",
    "/action",
    "/timestamp",
    "/protocol",
    "/rawMessage",
    "/envelope",
    "/queue",
    "/client",
];

#[derive(Clone)]
struct Registration {
    id: String,
    endpoint: Url,
    expires: Option<DateTime<Utc>>,
}
pub struct HooksClient {
    client: Client,
    registration_url: Url,
    token: String,
    name: String,
    timeout: Duration,
    response_limit: usize,
    insecure_loopback: bool,
    registration: Mutex<Option<Arc<Registration>>>,
}
impl HooksClient {
    pub async fn new(
        url: Url,
        token: String,
        name: String,
        timeout: Duration,
        insecure_loopback: bool,
    ) -> Result<Self> {
        validate_url(&url, insecure_loopback)?;
        if token.is_empty() {
            return Err(Error::Invalid("scanner credentials required"));
        }
        let client = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(timeout)
            .connect_timeout(timeout.min(Duration::from_secs(5)))
            .build()
            .map_err(http_error)?;
        let this = Self {
            client,
            registration_url: url,
            token,
            name,
            timeout,
            response_limit: 1024 * 1024,
            insecure_loopback,
            registration: Mutex::new(None),
        };
        // Fail startup visibly if the endpoint/credentials/registration are invalid.
        this.registered().await?;
        Ok(this)
    }
    async fn registered(&self) -> Result<Arc<Registration>> {
        let mut guard = self.registration.lock().await;
        if let Some(reg) = guard.as_ref()
            && reg
                .expires
                .is_none_or(|e| e > Utc::now() + chrono::Duration::seconds(5))
        {
            return Ok(reg.clone());
        }
        let response=self.client.post(self.registration_url.clone()).bearer_auth(&self.token).json(&json!({
            "name":self.name,"version":env!("CARGO_PKG_VERSION"),"timeoutMs":self.timeout.as_millis() as u64,
            "serialization":"json","inbound":{"stages":["data"],"properties":PROPERTIES},"outbound":null,
        })).send().await.map_err(http_error)?;
        if response.status() != StatusCode::CREATED {
            return Err(Error::Policy(format!(
                "registration HTTP {}",
                response.status().as_u16()
            )));
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
        if value["status"] != "active"
            || value["negotiated"]["serialization"] != "json"
            || value["negotiated"]["inbound"]["stages"] != json!(["data"])
        {
            return Err(Error::Invalid("incompatible registration"));
        }
        let props = value["negotiated"]["inbound"]["properties"]
            .as_array()
            .ok_or(Error::Invalid("registration properties"))?;
        if props.len() != PROPERTIES.len() || PROPERTIES.iter().any(|p| !props.contains(&json!(p)))
        {
            return Err(Error::Invalid(
                "scanner did not confirm required property profile",
            ));
        }
        let path = value["hookEndpoint"]
            .as_str()
            .ok_or(Error::Invalid("hook endpoint"))?;
        let endpoint = self
            .registration_url
            .join(path)
            .map_err(|_| Error::Invalid("hook endpoint URL"))?;
        validate_url(&endpoint, self.insecure_loopback)?;
        if endpoint.origin() != self.registration_url.origin() {
            return Err(Error::Invalid("cross-origin hook endpoint"));
        }
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
        let reg = Arc::new(Registration {
            id: id.to_owned(),
            endpoint,
            expires,
        });
        *guard = Some(reg.clone());
        Ok(reg)
    }
    async fn invoke(&self, session: &Session) -> Result<Decision> {
        let body = request(session)?;
        let request_id = Uuid::new_v4().to_string();
        let mut reg = self.registered().await?;
        // One recovery attempt, bounded together with registration by the policy deadline.
        for attempt in 0..2 {
            let response = self
                .client
                .post(reg.endpoint.clone())
                .bearer_auth(&self.token)
                .header("X-MTA-Hooks-Registration", &reg.id)
                .header("X-MTA-Hooks-Request-Id", &request_id)
                .json(&body)
                .send()
                .await
                .map_err(http_error)?;
            let status = response.status();
            if attempt == 0 && matches!(status, StatusCode::NOT_FOUND | StatusCode::GONE) {
                let mut guard = self.registration.lock().await;
                if guard.as_ref().is_some_and(|r| r.id == reg.id) {
                    *guard = None;
                }
                drop(guard);
                reg = self.registered().await?;
                continue;
            }
            if status == StatusCode::NO_CONTENT {
                return Ok(Decision::default());
            }
            if status != StatusCode::OK {
                return Err(Error::Policy(format!("hook HTTP {}", status.as_u16())));
            }
            return translate(bounded_json(response, self.response_limit).await?, session);
        }
        Err(Error::Policy("registration recovery exhausted".into()))
    }
}
impl Policy for HooksClient {
    fn stages(&self) -> Vec<Stage> {
        vec![Stage::EndMessage]
    }
    fn actions(&self) -> u32 {
        ADD_HEADERS | QUARANTINE
    }
    fn evaluate<'a>(&'a self, _: Stage, session: &'a Session) -> PolicyFuture<'a> {
        Box::pin(self.invoke(session))
    }
}
fn http_error(_: reqwest::Error) -> Error {
    Error::Policy("HTTP transport failure".into())
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
fn request(session: &Session) -> Result<Value> {
    let sender = session
        .message
        .sender
        .as_ref()
        .ok_or(Error::Invalid("missing sender"))?;
    let recipients = session
        .message
        .recipients
        .iter()
        .map(|r| address(r, false))
        .collect::<Result<Vec<_>>>()?;
    let queue = session
        .macro_value("i")
        .map(text)
        .transpose()?
        .map(|s| json!({"id":s}));
    let connection = session
        .connection
        .as_ref()
        .ok_or(Error::Invalid("missing connection"))?;
    let ip = session
        .macro_value("client_addr")
        .or(connection.address.as_deref())
        .map(text)
        .transpose()?;
    let ehlo = session.helo.as_deref().map(text).transpose()?;
    let mut client = json!({"ip":ip,"port":connection.port,"ehlo":ehlo});
    if let Some(ptr) = session.macro_value("client_ptr") {
        client["ptr"] = json!(text(ptr)?);
    }
    Ok(
        json!({"stage":"data","action":"accept","timestamp":Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis,true),
        "protocol":{"version":"1.0"},"rawMessage":STANDARD.encode(session.raw_message()),
        "envelope":{"from":address(sender,true)?,"to":recipients},"queue":queue,"client":client}),
    )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Operations {
    set: Option<Vec<Set>>,
    add: Option<Vec<Add>>,
    delete: Option<Vec<Value>>,
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
    value: Header,
    index: Option<u32>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    name: String,
    value: String,
}

/// Narrow update profile. No modification is emitted until the whole response is checked.
pub fn translate(value: Value, session: &Session) -> Result<Decision> {
    let ops: Operations =
        serde_json::from_value(value).map_err(|_| Error::Invalid("hook response schema"))?;
    let count = ops.set.as_ref().map_or(0, Vec::len)
        + ops.add.as_ref().map_or(0, Vec::len)
        + ops.delete.as_ref().map_or(0, Vec::len);
    if count > session.limits.modifications {
        return Err(Error::Limit("hook operations"));
    }
    if ops.delete.is_some_and(|v| !v.is_empty()) {
        return Err(Error::Invalid("delete outside supported update profile"));
    }
    let mut action = "accept".to_owned();
    let mut response = Value::Null;
    for set in ops.set.unwrap_or_default() {
        match set.path.as_str() {
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
            _ => return Err(Error::Invalid("set outside supported update profile")),
        }
    }
    let mut modifications = Vec::new();
    let mut header_count = session.message.headers.len();
    for add in ops.add.unwrap_or_default() {
        if add.path != "/message/headers" {
            return Err(Error::Invalid("add outside supported update profile"));
        }
        if header_count >= session.limits.headers {
            return Err(Error::Limit("headers after modifications"));
        }
        let Header { name, value } = add.value;
        let m = if let Some(index) = add.index {
            if index as usize > header_count {
                return Err(Error::Invalid("header insertion index"));
            }
            Modification::InsertHeader { index, name, value }
        } else {
            Modification::AddHeader { name, value }
        };
        m.frames(session.leading_space())?;
        modifications.push(m);
        header_count += 1;
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
        "discard" if response.is_null() => Verdict::Discard,
        "quarantine" if response.is_null() => {
            modifications.push(Modification::Quarantine("MTA Hooks policy".into()));
            Verdict::Continue
        }
        _ => {
            return Err(Error::Invalid(
                "unsupported action or SMTP response combination",
            ));
        }
    };
    Ok(Decision {
        verdict,
        modifications,
    })
}
