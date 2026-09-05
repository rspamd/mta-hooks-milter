//! Scanner transport configuration. Secrets are not included in Debug output.
use crate::protocol::{Error, HttpErrorKind, Result};
use base64::{Engine, engine::general_purpose::STANDARD};
use reqwest::{Certificate, Client, Identity, Url, header::HeaderValue};
use std::{io::Read, path::Path, time::Duration};

/// Prevalidated Authorization header, marked sensitive for HTTP diagnostics.
#[derive(Clone, Debug)]
pub struct Authentication(HeaderValue);

impl Authentication {
    pub fn bearer(token: &str) -> Result<Self> {
        if token.is_empty()
            || token
                .bytes()
                .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
        {
            return Err(Error::Invalid("nonempty single-line bearer token required"));
        }
        Self::header(format!("Bearer {token}"))
    }

    pub fn basic(username: &str, password: &str) -> Result<Self> {
        if username.is_empty()
            || username.contains(':')
            || password.is_empty()
            || username
                .bytes()
                .chain(password.bytes())
                .any(|b| b.is_ascii_control())
        {
            return Err(Error::Invalid("invalid basic credentials"));
        }
        Self::header(format!(
            "Basic {}",
            STANDARD.encode(format!("{username}:{password}"))
        ))
    }

    fn header(value: String) -> Result<Self> {
        let mut value = HeaderValue::from_str(&value)
            .map_err(|_| Error::Invalid("invalid authorization header"))?;
        value.set_sensitive(true);
        Ok(Self(value))
    }

    pub(crate) fn value(&self) -> HeaderValue {
        self.0.clone()
    }
}

#[derive(Default)]
pub enum ProxyMode {
    /// Reqwest's environment proxy and NO_PROXY behavior.
    #[default]
    Environment,
    Disabled,
    /// Explicit HTTP(S) proxy; environment settings, including NO_PROXY, ignored.
    Explicit(Url),
}

/// Shared by registration and hook requests. Does not alter the total policy deadline.
pub struct TransportOptions {
    pub root_certificates: Vec<Certificate>,
    pub built_in_roots: bool,
    /// PEM certificate chain and private key, parsed by reqwest.
    pub identity: Option<Identity>,
    pub proxy: ProxyMode,
    pub connect_timeout: Duration,
    pub pool_idle_timeout: Duration,
    /// Idle sockets only; this does not cap active requests.
    pub pool_max_idle_per_host: usize,
    /// Response decompression only. Outgoing mail JSON is never compressed.
    pub gzip: bool,
}

impl Default for TransportOptions {
    fn default() -> Self {
        Self {
            root_certificates: vec![],
            built_in_roots: true,
            identity: None,
            proxy: ProxyMode::Environment,
            connect_timeout: Duration::from_secs(5),
            pool_idle_timeout: Duration::from_secs(90),
            pool_max_idle_per_host: 16,
            gzip: false,
        }
    }
}

impl TransportOptions {
    pub(crate) fn build(self, timeout: Duration) -> Result<Client> {
        if timeout.is_zero() || self.connect_timeout.is_zero() || self.pool_idle_timeout.is_zero() {
            return Err(Error::Invalid("HTTP timeouts must be positive"));
        }
        if !self.built_in_roots && self.root_certificates.is_empty() {
            return Err(Error::Invalid("custom-only trust requires a root CA"));
        }
        let mut builder = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(timeout)
            .connect_timeout(timeout.min(self.connect_timeout))
            .pool_idle_timeout(self.pool_idle_timeout)
            .pool_max_idle_per_host(self.pool_max_idle_per_host)
            .tls_built_in_root_certs(self.built_in_roots)
            .gzip(self.gzip);
        for certificate in self.root_certificates {
            builder = builder.add_root_certificate(certificate);
        }
        if let Some(identity) = self.identity {
            builder = builder.identity(identity);
        }
        builder = match self.proxy {
            ProxyMode::Environment => builder,
            ProxyMode::Disabled => builder.no_proxy(),
            ProxyMode::Explicit(url) => {
                if !matches!(url.scheme(), "http" | "https")
                    || url.host_str().is_none()
                    || !url.username().is_empty()
                    || url.password().is_some()
                    || url.query().is_some()
                    || url.fragment().is_some()
                    || url.path() != "/"
                {
                    return Err(Error::Invalid(
                        "proxy must be an HTTP(S) origin without credentials",
                    ));
                }
                builder
                    .no_proxy()
                    .proxy(reqwest::Proxy::all(url).map_err(http_error)?)
            }
        };
        builder.build().map_err(http_error)
    }
}

/// Read once at startup, with a size bound. Errors intentionally omit the path.
pub fn read_config_file(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let file =
        std::fs::File::open(path).map_err(|_| Error::Invalid("cannot open credential/CA file"))?;
    if !file
        .metadata()
        .map_err(|_| Error::Invalid("cannot stat credential/CA file"))?
        .is_file()
    {
        return Err(Error::Invalid("credential/CA file must be a regular file"));
    }
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::Invalid("cannot read credential/CA file"))?;
    if bytes.len() > limit {
        return Err(Error::Limit("credential/CA file"));
    }
    Ok(bytes)
}

/// Accept one optional trailing LF/CRLF, without trimming password spaces.
pub fn read_secret_file(path: &Path) -> Result<String> {
    let mut secret = String::from_utf8(read_config_file(path, 8192)?)
        .map_err(|_| Error::Invalid("credential file must be UTF-8"))?;
    if secret.ends_with('\n') {
        secret.pop();
        if secret.ends_with('\r') {
            secret.pop();
        }
    }
    if secret.is_empty() || secret.bytes().any(|b| b.is_ascii_control()) {
        return Err(Error::Invalid(
            "credential file must contain one nonempty line",
        ));
    }
    Ok(secret)
}

pub(crate) fn http_error(error: reqwest::Error) -> Error {
    let kind = if error.is_timeout() {
        HttpErrorKind::Timeout
    } else if error.is_connect() {
        HttpErrorKind::Connect
    } else if error.is_decode() {
        HttpErrorKind::Decode
    } else if error.is_body() {
        HttpErrorKind::Body
    } else if error.is_request() || error.is_builder() {
        HttpErrorKind::Request
    } else {
        HttpErrorKind::Other
    };
    Error::HttpTransport(kind)
}
