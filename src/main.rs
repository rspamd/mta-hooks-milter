use clap::{Parser, ValueEnum};
use mta_hooks_milter::{
    hooks::HooksClient,
    http,
    server::{self, Config, Listener, Passthrough, Policy, Stats},
    transport::{Authentication, ProxyMode, TransportOptions, read_config_file, read_secret_file},
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
#[command(group(clap::ArgGroup::new("scanner_auth").args(["scanner_token", "scanner_token_file", "scanner_basic_user"])))]
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
    #[arg(long, requires = "scanner_auth")]
    scanner: Option<reqwest::Url>,
    #[arg(long, env = "MTA_HOOKS_TOKEN", hide_env_values = true)]
    scanner_token: Option<String>,
    /// Read the bearer token once at startup (at most 8 KiB).
    #[arg(long, requires = "scanner")]
    scanner_token_file: Option<PathBuf>,
    /// Basic authentication username; requires a password file.
    #[arg(long, requires_all = ["scanner", "scanner_basic_password_file"])]
    scanner_basic_user: Option<String>,
    #[arg(long, requires = "scanner_basic_user")]
    scanner_basic_password_file: Option<PathBuf>,
    /// Additional PEM root CA bundle; repeat for multiple files.
    #[arg(long, requires = "scanner")]
    scanner_ca: Vec<PathBuf>,
    /// Trust only --scanner-ca certificates, excluding built-in roots.
    #[arg(long, requires = "scanner_ca")]
    scanner_custom_roots_only: bool,
    /// PEM client certificate chain and private key for mutual TLS.
    #[arg(long, requires = "scanner")]
    scanner_identity: Option<PathBuf>,
    /// Explicit HTTP(S) proxy origin (no URL credentials); ignores environment proxies.
    #[arg(long, requires = "scanner", conflicts_with = "scanner_no_proxy")]
    scanner_proxy: Option<reqwest::Url>,
    /// Disable all environment/system proxies, including for loopback development.
    #[arg(long, requires = "scanner")]
    scanner_no_proxy: bool,
    #[arg(long, default_value_t = 5000, value_parser=clap::value_parser!(u64).range(1..))]
    scanner_connect_timeout_ms: u64,
    #[arg(long, default_value_t = 90000, value_parser=clap::value_parser!(u64).range(1..))]
    scanner_pool_idle_timeout_ms: u64,
    /// Idle connections retained per host, not an active request limit; 0 disables pooling.
    #[arg(long, default_value_t = 16)]
    scanner_pool_max_idle: usize,
    /// Accept/decompress gzip responses; does not compress outgoing JSON.
    #[arg(long, requires = "scanner")]
    scanner_gzip: bool,
    #[arg(long, value_enum, default_value_t = LogFormat::Text)]
    log_format: LogFormat,
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

#[derive(Clone, Copy, Debug, ValueEnum)]
enum LogFormat {
    Text,
    Json,
}

impl Args {
    fn authentication(&self) -> mta_hooks_milter::protocol::Result<Authentication> {
        if let Some(path) = &self.scanner_token_file {
            Authentication::bearer(&read_secret_file(path)?)
        } else if let Some(user) = &self.scanner_basic_user {
            Authentication::basic(
                user,
                &read_secret_file(
                    self.scanner_basic_password_file
                        .as_ref()
                        .expect("clap requires password file"),
                )?,
            )
        } else {
            Authentication::bearer(
                self.scanner_token
                    .as_deref()
                    .expect("clap requires scanner authentication"),
            )
        }
    }
    fn transport(&self) -> mta_hooks_milter::protocol::Result<TransportOptions> {
        use mta_hooks_milter::protocol::Error;
        let mut root_certificates = Vec::new();
        for path in &self.scanner_ca {
            let certs =
                reqwest::Certificate::from_pem_bundle(&read_config_file(path, 1024 * 1024)?)
                    .map_err(|_| Error::Invalid("invalid scanner CA bundle"))?;
            if certs.is_empty() {
                return Err(Error::Invalid("empty scanner CA bundle"));
            }
            root_certificates.extend(certs);
        }
        let identity = self
            .scanner_identity
            .as_ref()
            .map(|path| {
                reqwest::Identity::from_pem(&read_config_file(path, 1024 * 1024)?)
                    .map_err(|_| Error::Invalid("invalid scanner client identity PEM"))
            })
            .transpose()?;
        Ok(TransportOptions {
            root_certificates,
            built_in_roots: !self.scanner_custom_roots_only,
            identity,
            proxy: if self.scanner_no_proxy {
                ProxyMode::Disabled
            } else if let Some(url) = &self.scanner_proxy {
                ProxyMode::Explicit(url.clone())
            } else {
                ProxyMode::Environment
            },
            connect_timeout: Duration::from_millis(self.scanner_connect_timeout_ms),
            pool_idle_timeout: Duration::from_millis(self.scanner_pool_idle_timeout_ms),
            pool_max_idle_per_host: self.scanner_pool_max_idle,
            gzip: self.scanner_gzip,
        })
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let logging = tracing_subscriber::fmt().with_env_filter(
        tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
    );
    match args.log_format {
        LogFormat::Text => logging.init(),
        LogFormat::Json => logging.json().init(),
    }
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
    let stats = Arc::new(Stats::default());
    let policy: Arc<dyn Policy> = if let Some(url) = &args.scanner {
        Arc::new(
            HooksClient::with_options(
                url.clone(),
                args.authentication()?,
                args.name.clone(),
                config.policy_timeout,
                args.insecure_loopback,
                args.transport()?,
                stats.clone(),
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
    fn scanner_auth_and_transport_cli_validation() {
        let base = ["bridge", "--scanner", "https://example.test/register"];
        for extra in [
            vec![],
            vec!["--scanner-basic-user", "user"],
            vec![
                "--scanner-token",
                "synthetic",
                "--scanner-token-file",
                "token",
            ],
            vec![
                "--scanner-token",
                "synthetic",
                "--scanner-basic-user",
                "user",
                "--scanner-basic-password-file",
                "password",
            ],
            vec![
                "--scanner-token",
                "synthetic",
                "--scanner-no-proxy",
                "--scanner-proxy",
                "http://127.0.0.1:1",
            ],
            vec![
                "--scanner-token",
                "synthetic",
                "--scanner-connect-timeout-ms",
                "0",
            ],
            vec![
                "--scanner-token",
                "synthetic",
                "--scanner-pool-idle-timeout-ms",
                "0",
            ],
            vec![
                "--scanner-token",
                "synthetic",
                "--scanner-custom-roots-only",
            ],
        ] {
            assert!(Args::try_parse_from(base.into_iter().chain(extra)).is_err());
        }
        for extra in [
            vec!["--scanner-token-file", "token"],
            vec![
                "--scanner-basic-user",
                "user",
                "--scanner-basic-password-file",
                "password",
            ],
            vec![
                "--scanner-token",
                "synthetic",
                "--scanner-no-proxy",
                "--scanner-gzip",
                "--log-format",
                "json",
                "--scanner-pool-max-idle",
                "0",
            ],
        ] {
            assert!(Args::try_parse_from(base.into_iter().chain(extra)).is_ok());
        }
    }

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
