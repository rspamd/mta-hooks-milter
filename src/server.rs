pub use crate::stats::Stats;
use crate::{
    protocol::{self, Error, MacroLists, Result},
    session::{Decision, Limits, Session, Stage, Verdict},
};
use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, atomic::Ordering},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite},
    net::{TcpListener, UnixListener},
    sync::Semaphore,
    task::JoinSet,
    time::{timeout, timeout_at},
};
use tokio_util::sync::CancellationToken;
use tracing::Instrument;

pub type PolicyFuture<'a> = Pin<Box<dyn Future<Output = Result<Decision>> + Send + 'a>>;
/// Called serially per milter connection, concurrently across connections.
/// Policies cannot write wire replies themselves or retain mutable session state.
pub trait Policy: Send + Sync + 'static {
    fn stages(&self) -> Vec<Stage> {
        Stage::ALL.to_vec()
    }
    fn actions(&self) -> u32 {
        protocol::SUPPORTED_ACTIONS
    }
    /// Macro lists to request from the MTA during negotiation. The default
    /// keeps the MTA's own configuration; a non-empty request replaces all of it.
    fn macros(&self) -> MacroLists {
        MacroLists::default()
    }
    fn evaluate<'a>(&'a self, stage: Stage, session: &'a Session) -> PolicyFuture<'a>;
}
pub struct Passthrough;
impl Policy for Passthrough {
    fn stages(&self) -> Vec<Stage> {
        vec![]
    }
    fn actions(&self) -> u32 {
        0
    }
    fn evaluate<'a>(&'a self, _: Stage, _: &'a Session) -> PolicyFuture<'a> {
        Box::pin(async { Ok(Decision::default()) })
    }
}

#[derive(Clone, Debug)]
pub struct Config {
    pub limits: Limits,
    pub max_connections: usize,
    /// Time to the first byte of the next frame. None leaves idle handling to
    /// Postfix, whose SMTP session may be quiet between milter callbacks.
    pub idle_timeout: Option<Duration>,
    /// Absolute time to finish a frame after its first length byte arrives.
    pub frame_timeout: Duration,
    pub policy_timeout: Duration,
    /// Send SMFIR_PROGRESS at this interval while a callback is pending so the
    /// MTA's command/content timers do not expire before the policy deadline.
    pub progress_interval: Option<Duration>,
    pub write_timeout: Duration,
    pub shutdown_timeout: Duration,
    pub fail_open: bool,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            limits: Limits::default(),
            max_connections: 128,
            idle_timeout: None,
            frame_timeout: Duration::from_secs(60),
            policy_timeout: Duration::from_secs(20),
            progress_interval: Some(Duration::from_secs(10)),
            write_timeout: Duration::from_secs(10),
            shutdown_timeout: Duration::from_secs(30),
            fail_open: false,
        }
    }
}
struct Active(Arc<Stats>);
impl Drop for Active {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::Relaxed);
    }
}

pub async fn handle_connection<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    policy: &dyn Policy,
    config: &Config,
    stats: &Stats,
    stop: CancellationToken,
) -> Result<()> {
    let stages = policy.stages();
    let mut session = Session::new(config.limits.clone(), stages.clone(), policy.actions());
    session.request_macros(policy.macros());
    loop {
        let frame = tokio::select! {
            _=stop.cancelled()=>return Ok(()),
            result=read_next_frame(&mut stream,config)=>result?,
        };
        let Some(frame) = frame else {
            return Ok(());
        };
        let step = session.receive(frame)?;
        let mut frames = step.frames;
        if let Some(stage) = step.event {
            if stage == Stage::EndMessage {
                stats.messages.fetch_add(1, Ordering::Relaxed);
            }
            let observation = stages.contains(&stage).then(|| stats.policy.begin());
            let result = if stages.contains(&stage) {
                // Any frame already queued (none for callback stages) is flushed first
                // so progress notifications never interleave with an earlier reply.
                let deadline = tokio::time::Instant::now() + config.policy_timeout;
                let evaluation = policy.evaluate(stage, &session);
                evaluate_with_progress(&mut stream, evaluation, deadline, config, stats).await
            } else {
                Ok(Decision::default())
            };
            let result = result.and_then(|decision| session.complete(decision));
            if let Some(observation) = observation {
                observation.finish(&result);
            }
            match result {
                Ok(replies) => frames.extend(replies),
                Err(error) => {
                    stats.policy_errors.fetch_add(1, Ordering::Relaxed);
                    // Do not log HTTP errors with URLs: query strings can contain credentials.
                    tracing::warn!(
                        stage = stage.hook_name(),
                        kind = error.kind(),
                        "policy failed"
                    );
                    frames.extend(session.complete(Decision {
                        verdict: if config.fail_open {
                            Verdict::Continue
                        } else {
                            Verdict::Tempfail
                        },
                        modifications: vec![],
                    })?);
                }
            }
        }
        // Complete an in-flight callback and drain its response before graceful stop.
        timeout(config.write_timeout, async {
            for frame in frames {
                protocol::write_frame(&mut stream, &frame).await?;
            }
            Ok::<_, Error>(())
        })
        .await
        .map_err(|_| Error::Timeout)??;
        if step.close {
            return Ok(());
        }
    }
}
/// Drive a policy future to its deadline, emitting SMFIR_PROGRESS keepalives.
/// A failed keepalive write is fatal for the connection: the MTA is gone.
async fn evaluate_with_progress<S: AsyncWrite + Unpin>(
    stream: &mut S,
    evaluation: PolicyFuture<'_>,
    deadline: tokio::time::Instant,
    config: &Config,
    stats: &Stats,
) -> Result<Decision> {
    let mut evaluation = std::pin::pin!(timeout_at(deadline, evaluation));
    let Some(interval) = config.progress_interval else {
        return evaluation.await.map_err(|_| Error::Timeout)?;
    };
    let mut ticker = tokio::time::interval_at(tokio::time::Instant::now() + interval, interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let progress = protocol::Frame::empty(protocol::PROGRESS);
    loop {
        tokio::select! {
            result = &mut evaluation => return result.map_err(|_| Error::Timeout)?,
            _ = ticker.tick() => {
                stats.progress.fetch_add(1, Ordering::Relaxed);
                timeout(config.write_timeout, protocol::write_frame(stream, &progress))
                    .await
                    .map_err(|_| Error::Timeout)??;
            }
        }
    }
}
async fn read_next_frame<S: AsyncRead + Unpin>(
    stream: &mut S,
    config: &Config,
) -> Result<Option<protocol::Frame>> {
    let mut first = [0; 1];
    let read = stream.read(&mut first);
    let count = match config.idle_timeout {
        Some(idle) => timeout(idle, read).await.map_err(|_| Error::Timeout)??,
        None => read.await?,
    };
    if count == 0 {
        return Ok(None);
    }
    timeout(
        config.frame_timeout,
        protocol::read_frame_after_start(stream, first[0], config.limits.frame_bytes),
    )
    .await
    .map_err(|_| Error::Timeout)?
    .map(Some)
}

pub enum Listener {
    Tcp(TcpListener),
    Unix(UnixListener),
}
trait Io: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> Io for T {}
impl Listener {
    async fn accept(&self) -> std::io::Result<Box<dyn Io>> {
        match self {
            Self::Tcp(listener) => {
                let (s, _) = listener.accept().await?;
                s.set_nodelay(true)?;
                Ok(Box::new(s))
            }
            Self::Unix(listener) => {
                let (s, _) = listener.accept().await?;
                Ok(Box::new(s))
            }
        }
    }
}
pub async fn serve(
    listener: Listener,
    policy: Arc<dyn Policy>,
    config: Config,
    stats: Arc<Stats>,
    stop: CancellationToken,
) -> Result<()> {
    if config.max_connections == 0 {
        return Err(Error::Invalid("max_connections must be positive"));
    }
    let permits = Arc::new(Semaphore::new(config.max_connections));
    let mut tasks = JoinSet::new();
    let config = Arc::new(config);
    let transport = match &listener {
        Listener::Tcp(_) => "tcp",
        Listener::Unix(_) => "unix",
    };
    stats
        .listener
        .store(if transport == "tcp" { 1 } else { 2 }, Ordering::Relaxed);
    // Also clear listener state if the accept loop fails or its future is cancelled.
    struct ListenerState<'a>(&'a Stats);
    impl Drop for ListenerState<'_> {
        fn drop(&mut self) {
            self.0.listener.store(0, Ordering::Relaxed);
            self.0.ready.store(false, Ordering::Relaxed);
        }
    }
    let _listener_state = ListenerState(&stats);
    tracing::info!(transport, "milter listener started");
    loop {
        tokio::select! {
            _=stop.cancelled()=>break,
            joined=tasks.join_next(),if !tasks.is_empty()=>{
                if let Some(Err(error))=joined {
                    // Panic text from a custom policy may contain message data.
                    tracing::error!(panicked=error.is_panic(),cancelled=error.is_cancelled(),"connection task failed");
                }
            }
            accepted=listener.accept()=>{
                let stream=accepted?;
                let Ok(permit)=permits.clone().try_acquire_owned() else {
                    stats.overload.fetch_add(1,Ordering::Relaxed);drop(stream);continue;
                };
                stats.connections.fetch_add(1,Ordering::Relaxed);
                stats.active.fetch_add(1,Ordering::Relaxed);
                let active=Active(stats.clone());
                let (policy,config,stats,stop)=(policy.clone(),config.clone(),stats.clone(),stop.clone());
                let span = tracing::info_span!("milter_session", session_id=%uuid::Uuid::new_v4(), transport);
                tasks.spawn(async move {
                    let (_permit,_active)=(permit,active);
                    tracing::debug!("connection accepted");
                    if let Err(error)=handle_connection(stream,policy.as_ref(),&config,&stats,stop).await {
                        stats.connection_error(&error);
                        tracing::debug!(kind=error.kind(),"milter connection ended with error");
                    }
                    tracing::debug!("connection closed");
                }.instrument(span));
            }
        }
    }
    stats.ready.store(false, Ordering::Relaxed);
    stats.listener.store(0, Ordering::Relaxed);
    tracing::info!(connections = tasks.len(), "draining milter connections");
    if timeout(config.shutdown_timeout, async {
        while tasks.join_next().await.is_some() {}
    })
    .await
    .is_err()
    {
        stats.drain_forced.fetch_add(1, Ordering::Relaxed);
        tracing::warn!(
            connections = tasks.len(),
            "milter drain deadline exceeded; aborting remaining tasks"
        );
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    } else {
        stats.drain_graceful.fetch_add(1, Ordering::Relaxed);
        tracing::info!("milter drain completed");
    }
    Ok(())
}
