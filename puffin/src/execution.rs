use std::fmt::Debug;
use std::sync::mpsc;
use std::time::Duration;

use nix::errno::Errno;
use nix::sys::signal::{kill, Signal};
use nix::sys::wait::WaitStatus::{self, Exited, Signaled};
use nix::sys::wait::{waitpid, WaitPidFlag};
use nix::unistd::{fork, ForkResult, Pid};

use crate::error::Error;
use crate::protocol::ProtocolBehavior;
use crate::put_registry::PutRegistry;
use crate::trace::{Spawner, Trace, TraceContext};

pub trait TraceRunner {
    type PB: ProtocolBehavior;
    type R;
    type E;

    fn execute<T>(self, trace: T) -> Result<Self::R, Self::E>
    where
        T: AsRef<Trace<<Self::PB as ProtocolBehavior>::ProtocolTypes>>;
}

#[derive(Debug, Clone)]
pub struct Runner<PB: ProtocolBehavior> {
    registry: PutRegistry<PB>,
    spawner: Spawner<PB>,
}

impl<PB: ProtocolBehavior> Runner<PB> {
    pub fn new(registry: impl Into<PutRegistry<PB>>, spawner: impl Into<Spawner<PB>>) -> Self {
        Self {
            registry: registry.into(),
            spawner: spawner.into(),
        }
    }
}

impl<PB: ProtocolBehavior> TraceRunner for &Runner<PB> {
    type E = Error;
    type PB = PB;
    type R = TraceContext<Self::PB>;

    fn execute<T>(self, trace: T) -> Result<Self::R, Self::E>
    where
        T: AsRef<Trace<<Self::PB as ProtocolBehavior>::ProtocolTypes>>,
    {
        // We reseed all PUTs before executing a trace!
        self.registry.determinism_reseed_all_factories();

        let mut ctx = TraceContext::new(self.spawner.clone());
        trace.as_ref().execute(&mut ctx)?;
        Ok(ctx)
    }
}

#[derive(Debug)]
pub struct ForkedRunner<T: TraceRunner> {
    runner: T,
    timeout: Option<Duration>,
}

impl<T: TraceRunner> ForkedRunner<T> {
    pub const fn new(runner: T) -> Self {
        Self {
            runner,
            timeout: None,
        }
    }

    pub fn with_timeout(mut self, timeout: impl Into<Option<Duration>>) -> Self {
        self.timeout = timeout.into();
        self
    }
}

impl<T> From<T> for ForkedRunner<T>
where
    T: TraceRunner,
{
    fn from(runner: T) -> Self {
        Self::new(runner)
    }
}

impl<T: TraceRunner + Clone> TraceRunner for &ForkedRunner<T> {
    type E = ForkError;
    type PB = T::PB;
    type R = ExecutionStatus;

    fn execute<Tr>(self, trace: Tr) -> Result<Self::R, Self::E>
    where
        Tr: AsRef<Trace<<Self::PB as ProtocolBehavior>::ProtocolTypes>>,
    {
        let runner = self.runner.clone();

        run_in_subprocess(
            || {
                let ret = match runner.execute(trace) {
                    Ok(_) => 0,
                    Err(_) => 1,
                };

                std::process::exit(ret);
            },
            self.timeout,
        )
    }
}

#[derive(Debug, Clone)]
pub struct DifferentialRunner<PB: ProtocolBehavior> {
    registry: PutRegistry<PB>,
    first_spawner: Spawner<PB>,
    second_spawner: Spawner<PB>,
}

impl<PB: ProtocolBehavior> DifferentialRunner<PB> {
    pub fn new(
        registry: impl Into<PutRegistry<PB>>,
        first_spawner: impl Into<Spawner<PB>>,
        second_spawner: impl Into<Spawner<PB>>,
    ) -> Self {
        Self {
            registry: registry.into(),
            first_spawner: first_spawner.into(),
            second_spawner: second_spawner.into(),
        }
    }
}

impl<PB: ProtocolBehavior> TraceRunner for &DifferentialRunner<PB> {
    type E = Error;
    type PB = PB;
    type R = TraceContext<Self::PB>;

    fn execute<T>(self, trace: T) -> Result<Self::R, Self::E>
    where
        T: AsRef<Trace<<Self::PB as ProtocolBehavior>::ProtocolTypes>>,
    {
        // We reseed all PUTs before executing a trace!
        self.registry.determinism_reseed_all_factories();

        log::info!("Executing first PUT");
        let mut first_ctx = TraceContext::new(self.first_spawner.clone());
        trace.as_ref().execute(&mut first_ctx)?;

        log::info!("Executing second PUT");
        let mut second_ctx = TraceContext::new(self.second_spawner.clone());
        trace.as_ref().execute(&mut second_ctx)?;

        let is_diff = first_ctx.compare(&second_ctx);

        if let Err(_) = is_diff {
            println!("Difference between the PUTs");
            return Err(Error::Difference("ERROR".into()));
        }

        Ok(first_ctx)
    }
}

#[derive(Debug, Clone)]
pub struct ForkError {
    reason: String,
}

impl std::fmt::Display for ForkError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "forked trace execution error: {}", self.reason)
    }
}

impl From<Errno> for ForkError {
    fn from(e: Errno) -> Self {
        Self {
            reason: e.to_string(),
        }
    }
}

pub fn run_in_subprocess<R>(
    func: R,
    timeout: impl Into<Option<Duration>>,
) -> Result<ExecutionStatus, ForkError>
where
    R: FnOnce(),
{
    fn do_fork<R>(f: R) -> Result<Pid, ForkError>
    where
        R: FnOnce(),
    {
        match unsafe { fork() }? {
            ForkResult::Parent { child, .. } => Ok(child),
            ForkResult::Child => {
                f();
                std::process::exit(0);
            }
        }
    }

    fn collect_child(child_pid: impl Into<Pid>) -> Result<ExecutionStatus, ForkError> {
        let pid = child_pid.into();
        waitpid(pid, Some(WaitPidFlag::WNOHANG))
            .try_into()
            .or_else(|e| {
                // NOTE Child process has not terminated yet. We kill it.
                if let Err(errno @ (Errno::EINVAL | Errno::EPERM)) = kill(pid, Signal::SIGKILL) {
                    log::error!("kill({pid}, SIGKILL) failed: {errno}");
                    return Err(e);
                }

                waitpid(pid, Some(WaitPidFlag::empty())).try_into()
            })
    }

    let executor_pid = do_fork(func)?;

    let mut watchdog = WatchDog::new();
    let mut signals = signal_hook::iterator::SignalsInfo::<
        signal_hook::iterator::exfiltrator::WithOrigin,
    >::new([signal_hook::consts::SIGUSR1, signal_hook::consts::SIGCHLD])
    .map_err(|e| ForkError {
        reason: format!("failed to register signal handlers: {e}"),
    })?;

    watchdog.start(timeout.into());

    let mut result = ExecutionStatus::Timeout;
    for info in &mut signals {
        let source = info.process.map(|p| p.pid);
        result = match info.signal {
            signal_hook::consts::SIGUSR1 if source == Some(std::process::id() as i32) => {
                collect_child(executor_pid).ok();
                ExecutionStatus::Timeout
            }
            signal_hook::consts::SIGCHLD if source == Some(executor_pid.as_raw()) => {
                collect_child(executor_pid)?
            }
            _ => {
                continue;
            }
        };
        break;
    }

    Ok(result)
}

struct WatchDog {
    channel: Option<mpsc::Sender<()>>,
}

impl WatchDog {
    pub const fn new() -> Self {
        Self { channel: None }
    }

    pub fn start(&mut self, timeout: Option<Duration>) {
        let duration = if let Some(duration) = timeout {
            duration
        } else {
            return;
        };

        let (send, recv) = mpsc::channel::<()>();
        self.channel = Some(send);

        std::thread::spawn(move || {
            std::thread::sleep(duration);
            loop {
                kill(nix::unistd::Pid::this(), Signal::SIGUSR1).unwrap();
                if recv.recv_timeout(Duration::from_millis(200)).is_err() {
                    break;
                }
            }
        });
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ExecutionStatus {
    Timeout,
    Crashed,
    Success,
    Interrupted,
    Failure(i32),
}

impl TryFrom<Result<WaitStatus, Errno>> for ExecutionStatus {
    type Error = ForkError;

    fn try_from(status: Result<WaitStatus, Errno>) -> Result<Self, Self::Error> {
        match status {
            Ok(Signaled(_, Signal::SIGSEGV | Signal::SIGABRT, _)) => Ok(Self::Crashed),
            Ok(Signaled(_, _, _)) => Ok(Self::Interrupted),
            Ok(Exited(_, code)) => match code {
                0 => Ok(Self::Success),
                _ => Ok(Self::Failure(code)),
            },
            Ok(s) => Err(ForkError {
                reason: format!("failed to retrieve process status: {s:?}"),
            }),
            Err(e) => Err(ForkError {
                reason: format!("failed to retrieve process status: {e:?}"),
            }),
        }
    }
}
