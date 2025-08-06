use std::fmt::{Debug, Display};
use std::sync::mpsc;
use std::time::Duration;

use nix::errno::Errno;
use nix::sys::signal::{kill, Signal};
use nix::sys::wait::WaitStatus::{self, Exited, Signaled};
use nix::sys::wait::{waitpid, WaitPidFlag};
use nix::unistd::{fork, ForkResult, Pid};

use crate::error::Error;
use crate::protocol::{ProtocolBehavior, ProtocolTypes};
use crate::put_registry::PutRegistry;
use crate::trace::{Spawner, Trace, TraceContext};

pub trait TraceRunner {
    type PB: ProtocolBehavior;
    type R;
    type E: Display;

    fn execute<T>(self, trace: T, executed_until: &mut usize) -> Result<Self::R, Self::E>
    where
        Self: Sized,
        T: AsRef<Trace<<Self::PB as ProtocolBehavior>::ProtocolTypes>>,
    {
        self.execute_config(trace, true, executed_until)
    }

    fn execute_config<T>(
        self,
        trace: T,
        with_reseed: bool,
        executed_until: &mut usize,
    ) -> Result<Self::R, Self::E>
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

    fn execute_config<T>(
        self,
        trace: T,
        with_reseed: bool,
        executed_until: &mut usize,
    ) -> Result<Self::R, Self::E>
    where
        T: AsRef<Trace<<Self::PB as ProtocolBehavior>::ProtocolTypes>>,
    {
        if with_reseed {
            // We reseed all PUTs before executing a trace!
            self.registry.determinism_reseed_all_factories();
        }

        let mut ctx = TraceContext::new(self.spawner.clone());
        trace.as_ref().execute(&mut ctx, &mut 0).map_err(|e| {
            *executed_until = ctx.executed_until;
            e
        })?;
        *executed_until = ctx.executed_until;
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

    fn execute_config<Tr>(
        self,
        trace: Tr,
        with_reseed: bool,
        executed_until: &mut usize,
    ) -> Result<Self::R, Self::E>
    where
        Tr: AsRef<Trace<<Self::PB as ProtocolBehavior>::ProtocolTypes>>,
    {
        let runner = self.runner.clone();

        run_in_subprocess(
            || {
                let ret = match runner.execute_config(trace, with_reseed, executed_until) {
                    Ok(_) => 0,
                    Err(e) => {
                        log::info!("{}", e);
                        1
                    }
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

    fn execute_config<T>(
        self,
        trace: T,
        with_reseed: bool,
        executed_until: &mut usize,
    ) -> Result<Self::R, Self::E>
    where
        T: AsRef<Trace<<Self::PB as ProtocolBehavior>::ProtocolTypes>>,
    {
        if with_reseed {
            // We reseed all PUTs before executing a trace!
            self.registry.determinism_reseed_all_factories();
        }

        log::info!("Executing first PUT");
        let mut first_ctx = TraceContext::new(self.first_spawner.clone());
        let first_trace_status = trace.as_ref().execute(&mut first_ctx, &mut 0);

        log::info!("Executing second PUT");
        let mut second_ctx = TraceContext::new(self.second_spawner.clone());
        let second_trace_status = trace.as_ref().execute(&mut second_ctx, &mut 0);

        // check status fist
        match (&first_trace_status, &second_trace_status) {
            (Err(Error::Put(put1_error)), Err(Error::Put(put2_error))) => {
                // If both PUT fail at the same step we consider that they fail for the same
                // reason
                if first_ctx.executed_until != second_ctx.executed_until {
                    return Err(crate::differential::StatusDiff {
                        first_executed_steps: first_ctx.executed_until,
                        first_status: put1_error.to_string(),
                        second_executed_steps: second_ctx.executed_until,
                        second_status: put2_error.to_string(),
                        total_step: trace.as_ref().steps.len(),
                    }
                    .as_trace_difference()
                    .as_error());
                }
            }
            (Err(Error::Put(put1_error)), second_put_status) => {
                return Err(crate::differential::StatusDiff {
                    first_executed_steps: first_ctx.executed_until,
                    first_status: put1_error.to_string(),
                    second_executed_steps: second_ctx.executed_until,
                    second_status: match second_put_status {
                        Ok(_) => "Success".into(),
                        Err(e) => e.to_string(),
                    },
                    total_step: trace.as_ref().steps.len(),
                }
                .as_trace_difference()
                .as_error());
            }
            (first_put_status, Err(Error::Put(put2_error))) => {
                return Err(crate::differential::StatusDiff {
                    first_executed_steps: first_ctx.executed_until,
                    first_status: match first_put_status {
                        Ok(_) => "Success".into(),
                        Err(e) => e.to_string(),
                    },
                    second_executed_steps: second_ctx.executed_until,
                    second_status: put2_error.to_string(),
                    total_step: trace.as_ref().steps.len(),
                }
                .as_trace_difference()
                .as_error());
            }
            _ => (),
        }

        *executed_until = usize::max(first_ctx.executed_until, second_ctx.executed_until);

        //check if we have security claim violation
        let mut diff = match (&first_trace_status, &second_trace_status) {
            (Err(Error::SecurityClaim(put1_err)), Err(Error::SecurityClaim(put2_err))) => {
                vec![crate::differential::SecurityClaimDiff::BothError {
                    first_put: put1_err.to_string(),
                    second_put: put2_err.to_string(),
                }
                .as_trace_difference()]
            }
            (Err(Error::SecurityClaim(put1_err)), _) => {
                vec![crate::differential::SecurityClaimDiff::Different {
                    put: 1,
                    claim: put1_err.to_string(),
                }
                .as_trace_difference()]
            }
            (_, Err(Error::SecurityClaim(put2_err))) => {
                vec![crate::differential::SecurityClaimDiff::Different {
                    put: 2,
                    claim: put2_err.to_string(),
                }
                .as_trace_difference()]
            }
            _ => vec![],
        };

        // Compare the trace context
        diff.extend(first_ctx.compare(&second_ctx, &trace.as_ref().descriptors));

        // Apply filter to remove false positives
        diff = diff
            .into_iter()
            .filter(<<PB as ProtocolBehavior>::ProtocolTypes as ProtocolTypes>::differential_fuzzing_filter_diff)
            .collect();

        if !diff.is_empty() {
            return Err(Error::Difference(diff));
        }

        Ok(first_ctx)
    }

    fn execute<T>(self, trace: T, executed_until: &mut usize) -> Result<Self::R, Self::E>
    where
        T: AsRef<Trace<<Self::PB as ProtocolBehavior>::ProtocolTypes>>,
    {
        self.execute_config(trace, true, executed_until)
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
