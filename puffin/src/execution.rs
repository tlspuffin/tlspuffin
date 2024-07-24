use std::thread;
use std::time::Duration;

use nix::sys::signal::{kill, Signal};
use nix::sys::wait::WaitStatus::{Exited, Signaled};
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
        T: AsRef<Trace<<Self::PB as ProtocolBehavior>::Matcher>>;
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
        T: AsRef<Trace<<Self::PB as ProtocolBehavior>::Matcher>>,
    {
        // We reseed all PUTs before executing a trace!
        self.registry.determinism_reseed_all_factories();

        let mut ctx = TraceContext::new(self.spawner.clone());
        trace.as_ref().execute(&mut ctx)?;
        Ok(ctx)
    }
}

pub fn forked_execution<R>(func: R, timeout: Option<Duration>) -> Result<ExecutionStatus, String>
where
    R: FnOnce(),
{
    match unsafe { fork() } {
        Ok(ForkResult::Parent { child, .. }) => {
            let status = waitpid(child, Option::from(WaitPidFlag::empty())).unwrap();

            if let Signaled(_, signal, _) = status {
                match signal {
                    Signal::SIGSEGV | Signal::SIGABRT => return Ok(ExecutionStatus::Crashed),
                    Signal::SIGUSR2 if timeout.is_some() => return Ok(ExecutionStatus::Timeout),
                    _ => {
                        return Err(format!(
                            "execution process finished with unexpected signal {}",
                            signal
                        ))
                    }
                }
            } else if let Exited(_, code) = status {
                if code == 0 {
                    return Ok(ExecutionStatus::Success);
                } else {
                    return Ok(ExecutionStatus::Failure(code));
                }
            }

            Err(format!(
                "execution process finished with unexpected status {:?}",
                status
            ))
        }
        Ok(ForkResult::Child) => {
            if let Some(t) = timeout {
                thread::spawn(move || {
                    thread::sleep(t);
                    kill(Pid::this(), Signal::SIGUSR2).ok();
                });
            }

            func();
            std::process::exit(0);
        }
        Err(e) => Err(format!("fork failed: {}", e)),
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ExecutionStatus {
    Timeout,
    Crashed,
    Success,
    Failure(i32),
}
