use std::thread;
use std::time::Duration;

use nix::sys::signal::{kill, Signal};
use nix::sys::wait::WaitStatus::{Exited, Signaled};
use nix::sys::wait::{waitpid, WaitPidFlag};
use nix::unistd::{fork, ForkResult, Pid};

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

pub trait AssertExecution {
    fn expect_crash(self);
}

impl AssertExecution for Result<ExecutionStatus, String> {
    fn expect_crash(self) {
        use ExecutionStatus as S;
        match self {
            Ok(S::Failure(_)) | Ok(S::Crashed) => (),
            Ok(S::Timeout) => panic!("trace execution timed out"),
            Ok(S::Success) => panic!("expected trace execution to crash, but succeeded"),
            Err(reason) => panic!("trace execution error: {reason}"),
        }
    }
}
