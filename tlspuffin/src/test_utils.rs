use nix::{
    sys::{
        signal::Signal,
        wait::{
            waitpid, WaitPidFlag,
            WaitStatus::{Exited, Signaled},
        },
    },
    unistd::{fork, ForkResult},
};

pub fn expect_crash<R>(mut func: R)
where
    R: FnMut(),
{
    match unsafe { fork() } {
        Ok(ForkResult::Parent { child, .. }) => {
            let status = waitpid(child, Option::from(WaitPidFlag::empty())).unwrap();

            if let Signaled(_, signal, _) = status {
                if signal != Signal::SIGSEGV && signal != Signal::SIGABRT {
                    panic!("Trace did not crash with SIGSEGV/SIGABRT!")
                }
            } else if let Exited(_, code) = status {
                if code == 0 {
                    panic!("Trace did not crash exit with non-zero code (AddressSanitizer)!")
                }
            } else {
                panic!("Trace did not signal!")
            }
        }
        Ok(ForkResult::Child) => {
            func();
            std::process::exit(0);
        }
        Err(_) => panic!("Fork failed"),
    }
}
