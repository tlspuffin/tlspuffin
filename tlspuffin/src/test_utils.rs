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
use puffin::{algebra::Matcher, put::PutOptions, trace::Trace};

use crate::{
    put_registry::TLS_PUT_REGISTRY,
    query::TlsQueryMatcher,
    tls::{trace_helper::TraceExecutor, vulnerabilities::seed_cve_2022_38153, TLS_SIGNATURE},
};

pub fn expect_trace_crash(trace: Trace<TlsQueryMatcher>, default_put_options: PutOptions) {
    expect_crash(move || {
        // Ignore Rust errors
        let _ = trace.execute_deterministic(&TLS_PUT_REGISTRY, default_put_options);
    });
}

pub fn expect_crash<R>(mut func: R)
where
    R: FnOnce(),
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
