use libafl::executors::ExitKind;
use rand::Rng;

use crate::trace::{Trace, TraceContext};
use crate::error::Error;

pub fn harness(input: &Trace) -> ExitKind {
    let mut ctx = TraceContext::new();

    if let Err(err) = input.spawn_agents(&mut ctx) {
        match err {
            Error::Fn(err) => panic!("{}", err),
            Error::OpenSSL(err) => panic!("{}", err),
            Error::IO(err) => panic!("{}", err),
            Error::Agent(err) => panic!("{}", err),
            Error::Stream(err) => panic!("{}", err),
        }
    }

    if let Err(err) = input.execute(&mut ctx) {
        match err {
            Error::Fn(err) => panic!("{}", err),
            Error::OpenSSL(err) => panic!("{}", err),
            Error::IO(err) => panic!("{}", err),
            Error::Agent(err) => panic!("{}", err),
            Error::Stream(err) => panic!("{}", err),
        }
    }

    ExitKind::Ok
}

pub fn dummy_harness(_input: &Trace) -> ExitKind {
    let mut rng = rand::thread_rng();

    let n1 = rng.gen_range(0..10);
    println!("Run {}", n1);
    if n1 <= 5 {
        return ExitKind::Timeout;
    }
    ExitKind::Ok // Everything other than Ok is recorded in the crash corpus
}
