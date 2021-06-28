use libafl::executors::ExitKind;
use rand::Rng;

use crate::trace::{Trace, TraceContext};
use crate::error::Error;
use crate::fuzzer::error_observer::{increment, FN_ERROR, TERM, STREAM, OPENSSL, AGENT, IO, EXTRACTION};

pub fn harness(input: &Trace) -> ExitKind {
    let mut ctx = TraceContext::new();

    if let Err(err) = input.spawn_agents(&mut ctx) {
        trace!("{}", err);
    }

    if let Err(err) = input.execute(&mut ctx) {
        match &err {
            Error::Fn(_) => {
                increment(&FN_ERROR)
            },
            Error::Term(e) => {
                increment(&TERM)
            },
            Error::OpenSSL(_)=>  {
                increment(&OPENSSL)
            },
            Error::IO(_) => increment(&IO),
            Error::Agent(_) => increment(&AGENT),
            Error::Stream(_) => increment(&STREAM),
            Error::Extraction(_) => increment(&EXTRACTION),
        }

        trace!("{}", err);
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
