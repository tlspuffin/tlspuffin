use libafl::executors::ExitKind;
use rand::Rng;

use crate::trace::{Trace, TraceContext, Action};
use crate::error::Error;
use crate::fuzzer::stats_observer::*;

pub fn harness(input: &Trace) -> ExitKind {
    let mut ctx = TraceContext::new();

    TRACE_LENGTH.update(input.steps.len());

    for step in &input.steps {
        match &step.action {
            Action::Input(input) => {
                TERM_SIZE.update(input.recipe.size());
            }
            Action::Output(_) => {}
        }
    }

    if let Err(err) = input.spawn_agents(&mut ctx) {
        trace!("{}", err);
    }

    if let Err(err) = input.execute(&mut ctx) {
        match &err {
            Error::Fn(_) => {
                FN_ERROR.increment()
            },
            Error::Term(_e) => {
                TERM.increment()
            },
            Error::OpenSSL(_)=>  {
                OPENSSL.increment()
            },
            Error::IO(_) => IO.increment(),
            Error::Agent(_) => AGENT.increment(),
            Error::Stream(_) => STREAM.increment(),
            Error::Extraction(_) => EXTRACTION.increment(),
            Error::SecurityClaim(msg, claims) => {
                warn!("{} claims: {:?}", msg, claims);
                std::process::abort()
            }
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
