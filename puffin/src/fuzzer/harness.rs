use libafl::executors::ExitKind;
use log::{info, trace, warn};
use once_cell::sync::Lazy;
use rand::Rng;

use crate::{
    error::Error,
    fuzzer::stats_stage::*,
    put_registry::{ProtocolBehavior, PutRegistry},
    trace::{Action, Trace, TraceContext},
};

/*static CURRENT_SIGNATURE: Lazy<Option<&'static PutRegistry>> = Lazy::new(|| None);

pub fn current_put_registry() -> &'static PutRegistry {
    CURRENT_SIGNATURE.expect("current put registry needs to be set")
}
*/
pub fn harness<PB: ProtocolBehavior + 'static>(input: &Trace) -> ExitKind {
    let mut ctx = TraceContext::new(PB::new_registry());

    TRACE_LENGTH.update(input.steps.len());

    for step in &input.steps {
        match &step.action {
            Action::Input(input) => {
                TERM_SIZE.update(input.recipe.size());
            }
            Action::Output(_) => {}
        }
    }

    if let Err(err) = input.execute(&mut ctx) {
        match &err {
            Error::Fn(_) => FN_ERROR.increment(),
            Error::Term(_e) => TERM.increment(),
            Error::OpenSSL(_) => OPENSSL.increment(),
            Error::IO(_) => IO.increment(),
            Error::Agent(_) => AGENT.increment(),
            Error::Stream(_) => STREAM.increment(),
            Error::Extraction() => EXTRACTION.increment(),
            Error::SecurityClaim(msg) => {
                warn!("{}", msg);
                std::process::abort()
            }
        }

        trace!("{}", err);
    }

    ExitKind::Ok
}

#[allow(unused)]
pub fn dummy_harness(_input: &Trace) -> ExitKind {
    let mut rng = rand::thread_rng();

    let n1 = rng.gen_range(0..10);
    info!("Run {}", n1);
    if n1 <= 5 {
        return ExitKind::Timeout;
    }
    ExitKind::Ok // Everything other than Ok is recorded in the crash corpus
}
