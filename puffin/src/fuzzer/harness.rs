use libafl::executors::ExitKind;
use log::{debug, info, trace, warn};
use once_cell::sync::OnceCell;
use rand::Rng;

use crate::algebra::TermType;
use crate::{
    error::Error,
    fuzzer::stats_stage::*,
    protocol::ProtocolBehavior,
    put::PutOptions,
    trace::{Action, Trace, TraceContext},
};

static DEFAULT_PUT_OPTIONS: OnceCell<PutOptions> = OnceCell::new();

/// Returns the current default put options which are used
pub fn default_put_options() -> &'static PutOptions {
    DEFAULT_PUT_OPTIONS
        .get()
        .expect("current default put options needs to be set")
}

pub fn set_default_put_options(default_put_options: PutOptions) -> Result<(), ()> {
    DEFAULT_PUT_OPTIONS
        .set(default_put_options)
        .map_err(|_err| ())
}

pub fn harness<PB: ProtocolBehavior + 'static>(input: &Trace<PB::Matcher>) -> ExitKind {
    debug!("Harness is called on trace with #{} steps", input.steps.len());
    let mut ctx = TraceContext::new(PB::registry(), default_put_options().clone());

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
            Error::Put(_) => PUT.increment(),
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
pub fn dummy_harness<PB: ProtocolBehavior + 'static>(_input: &Trace<PB::Matcher>) -> ExitKind {
    let mut rng = rand::thread_rng();

    let n1 = rng.gen_range(0..10);
    info!("Run {}", n1);
    if n1 <= 5 {
        return ExitKind::Timeout;
    }
    ExitKind::Ok // Everything other than Ok is recorded in the crash corpus
}
