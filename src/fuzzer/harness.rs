use libafl::executors::ExitKind;
use rand::Rng;

use crate::trace::{Trace, TraceContext};

pub fn harness(input: &Trace) -> ExitKind {
    let mut ctx = TraceContext::new();
    input.execute(&mut ctx);
    ExitKind::Ok // Everything other than Ok is recorded in the crash corpus
}

pub fn dummy_harness(input: &Trace) -> ExitKind {
    let mut rng = rand::thread_rng();

    let n1 = rng.gen_range(0..10);
    //println!("Run {}", n1);
    if n1 <= 5 {
        return ExitKind::Timeout;
    }
    ExitKind::Ok
}
