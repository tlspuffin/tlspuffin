use libafl::executors::ExitKind;
use rand::Rng;

use crate::trace::{Trace, TraceContext};

pub fn harness(input: &Trace) -> ExitKind {
    let mut ctx = TraceContext::new();
    // todo gurantee that the agents have the correct name
    ctx.new_openssl_agent(false);
    ctx.new_openssl_agent(true);
    input.execute(&mut ctx);
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
