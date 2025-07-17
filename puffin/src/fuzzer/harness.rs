use libafl::executors::ExitKind;
use rand::Rng;

use crate::algebra::TermType;
use crate::execution::{Runner, TraceRunner};
use crate::fuzzer::feedback::FAIL_AT_STEP;
use crate::fuzzer::stats_stage::{
    HARNESS_EXEC, HARNESS_EXEC_AGENT_SUCCESS, HARNESS_EXEC_SUCCESS, NB_PAYLOAD, PAYLOAD_LENGTH,
    TERM_SIZE, TRACE_LENGTH,
};
use crate::protocol::ProtocolBehavior;
use crate::put_registry::PutRegistry;
use crate::trace::{Action, Spawner, Trace};

pub fn harness<PB: ProtocolBehavior + 'static>(
    put_registry: &PutRegistry<PB>,
    input: &Trace<PB::ProtocolTypes>,
) -> ExitKind {
    // Stats
    HARNESS_EXEC.increment();
    TRACE_LENGTH.update(input.steps.len());

    if cfg!(feature = "introspection") {
        NB_PAYLOAD.update(input.all_payloads().len());
        for payload in input.all_payloads() {
            PAYLOAD_LENGTH.update(payload.len());
        }
        for step in &input.steps {
            match &step.action {
                Action::Input(input) => {
                    TERM_SIZE.update(input.recipe.size());
                }
                Action::Output(_) => {}
            }
        }
    }
    // Execute the trace
    let runner = Runner::new(put_registry.clone(), Spawner::new(put_registry.clone()));
    let mut fail_at_step = 0;
    if let Ok(ctx) = runner.execute(input, &mut fail_at_step) {
        HARNESS_EXEC_SUCCESS.increment();
        if cfg!(feature = "introspection") {
            if ctx.agents_successful() {
                HARNESS_EXEC_AGENT_SUCCESS.increment();
            }
        }
    }

    // Update FAIL_AT_STEP
    log::trace!(
        "[a:trace len={}/size={}/{fail_at_step}] [[harness] Executed until {fail_at_step}.",
        input.steps.len(),
        input.size(),
    );
    FAIL_AT_STEP.set(Some(fail_at_step));

    ExitKind::Ok
}

#[allow(unused)]
#[must_use]
pub fn dummy_harness<PB: ProtocolBehavior + 'static>(
    _input: &Trace<PB::ProtocolTypes>,
) -> ExitKind {
    let mut rng = rand::thread_rng();

    let n1 = rng.gen_range(0..10);
    log::info!("Run {}", n1);
    if n1 <= 5 {
        return ExitKind::Timeout;
    }
    ExitKind::Ok // Everything other than Ok is recorded in the crash corpus
}
