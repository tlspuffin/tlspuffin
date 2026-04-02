use libafl::executors::ExitKind;
use rand::Rng;

use crate::algebra::TermType;
use crate::error::Error;
use crate::execution::{DifferentialRunner, Runner, TraceRunner};
use crate::fuzzer::feedback::FAIL_AT_STEP;
use crate::fuzzer::stats_stage::{
    HARNESS_EXEC, HARNESS_EXEC_AGENT_SUCCESS, HARNESS_EXEC_SUCCESS, NB_PAYLOAD, PAYLOAD_LENGTH,
    TERM_SIZE, TRACE_LENGTH,
};
use crate::protocol::{ProtocolBehavior, ProtocolTypes};
use crate::put::PutDescriptor;
use crate::put_registry::PutRegistry;
use crate::trace::{Action, ConfigTrace, Spawner, Trace};

pub fn harness<PB: ProtocolBehavior + 'static>(
    put_registry: &PutRegistry<PB>,
    put_descriptor: &PutDescriptor,
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
    let runner = Runner::new(
        put_registry.clone(),
        Spawner::new(put_registry.clone()).with_mapping(
            &input
                .descriptors
                .iter()
                .map(|d| (d.name, put_descriptor.clone()))
                .collect::<Vec<_>>(),
        ),
    );
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

pub fn differential_harness<PB: ProtocolBehavior + 'static>(
    put_registry: &PutRegistry<PB>,
    first_put: &PutDescriptor,
    second_put: &PutDescriptor,
    input: &Trace<PB::ProtocolTypes>,
) -> ExitKind {
    // Uniformize the put configuration
    let input = <PB::ProtocolTypes as ProtocolTypes>::differential_fuzzing_uniformise_put_config(
        input.clone(),
    );

    let runner = DifferentialRunner::new(
        put_registry.clone(),
        Spawner::new(put_registry.clone()).with_mapping(
            &input
                .descriptors
                .iter()
                .map(|d| (d.name, first_put.clone()))
                .collect::<Vec<_>>(),
        ),
        Spawner::new(put_registry.clone()).with_mapping(
            &input
                .descriptors
                .iter()
                .map(|d| (d.name, second_put.clone()))
                .collect::<Vec<_>>(),
        ),
    );

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

    let input_len = input.steps.len();
    let input_size = input.size();

    // Execute the trace
    let mut fail_at_step = 0;
    let exec_res = runner.execute_config(
        input,
        ConfigTrace {
            check_security_violation: false,
            ..Default::default()
        },
        &mut fail_at_step,
    );

    log::trace!(
        "[a:trace len={}/size={}/{fail_at_step}] [[harness] Executed until {fail_at_step}.",
        input_len,
        input_size,
    );
    FAIL_AT_STEP.set(Some(fail_at_step));

    match exec_res {
        Ok(ctx) => {
            HARNESS_EXEC_SUCCESS.increment();
            if cfg!(feature = "introspection") {
                if ctx.0.agents_successful() && ctx.1.agents_successful() {
                    HARNESS_EXEC_AGENT_SUCCESS.increment();
                }
            }
        }
        Err(err) => match &err {
            Error::SecurityClaim(msg) => {
                log::warn!("{}", msg);
                std::process::abort()
            }
            Error::Difference(diffs) => {
                log::warn!(
                    "{}",
                    diffs
                        .iter()
                        .map(|x| x.to_string())
                        .collect::<Vec<String>>()
                        .join("\n")
                );
                std::process::abort()
            }
            _ => (),
        },
    }

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
