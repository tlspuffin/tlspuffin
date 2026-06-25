use std::hash::{DefaultHasher, Hash, Hasher};

use libafl::executors::ExitKind;
use rand::Rng;

use crate::algebra::TermType;
use crate::claims::Claim;
use crate::error::Error;
use crate::execution::{DifferentialRunner, Runner, TraceRunner};
use crate::fuzzer::feedback::claim_observer::CAPTURED_CLAIMS;
use crate::fuzzer::objective_feedback::{FAIL_AT_STEP, OBJECTIVE_HASH, OBJECTIVE_TRIGGERED};
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
    OBJECTIVE_TRIGGERED.set(false);

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
    match runner.execute(input, &mut fail_at_step) {
        Ok(ctx) => {
            CAPTURED_CLAIMS.with(|captured| {
                let claims_borrow = ctx.claims.claims.borrow();
                let mut claim_keys: Vec<String> = Vec::new();
                for claim in claims_borrow.iter() {
                    let key = claim.format_content_normalized();
                    claim_keys.push(key);
                }
                *captured.borrow_mut() = Some(Box::new(claim_keys));
            });
            HARNESS_EXEC_SUCCESS.increment();
            if cfg!(feature = "introspection") && ctx.agents_successful() {
                HARNESS_EXEC_AGENT_SUCCESS.increment();
            }
        }
        Err(Error::SecurityClaim(msg)) => {
            log::warn!("{}", msg);
            OBJECTIVE_TRIGGERED.set(true);
        }
        Err(_) => {}
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
    OBJECTIVE_TRIGGERED.set(false);
    OBJECTIVE_HASH.set(None);

    // Uniformize the put configuration
    let input = <PB::ProtocolTypes as ProtocolTypes>::differential_fuzzing_uniformise_put_config(
        input.clone(),
    );

    // Map ALL agents in the trace (including prior traces) to the specified PUT.
    // Without this, agents in prior traces silently fall back to the default PUT.
    let first_mappings: Vec<_> = input
        .all_descriptors()
        .iter()
        .map(|d| (d.name, first_put.clone()))
        .collect();
    let second_mappings: Vec<_> = input
        .all_descriptors()
        .iter()
        .map(|d| (d.name, second_put.clone()))
        .collect();

    let runner = DifferentialRunner::new(
        put_registry.clone(),
        Spawner::new(put_registry.clone()).with_mapping(&first_mappings),
        Spawner::new(put_registry.clone()).with_mapping(&second_mappings),
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
            CAPTURED_CLAIMS.with(|captured| {
                let claims_borrow = ctx.0.claims.claims.borrow();
                let mut claim_keys: Vec<String> = Vec::new();
                for claim in claims_borrow.iter() {
                    claim_keys.push(claim.format_content_normalized());
                }
                *captured.borrow_mut() = Some(Box::new(claim_keys));
            });
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
                OBJECTIVE_TRIGGERED.set(true);
            }
            Error::Difference {
                differences: diffs,
                put1_status: s1,
                put2_status: s2,
            } => {
                log::warn!(
                    "{}",
                    diffs
                        .iter()
                        .map(|x| x.to_string())
                        .collect::<Vec<String>>()
                        .join("\n")
                );
                let mut h = DefaultHasher::new();
                diffs.hash(&mut h);
                s1.hash(&mut h);
                s2.hash(&mut h);

                OBJECTIVE_HASH.set(Some(h.finish()));

                OBJECTIVE_TRIGGERED.set(true);
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
