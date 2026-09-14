use std::hash::{DefaultHasher, Hash, Hasher};

use libafl::executors::ExitKind;
use rand::Rng;

use crate::algebra::{DYTerm, Term, TermType};
use crate::error::Error;
use crate::execution::{DifferentialRunner, Runner, TraceRunner};
use crate::fuzzer::feedback::{FAIL_AT_STEP, OBJECTIVE_HASH, OBJECTIVE_TRIGGERED};
use crate::fuzzer::stats_stage::{
    HARNESS_EXEC, HARNESS_EXEC_AGENT_SUCCESS, HARNESS_EXEC_SUCCESS, LISTS, NB_PAYLOAD,
    PAYLOAD_LENGTH, TERM_SIZE, TRACE_LENGTH,
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

    if cfg!(feature = "introspection") {
        record_trace_stats(input, &fail_at_step);
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

/// Feeds the introspection stats every trace execution reports: the payloads and term sizes of
/// the trace, and the length and element diversity of each of its lists.
fn record_trace_stats<PT: ProtocolTypes>(input: &Trace<PT>, fail_at_step: &usize) {
    NB_PAYLOAD.update(input.all_payloads().len());
    for payload in input.all_payloads() {
        PAYLOAD_LENGTH.update(payload.len());
    }
    for (idx, step) in input.steps.iter().enumerate() {
        match &step.action {
            Action::Input(input) => {
                TERM_SIZE.update(input.recipe.size());
                record_list_stats(&input.recipe, idx < *fail_at_step);
            }
            Action::Output(_) => {}
        }
    }
}

/// Records every [`DYTerm::List`] node of `recipe`, keyed by its list type.
///
/// Iterating a term yields the sub-terms that are actually evaluated, so a list buried under a
/// payload is skipped -- which is also the list the mutators leave alone.
fn record_list_stats<PT: ProtocolTypes>(recipe: &Term<PT>, executable: bool) {
    for subterm in recipe {
        let DYTerm::List(typ, elements) = &subterm.term else {
            continue;
        };
        let distinct = count_distinct(elements);
        LISTS.update(typ.name, elements.len(), distinct, executable);
    }
}

/// Distinct elements of a list, compared by the hash of the whole (sub-)term: two elements count
/// as one when they are the same recipe, payloads included.
fn count_distinct<PT: ProtocolTypes>(elements: &[Term<PT>]) -> usize {
    elements
        .iter()
        .map(|element| {
            let mut hasher = DefaultHasher::new();
            element.hash(&mut hasher);
            hasher.finish()
        })
        .collect::<std::collections::HashSet<_>>()
        .len()
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

    let input_len = input.steps.len();
    let input_size = input.size();

    // Execute the trace
    let mut fail_at_step = 0;
    let exec_res = runner.execute_config(
        &input,
        ConfigTrace {
            check_security_violation: false,
            ..Default::default()
        },
        &mut fail_at_step,
    );

    if cfg!(feature = "introspection") {
        record_trace_stats(&input, &fail_at_step);
    }

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

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use libafl::monitors::stats::{UserStats, UserStatsValue};

    use super::*;
    use crate::algebra::test_signature::{
        fn_ec_point_formats_extension, fn_signature_algorithm_extension, ClientExtension,
        TestProtocolTypes,
    };
    use crate::fuzzer::stats_stage::Fire;
    use crate::term;

    fn fired() -> HashMap<String, u64> {
        let mut stats = HashMap::new();
        let mut collect = |name: String, value: UserStats| {
            if let UserStatsValue::Number(n) = value.value() {
                stats.insert(name, *n);
            }
            Ok(())
        };
        LISTS.fire(&mut collect).unwrap();
        stats
    }

    /// `Vec<ClientExtension>` is the one list type of the test signature, so these statics are
    /// this test's alone within the test binary.
    #[test_log::test]
    fn list_stats_count_lengths_and_distinct_elements() {
        // Three elements, two of them the same term: length bucket 2 (lengths 2..3), 2 distinct.
        let recipe: Term<TestProtocolTypes> = term! {
            [
                fn_signature_algorithm_extension,
                fn_signature_algorithm_extension,
                fn_ec_point_formats_extension
            ] / Vec<ClientExtension>
        };
        record_list_stats(&recipe, true);

        let stats = fired();
        assert_eq!(stats["list-length|Vec<ClientExtension>|2"], 1);
        assert_eq!(stats["list-length|Vec<ClientExtension>|0"], 0);
        assert_eq!(stats["list-diversity|Vec<ClientExtension>|lists"], 1);
        assert_eq!(stats["list-diversity|Vec<ClientExtension>|nonempty"], 1);
        assert_eq!(stats["list-diversity|Vec<ClientExtension>|elements"], 3);
        assert_eq!(stats["list-diversity|Vec<ClientExtension>|distinct"], 2);
        assert_eq!(
            stats["list-diversity|Vec<ClientExtension>|ratio-permille"],
            666
        );

        // An empty list is still a list: it lands in bucket 0 and leaves `nonempty` alone.
        let empty: Term<TestProtocolTypes> = term! { [] / Vec<ClientExtension> };
        record_list_stats(&empty, true);

        let stats = fired();
        assert_eq!(stats["list-length|Vec<ClientExtension>|0"], 1);
        assert_eq!(stats["list-diversity|Vec<ClientExtension>|lists"], 2);
        assert_eq!(stats["list-diversity|Vec<ClientExtension>|nonempty"], 1);

        // Both lists above were executable, so the executable stats mirror the plain ones.
        assert_eq!(stats["executable-list-length|Vec<ClientExtension>|2"], 1);
        assert_eq!(stats["executable-list-length|Vec<ClientExtension>|0"], 1);
        assert_eq!(
            stats["executable-list-diversity|Vec<ClientExtension>|lists"],
            2
        );
        assert_eq!(
            stats["executable-list-diversity|Vec<ClientExtension>|nonempty"],
            1
        );
        assert_eq!(
            stats["executable-list-diversity|Vec<ClientExtension>|elements"],
            3
        );
        assert_eq!(
            stats["executable-list-diversity|Vec<ClientExtension>|distinct"],
            2
        );

        // A list of a step that was never reached only feeds the plain stats.
        record_list_stats(&recipe, false);

        let stats = fired();
        assert_eq!(stats["list-length|Vec<ClientExtension>|2"], 2);
        assert_eq!(stats["list-diversity|Vec<ClientExtension>|lists"], 3);
        assert_eq!(stats["executable-list-length|Vec<ClientExtension>|2"], 1);
        assert_eq!(
            stats["executable-list-diversity|Vec<ClientExtension>|lists"],
            2
        );
        assert_eq!(
            stats["executable-list-diversity|Vec<ClientExtension>|elements"],
            3
        );
    }
}
