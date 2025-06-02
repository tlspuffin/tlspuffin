use puffin::agent::AgentName;
use puffin::algebra::dynamic_function::{DescribableFunction, TypeShape};
use puffin::algebra::{DYTerm, TermType};
use puffin::execution::{run_in_subprocess, TraceRunner};
use puffin::fuzzer::bit_mutations::{ByteFlipMutatorDY, ByteInterestingMutatorDY, MakeMessage};
use puffin::fuzzer::mutations::{
    MutationConfig, RemoveAndLiftMutator, RepeatMutator, ReplaceMatchMutator, ReplaceReuseMutator,
};
use puffin::fuzzer::utils::TermConstraints;
use puffin::libafl::corpus::{Corpus, InMemoryCorpus, Testcase};
use puffin::libafl::mutators::{MutationResult, Mutator, MutatorsTuple};
use puffin::libafl::state::{HasCorpus, StdState};
use puffin::libafl_bolts::rands::{RomuDuoJrRand, StdRand};
use puffin::libafl_bolts::tuples::HasConstLen;
use puffin::libafl_bolts::HasLen;
use puffin::protocol::{ProtocolBehavior, ProtocolTypes};
use puffin::put_registry::PutRegistry;
use puffin::test_utils::AssertExecution;
use puffin::trace::{Action, Spawner, Step, Trace, TraceContext};
use puffin::trace_helper::TraceHelper;
use puffin_macros::apply;
use tlspuffin::protocol::{TLSProtocolBehavior, TLSProtocolTypes};
use tlspuffin::put_registry::tls_registry;
use tlspuffin::test_utils::prelude::*;
use tlspuffin::test_utils::{create_state, default_runner_for, test_mutations, TLSState};
use tlspuffin::tls::fn_impl::{
    fn_client_hello, fn_encrypt12, fn_seq_1, fn_sign_transcript, fn_signature_algorithm_extension,
    fn_support_group_extension,
};
use tlspuffin::tls::seeds::{
    _seed_client_attacker12, create_corpus, seed_client_attacker_full, seed_successful,
};
use tlspuffin::tls::TLS_SIGNATURE;

/// Test that all mutations can be successfully applied on all traces from the corpus
#[test_log::test]
#[ignore]
fn test_mutators() {
    let with_dy = true;
    let with_bit_level = true;
    let registry = tls_registry();
    let factory = registry.default();

    let inputs: Vec<Trace<TLSProtocolTypes>> = create_corpus(factory)
        .iter()
        .map(|(t, _)| t.to_owned())
        .collect();

    if inputs.is_empty() {
        // NOTE: no seeds to test our mutations, nothing to do
        return;
    }

    let mut state = create_state();

    let mut mutations = test_mutations(&registry, with_bit_level, with_dy);

    let mut nb_failures = 0;
    let mut nb_success = 0;

    if with_dy {
        log::debug!("Start [test_mutators::with_dy] with nb mutations={} and corpus: {:?}, DY mutations only first", mutations.len(), inputs);

        for (id_i, input) in inputs.iter().enumerate() {
            log::debug!("Treating input nb{id_i}....");
            let max_idx = if with_bit_level { 8 } else { 7 }; // all DY mutations, including MakeMessages
            'outer: for idx in 0..max_idx {
                log::debug!("Treating mutation nb{idx}");
                for c in 0..10000 {
                    // log::debug!(".");
                    let mut mutant = input.clone();
                    match mutations
                        .get_and_mutate(idx.into(), &mut state, &mut mutant, 0)
                        .unwrap()
                    {
                        MutationResult::Mutated => {
                            log::debug!("Success");
                            if c > 0 {
                                log::warn!("[test_mutators::with_dy] Treating input nb{id_i} and mutation nb{idx}: Success but after {c} attempts....")
                            }
                            continue 'outer;
                        }
                        MutationResult::Skipped => (),
                    };
                }
                if idx == 4 || idx == 1 {
                    // former requires a list that some traces don't have, latter requires a trace
                    // of length >2
                    log::error!("[test_mutators::with_dy] Failed to process input nb{id_i} for mutation id {idx}.\n Trace is {}", input)
                } else {
                    panic!("[test_mutators::with_dy] Failed to process input nb{id_i} for mutation id {idx}.\n Trace is {}", input)
                }
            }
        }
    }
    if with_bit_level {
        log::debug!("Start [test_mutators:MakeMessage] with nb mutations={} and corpus: {:?}, MakeMessage only", mutations.len(), inputs);
        let mut acc = vec![];
        let idx = 7; // mutation ID for MakeMessage
        log::debug!(
            "First generating many MakeMessages nb idx={} from the inputs...",
            idx
        );
        for (id_i, input) in inputs.iter().enumerate() {
            log::debug!("Treating input nb{id_i}....");
            let mut mutant = input.clone();
            for c in 0..15 {
                // log::debug!(".");
                match mutations
                    .get_and_mutate(idx.into(), &mut state, &mut mutant, 0)
                    .unwrap()
                {
                    MutationResult::Mutated => {
                        log::debug!("Success MakeMessage: adding to new inputs");
                        acc.push(mutant.clone());
                    }
                    MutationResult::Skipped => {
                        if mutant.steps.iter().any(|e| match &e.action {
                            puffin::trace::Action::Input(r) => r.recipe.is_symbolic(),
                            _ => false,
                        }) {
                            log::error!("Mutant: {mutant:?}");
                            log::error!("[test_mutators:MakeMessage] Treating input nb{id_i} and mutation nb{idx}: Failed at attempt {c} with mutant: {mutant}...")
                        } else {
                            log::debug!("Mutant has no symbolic terms after {c} steps: {mutant:?}");
                            break;
                        }
                    }
                };
            }
        }
        if acc.len()
            < if with_dy {
                core::cmp::max(5, inputs.len())
            } else {
                inputs.len()
            }
        {
            panic!(
                "[test_mutators:MakeMessage] Failed to generate enough MakeMessage! {} < {}",
                acc.len(),
                inputs.len()
            );
        }
        log::debug!(
            "Adding 4th MakeMessage inputs to the corpus (required for CrossOver mutations..."
        );
        for t in &acc {
            state.corpus_mut().add(Testcase::new(t.clone()));
        }
        acc.retain(|t| {
            !t.is_symbolic()
                && t.steps.len() > 2
                && t.all_payloads().iter().any(|p| p.payload.len() > 8)
        });

        log::debug!("Start [test_mutators:with_bit_level] with nb mutations={} and corpus: {:?}, bit-level mutations only (!= MakeMessage)", mutations.len(), inputs);
        let max_tries = 1000;
        for (id_i, input) in acc.iter().enumerate() {
            log::debug!("Treating MakeMessage input nb{id_i}....");
            for idx in 8..mutations.len() {
                log::debug!("Treating mutation nb{idx}");
                let mut succeeded = false;
                for c in 0..max_tries {
                    // log::debug!(".");
                    let mut mutant = input.clone();
                    match mutations
                        .get_and_mutate(idx.into(), &mut state, &mut mutant, 0)
                        .unwrap()
                    {
                        MutationResult::Mutated => {
                            log::debug!("Success");
                            if c > 0 {
                                log::warn!("[test_mutators:with_bit_level] Treating input nb{id_i} and mutation nb{idx}: Success but after {c} attempts....")
                            }
                            nb_success += 1;
                            succeeded = true;
                        }
                        MutationResult::Skipped => {
                            log::debug!("Skipped");
                            nb_failures += 1;
                        }
                    };
                }
                if !succeeded {
                    log::debug!("Input: {}", input);
                    panic!("[test_mutators:with_bit_level] Failed to process input nb{id_i} for mutation id {idx}.\n Trace: {input}\n");
                }
            }
        }
        log::error!("All bit-level mutations could be applied at least once with a total of #{nb_failures} failures over #{nb_success} successes. On {} inputs, and {max_tries} tries for each.", acc.len());
    }
}

#[apply(test_puts, filter = all(tls13))]
fn test_make_message(put: &str) {
    let runner = default_runner_for(put);
    let tls_registry = runner.registry;
    let mut state = create_state();
    let mut mutator = MakeMessage::new(MutationConfig::default(), &tls_registry);

    let mut trace = seed_client_attacker_full.build_trace();

    loop {
        mutator.mutate(&mut state, &mut trace, 0).unwrap();

        let all_payloads = if let Some(first) = trace.steps.get(0) {
            match &first.action {
                Action::Input(input) => Some(input.recipe.all_payloads()),
                Action::Output(_) => None,
            }
        } else {
            None
        };

        if let Some(payloads) = all_payloads {
            if !payloads.is_empty() {
                log::debug!("MakeMessage created payloads: {:?}", payloads);
                break;
            }
        }
    }
}

/// Test that MakeMessage can be applied on a strict sub-term and them on a whole term, erasing all
/// payloads of strict sub-terms
// require version which supports TLS 1.3, removed boringssl-binding as seed_client_attacker_full
// cannot be executed with boringssl
#[apply(test_puts, filter = all(tls13))]
fn test_byte_remove_payloads(put: &str) {
    let runner = default_runner_for(put);
    let tls_registry = runner.registry;
    let mut state = create_state();
    let mut mutator_config = MutationConfig::default();
    mutator_config.term_constraints.must_be_symbolic = true;
    let mut mutator_make = MakeMessage::new(mutator_config, &tls_registry);

    let mut trace = seed_client_attacker_full.build_trace();
    let mut i = 0;
    let MAX = 1000;

    while i < MAX {
        i += 1;
        mutator_make.mutate(&mut state, &mut trace, 0).unwrap();

        if let Some(first) = trace.steps.get(0) {
            match &first.action {
                Action::Input(input) => {
                    if let DYTerm::Application(fd, args) = &input.recipe.term {
                        if args.len() > 5
                            && input.recipe.is_symbolic()
                            && !args[5].payloads_to_replace().is_empty()
                        {
                            log::debug!(
                                "Found term with payload in argument 5: {}",
                                &input.recipe.term
                            );
                            log::debug!(
                                "MakeMessage created at step {i} new payloads in a strict sub-term: {:?}",
                                args[5].payloads_to_replace()
                            );
                            break;
                        }
                    }
                }
                Action::Output(_) => {}
            }
        }
    }
    assert_ne!(i, MAX); // success condition

    // This further test only applies when we allow MakeMessage with no_payload_in_subterm: false,
    // which is currently the case
    i = 0;
    while i < MAX {
        i += 1;
        mutator_make.mutate(&mut state, &mut trace, 0).unwrap();

        if let Some(first) = trace.steps.get(0) {
            match &first.action {
                Action::Input(input) => {
                    if let DYTerm::Application(fd, args) = &input.recipe.term {
                        if args.len() > 5 && !input.recipe.is_symbolic() {
                            if args[5].payloads_to_replace().is_empty()
                                && input.recipe.payloads_to_replace().len() == 1
                            {
                                log::debug!(
                                    "MakeMessage created new payloads at step {i} in the
    client hello {} and removed payloads in the strict sub-terms. New paylaod: {:?}",
                                    &input.recipe,
                                    input.recipe.payloads.as_ref().unwrap()
                                );
                                break;
                            } else {
                                log::debug!(
                                    "Failed to remove payloads in strict sub-terms when
    adding a payload at top level"
                                );
                                log::debug!(
                                    "Should never
    happen"
                                );
                            }
                        }
                    }
                }
                Action::Output(_) => {}
            }
        }
    }
    assert_ne!(i, MAX); // success condition
}

#[apply(test_puts, filter = all(tls13))] // require version which supports TLS 1.3
fn test_byte_simple(put: &str) {
    let runner = default_runner_for(put);
    let tls_registry = runner.registry;
    let mut state = create_state();
    let mut mutator_config = MutationConfig::default();
    mutator_config.term_constraints.must_be_symbolic = true;
    let mut mutator_make = MakeMessage::new(mutator_config, &tls_registry);
    let mut mutator_byte = ByteFlipMutatorDY::new(true);

    let mut trace = seed_client_attacker_full.build_trace();
    let mut i = 0;
    let MAX = 1000;

    while i < MAX {
        i += 1;
        mutator_make.mutate(&mut state, &mut trace, 0).unwrap();

        let all_payloads = if let Some(first) = trace.steps.get(0) {
            match &first.action {
                Action::Input(input) => Some(input.recipe.all_payloads()),
                Action::Output(_) => None,
            }
        } else {
            None
        };

        if let Some(payloads) = all_payloads {
            if !payloads.is_empty() && !payloads[0].payload_0.is_empty() {
                log::debug!(
                    "MakeMessage created new non-empty payloads at step {i}: {:?}",
                    payloads
                );
                break;
            }
        }
    }

    assert_ne!(i, MAX);
    i = 0;

    while i < MAX {
        println!("START");
        i += 1;
        mutator_byte.mutate(&mut state, &mut trace, 0).unwrap();

        if let Some(first) = trace.steps.get(0) {
            match &first.action {
                Action::Input(input) => {
                    let mut found = false;
                    for payload in input.recipe.all_payloads() {
                        if payload.payload_0 != payload.payload {
                            log::debug!(
                                "ByteFlipMutatorDY created different payloads at step {i}: {:?}",
                                payload
                            );
                            found = true;
                        }
                    }
                    if found {
                        break;
                    }
                }
                Action::Output(_) => {}
            }
        }
    }
    assert_ne!(i, MAX);
}

#[apply(test_puts, filter = all(tls13))] // require version which supports TLS 1.3
fn test_byte_interesting(put: &str) {
    let runner = default_runner_for(put);
    let tls_registry = runner.registry;
    let spawner = Spawner::new(tls_registry.clone());
    let mut state = create_state();
    let mut mutator_make = MakeMessage::new(MutationConfig::default(), &tls_registry);
    let mut mutator_byte_interesting = ByteInterestingMutatorDY::new(true);

    let ctx = TraceContext::new(spawner);
    let mut trace = seed_client_attacker_full.build_trace();
    let mut i = 0;
    let MAX = 1000;

    while i < MAX {
        i += 1;
        mutator_make.mutate(&mut state, &mut trace, 0).unwrap();

        let all_payloads = if let Some(first) = trace.steps.get(0) {
            match &first.action {
                Action::Input(input) => Some(input.recipe.all_payloads()),
                Action::Output(_) => None,
            }
        } else {
            None
        };

        if let Some(payloads) = all_payloads {
            let mut found = false;
            for payload in payloads {
                if payload.payload_0.len() >= size_of::<u8>() {
                    // condition for ByteInterestingMutatorDY to work
                    log::debug!(
                        "MakeMessage created sufficiently large (>= {}) payloads at step {i}: {:?}",
                        size_of::<u8>(),
                        payload
                    );
                    found = true;
                    break;
                }
            }
            if found {
                break;
            }
        }
    }

    assert_ne!(i, MAX);
    i = 0;

    // This second while loop may always fail because we might have chosen a MakeMessage on som
    // sub-term that cannot be meaningfully mutated (e.g., NamedGroup under encryption)
    while i < MAX {
        i += 1;
        log::error!("Test attempt {i}");
        mutator_byte_interesting
            .mutate(&mut state, &mut trace, 0)
            .unwrap();

        if let Some(first) = trace.steps.get(0) {
            match &first.action {
                Action::Input(input) => {
                    let mut found = false;
                    let t = &input.recipe;
                    for payload in t.all_payloads() {
                        if payload.payload_0 != payload.payload {
                            log::debug!(
                                "[test_byte_interesting] ByteInterestingMutatorDY created different payloads at step {i}: {:?}",
                                payload
                            );
                            found = true;
                        }
                    }
                    if found {
                        log::debug!("[test_byte_interesting] We found different payload. Now evaluating e1\n {t}....",);
                        if let Ok(e1) = t.evaluate(&ctx) {
                            log::debug!("[test_byte_interesting] Now symbolically evaluating....",);
                            if let Ok(e2) = t.evaluate_symbolic(&ctx) {
                                if e1 != e2 {
                                    log::debug!(
                                        "[test_byte_interesting] Evaluation differed, good..."
                                    );
                                    break;
                                } else {
                                    log::error!("[test_byte_interesting] Should never happen!");
                                }
                            } else {
                                log::error!("[test_byte_interesting] e2 failed while e1 succeeded: should not happen");
                                continue;
                            }
                        } else {
                            log::warn!(
                                "Evaluating e1 failed for term:\n {t}\n and payloads: {:?}",
                                t.all_payloads()
                            );
                            continue;
                        }
                    }
                }
                Action::Output(_) => {}
            }
        }
    }
    assert_ne!(i, MAX);
}

fn search_for_seed_cve_2021_3449(state: &mut TLSState) -> Option<Trace<TLSProtocolTypes>> {
    let loop_tries = 1000;
    let mut attempts = 0;
    let (mut trace, _) = _seed_client_attacker12(AgentName::first());
    let mut success = false;

    // Check if we can append another encrypted message
    let mut mutator = RepeatMutator::new(15, true);

    fn check_is_encrypt12(step: &Step<TLSProtocolTypes>) -> bool {
        if let Action::Input(input) = &step.action {
            if input.recipe.name() == fn_encrypt12.name() {
                return true;
            }
        }
        false
    }
    log::error!("Start, initial length: {}", trace.steps.len());
    for _i in 0..loop_tries {
        attempts += 1;
        let mut mutate = trace.clone();
        mutator.mutate(state, &mut mutate, 0).unwrap();

        let length = mutate.steps.len();
        if length > 5 {
            continue;
        }
        if let Some(last) = mutate.steps.get(length - 1) {
            if check_is_encrypt12(last) {
                if let Some(step) = mutate.steps.get(length - 2) {
                    if check_is_encrypt12(step) {
                        trace = mutate;
                        success = true;
                        break;
                    }
                }
            }
        }
    }
    if !success {
        return None;
    }
    success = false;
    log::error!("attempts 1: {}. Length: {}", attempts, trace.steps.len());
    attempts = 0;

    // Check if we have a client hello in last encrypted one
    let constraints = TermConstraints::default();
    let mut mutator = ReplaceReuseMutator::new(constraints, true, true);

    for _i in 0..loop_tries {
        attempts += 1;
        let mut mutate = trace.clone();
        mutator.mutate(state, &mut mutate, 0).unwrap();

        if let Some(last) = mutate.steps.iter().last() {
            match &last.action {
                Action::Input(input) => match &input.recipe.term {
                    DYTerm::Variable(_) => {}
                    DYTerm::Application(_, subterms) => {
                        if let Some(first_subterm) = subterms.iter().next() {
                            if first_subterm.name() == fn_client_hello.name() {
                                trace = mutate;
                                success = true;
                                break;
                            }
                        }
                    }
                },
                Action::Output(_) => {}
            }
        }
    }
    if !success {
        return None;
    }
    success = false;
    log::error!(
        "attempts 2: {}\n Term: {}",
        attempts,
        trace.steps.iter().last().unwrap().action
    );
    attempts = 0;

    // Test if we can replace the sequence number
    let mut mutator = ReplaceMatchMutator::new(constraints, &TLS_SIGNATURE, true);

    for _i in 0..loop_tries {
        attempts += 1;
        let mut mutate = trace.clone();
        mutator.mutate(state, &mut mutate, 0).unwrap();

        if let Some(last) = mutate.steps.iter().last() {
            match &last.action {
                Action::Input(input) => match &input.recipe.term {
                    DYTerm::Variable(_) => {}
                    DYTerm::Application(_, subterms) => {
                        if let Some(last_subterm) = subterms
                            .iter()
                            .filter(|sb| *sb.get_type_shape() == TypeShape::of::<u64>())
                            .last()
                        {
                            log::warn!("mutational result last subterm: {}", last_subterm);
                            if last_subterm.name() == fn_seq_1.name() {
                                trace = mutate;
                                success = true;
                                break;
                            }
                        }
                    }
                },
                Action::Output(_) => {}
            }
        }
    }
    if !success {
        return None;
    }
    success = false;
    log::error!(
        "attempts 3: {}\n Term: {}",
        attempts,
        trace.steps.iter().last().unwrap().action
    );
    attempts = 0;

    // Remove sig algo
    let mut mutator = RemoveAndLiftMutator::new(constraints, true);

    for _i in 0..loop_tries {
        attempts += 1;
        let mut mutate = trace.clone();
        let result = mutator.mutate(state, &mut mutate, 0).unwrap();
        if let MutationResult::Mutated = result {
            if let Some(last) = mutate.steps.iter().last() {
                match &last.action {
                    Action::Input(input) => match &input.recipe.term {
                        DYTerm::Variable(_) => {}
                        DYTerm::Application(_, subterms) => {
                            if let Some(first_subterm) = subterms.iter().next() {
                                log::warn!("mutational result: {:?}", first_subterm);
                                let sig_alg_extensions = first_subterm.count_functions_by_name(
                                    fn_signature_algorithm_extension.name(),
                                );
                                let support_groups_extensions = first_subterm
                                    .count_functions_by_name(fn_support_group_extension.name());
                                if sig_alg_extensions == 0 && support_groups_extensions == 1 {
                                    trace = mutate;
                                    success = true;
                                    break;
                                }
                            }
                        }
                    },
                    Action::Output(_) => {}
                }
            }
        }
    }
    if !success {
        return None;
    }
    success = false;
    log::error!(
        "attempts 4: {}\n Term: {}",
        attempts,
        trace.steps.iter().last().unwrap().action
    );
    attempts = 0;

    // Sucessfully renegotiate

    let mut mutator = ReplaceReuseMutator::new(constraints, true, true);

    for _i in 0..loop_tries {
        attempts += 1;
        let mut mutate = trace.clone();
        mutator.mutate(state, &mut mutate, 0).unwrap();

        if let Some(last) = mutate.steps.iter().last() {
            match &last.action {
                Action::Input(input) => match &input.recipe.term {
                    DYTerm::Variable(_) => {}
                    DYTerm::Application(_, subterms) => {
                        if let Some(first_subterm) = subterms.iter().next() {
                            let signatures =
                                first_subterm.count_functions_by_name(fn_sign_transcript.name());
                            if signatures == 1 {
                                trace = mutate;
                                success = true;
                                break;
                            }
                        }
                    }
                },
                Action::Output(_) => {}
            }
        }
    }
    if !success {
        return None;
    }
    log::error!(
        "attempts 5: {}\n Term: {}",
        attempts,
        trace.steps.iter().last().unwrap().action
    );
    Some(trace)
}

#[test_log::test]
fn test_mutate_seed_cve_2021_3449() {
    let mut state = create_state();
    let trace = search_for_seed_cve_2021_3449(&mut state);
    assert!(trace.is_some());
}

// The test below succeeds when executed in isolation but fails when run with others :( TODO:
// investigate why
// #[apply(test_puts, filter = all(CVE_2021_3449, tls12))]
fn test_mutate_and_execute_seed_cve_2021_3449(put: &str) {
    let runner = default_runner_for(put);
    let mut state = create_state();
    run_in_subprocess(
        move || {
            log::error!("start in subprocess");
            if let Some(trace) = search_for_seed_cve_2021_3449(&mut state) {
                // In case we get None, the other test `test_mutate_seed_cve_2021_3449` will fail
                log::error!("try");
                for _i in 0..50 {
                    let _ = runner.execute(&trace);
                }
            }
        },
        std::time::Duration::from_secs(100),
    )
    .expect_crash();
}
