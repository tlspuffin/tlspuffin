use log::{debug, error, warn};
use puffin::agent::AgentName;
use puffin::algebra::dynamic_function::DescribableFunction;
use puffin::algebra::{DYTerm, TermType};
use puffin::execution::forked_execution;
use puffin::fuzzer::bit_mutations::{ByteFlipMutatorDY, ByteInterestingMutatorDY};
use puffin::fuzzer::harness::set_default_put_options;
use puffin::fuzzer::mutations::{
    trace_mutations, MakeMessage, MutationConfig, RemoveAndLiftMutator, RepeatMutator,
    ReplaceMatchMutator, ReplaceReuseMutator,
};
use puffin::fuzzer::utils::TermConstraints;
use puffin::libafl::corpus::{Corpus, InMemoryCorpus, Testcase};
use puffin::libafl::mutators::{MutationResult, Mutator, MutatorsTuple};
use puffin::libafl::state::{HasCorpus, StdState};
use puffin::libafl_bolts::rands::{RomuDuoJrRand, StdRand};
use puffin::libafl_bolts::tuples::HasConstLen;
use puffin::libafl_bolts::HasLen;
use puffin::protocol::ProtocolBehavior;
use puffin::put::PutOptions;
use puffin::put_registry::PutRegistry;
use puffin::test_utils::AssertExecution;
use puffin::trace::{Action, Step, Trace, TraceContext};
use puffin::trace_helper::TraceHelper;

use crate::protocol::TLSProtocolBehavior;
use crate::put_registry::tls_registry;
use crate::query::TlsQueryMatcher;
use crate::tls::fn_impl::{
    fn_client_hello, fn_encrypt12, fn_seq_1, fn_sign_transcript, fn_signature_algorithm_extension,
    fn_support_group_extension,
};
use crate::tls::seeds::{
    _seed_client_attacker12, create_corpus, seed_client_attacker_full, seed_successful,
};
use crate::tls::TLS_SIGNATURE;

pub type TLSState = StdState<
    Trace<TlsQueryMatcher>,
    InMemoryCorpus<Trace<TlsQueryMatcher>>,
    RomuDuoJrRand,
    InMemoryCorpus<Trace<TlsQueryMatcher>>,
>;

fn create_state() -> TLSState {
    let rand = StdRand::with_seed(1235);
    let mut corpus: InMemoryCorpus<Trace<_>> = InMemoryCorpus::new();
    corpus.add(Testcase::new(seed_successful.build_trace()));
    StdState::new(rand, corpus, InMemoryCorpus::new(), &mut (), &mut ()).unwrap()
}

fn test_mutations(
    registry: &PutRegistry<TLSProtocolBehavior>,
    with_bit_level: bool,
    with_dy: bool,
) -> impl MutatorsTuple<Trace<TlsQueryMatcher>, TLSState> + '_ {
    let MutationConfig {
        fresh_zoo_after,
        max_trace_length,
        min_trace_length,
        term_constraints,
        with_bit_level: _,
        with_dy: _,
        ..
    } = MutationConfig::default();

    trace_mutations::<TLSState, TlsQueryMatcher, TLSProtocolBehavior>(
        min_trace_length,
        max_trace_length,
        term_constraints,
        fresh_zoo_after,
        with_bit_level,
        with_dy,
        TLSProtocolBehavior::signature(),
        registry,
    )
}

/// Test that all mutations can be successfully applied on all traces from the corpus
#[test_log::test]
fn test_mutators() {
    let with_dy = true;
    let with_bit_level = true;

    let inputs: Vec<Trace<TlsQueryMatcher>> =
        create_corpus().iter().map(|(t, _)| t.to_owned()).collect();
    assert_ne!(inputs.len(), 0);
    let tls_registry = tls_registry();
    let mut state = create_state();
    set_default_put_options(PutOptions::default());

    let mut mutations = test_mutations(&tls_registry, with_bit_level, with_dy);

    let mut nb_failures = 0;
    let mut nb_success = 0;

    if with_dy {
        debug!("Start [test_mutators::with_dy] with nb mutations={} and corpus: {:?}, DY mutations only first", mutations.len(), inputs);

        for (id_i, input) in inputs.iter().enumerate() {
            debug!("Treating input nb{id_i}....");
            let max_idx = if with_bit_level { 8 } else { 7 }; // all DY mutations, including MakeMessages
            'outer: for idx in 0..max_idx {
                debug!("Treating mutation nb{idx}");
                for c in 0..10000 {
                    // debug!(".");
                    let mut mutant = input.clone();
                    match mutations
                        .get_and_mutate(idx.into(), &mut state, &mut mutant, 0)
                        .unwrap()
                    {
                        MutationResult::Mutated => {
                            debug!("Success");
                            if c > 0 {
                                warn!("[test_mutators::with_dy] Treating input nb{id_i} and mutation nb{idx}: Success but after {c} attempts....")
                            }
                            continue 'outer;
                        }
                        MutationResult::Skipped => (),
                    };
                }
                if idx == 4 || idx == 1 {
                    // former requires a list that some traces don't have, latter requires a trace
                    // of length >2
                    error!("[test_mutators::with_dy] Failed to process input nb{id_i} for mutation id {idx}.\n Trace is {}", input)
                } else {
                    panic!("[test_mutators::with_dy] Failed to process input nb{id_i} for mutation id {idx}.\n Trace is {}", input)
                }
            }
        }
    }
    if with_bit_level {
        debug!("Start [test_mutators:MakeMessage] with nb mutations={} and corpus: {:?}, MakeMessage only", mutations.len(), inputs);
        let mut acc = vec![];
        let idx = 7; // mutation ID for MakeMessage
        debug!(
            "First generating many MakeMessages nb idx={} from the inputs...",
            idx
        );
        for (id_i, input) in inputs.iter().enumerate() {
            debug!("Treating input nb{id_i}....");
            let mut mutant = input.clone();
            for c in 0..15 {
                // debug!(".");
                match mutations
                    .get_and_mutate(idx.into(), &mut state, &mut mutant, 0)
                    .unwrap()
                {
                    MutationResult::Mutated => {
                        debug!("Success MakeMessage: adding to new inputs");
                        acc.push(mutant.clone());
                    }
                    MutationResult::Skipped => {
                        if mutant.steps.iter().any(|e| match &e.action {
                            puffin::trace::Action::Input(r) => r.recipe.is_symbolic(),
                            _ => false,
                        }) {
                            error!("Mutant: {mutant:?}");
                            error!("[test_mutators:MakeMessage] Treating input nb{id_i} and mutation nb{idx}: Failed at attempt {c} with mutant: {mutant}...")
                        } else {
                            debug!("Mutant has no symbolic terms after {c} steps: {mutant:?}");
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
        debug!("Adding 4th MakeMessage inputs to the corpus (required for CrossOver mutations...");
        for t in &acc {
            state.corpus_mut().add(Testcase::new(t.clone()));
        }
        acc.retain(|t| {
            !t.is_symbolic()
                && t.steps.len() > 2
                && t.all_payloads().iter().any(|p| p.payload.len() > 8)
        });

        debug!("Start [test_mutators:with_bit_level] with nb mutations={} and corpus: {:?}, bit-level mutations only (!= MakeMessage)", mutations.len(), inputs);
        let max_tries = 1000;
        for (id_i, input) in acc.iter().enumerate() {
            debug!("Treating MakeMessage input nb{id_i}....");
            for idx in 8..mutations.len() {
                debug!("Treating mutation nb{idx}");
                let mut succeeded = false;
                for c in 0..max_tries {
                    // debug!(".");
                    let mut mutant = input.clone();
                    match mutations
                        .get_and_mutate(idx.into(), &mut state, &mut mutant, 0)
                        .unwrap()
                    {
                        MutationResult::Mutated => {
                            debug!("Success");
                            if c > 0 {
                                warn!("[test_mutators:with_bit_level] Treating input nb{id_i} and mutation nb{idx}: Success but after {c} attempts....")
                            }
                            nb_success += 1;
                            succeeded = true;
                        }
                        MutationResult::Skipped => {
                            debug!("Skipped");
                            nb_failures += 1;
                        }
                    };
                }
                if !succeeded {
                    debug!("Input: {}", input);
                    panic!("[test_mutators:with_bit_level] Failed to process input nb{id_i} for mutation id {idx}.\n Trace: {input}\n");
                }
            }
        }
        error!("All bit-level mutations could be applied at least once with a total of #{nb_failures} failures over #{nb_success} successes. On {} inputs, and {max_tries} tries for each.", acc.len());
    }
}

#[cfg(feature = "tls13")] // require version which supports TLS 1.3
#[test_log::test]
fn test_make_message() {
    let tls_registry = tls_registry();
    let mut state = create_state();
    let mut mutator: MakeMessage<
        StdState<
            Trace<TlsQueryMatcher>,
            InMemoryCorpus<Trace<TlsQueryMatcher>>,
            RomuDuoJrRand,
            InMemoryCorpus<Trace<TlsQueryMatcher>>,
        >,
        TLSProtocolBehavior,
    > = MakeMessage::new(TermConstraints::default(), &tls_registry, true, true);

    let mut ctx = TraceContext::new(&tls_registry, PutOptions::default());
    ctx.set_deterministic(true);
    let mut trace = seed_client_attacker_full.build_trace();
    set_default_put_options(PutOptions::default());

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
                debug!("MakeMessage created payloads: {:?}", payloads);
                break;
            }
        }
    }
}

/// Test that MakeMessage can be applied on a strict sub-term and them on a whole term, erasing all
/// payloads of strict sub-terms
#[cfg(all(feature = "tls13", not(feature = "boringssl-binding")))]
// require version which supports TLS 1.3, removed boringssl-binding as seed_client_attacker_full
// cannot be executed with boringssl
#[test_log::test]
fn test_byte_remove_payloads() {
    let tls_registry = tls_registry();
    let mut state = create_state();
    let mut mutator_make: MakeMessage<
        StdState<
            Trace<TlsQueryMatcher>,
            InMemoryCorpus<Trace<TlsQueryMatcher>>,
            RomuDuoJrRand,
            InMemoryCorpus<Trace<TlsQueryMatcher>>,
        >,
        TLSProtocolBehavior,
    > = MakeMessage::new(
        TermConstraints {
            must_be_symbolic: true,
            ..TermConstraints::default()
        },
        &tls_registry,
        true,
        true,
    );

    let mut ctx = TraceContext::new(&tls_registry, PutOptions::default());
    ctx.set_deterministic(true);
    let mut trace = seed_client_attacker_full.build_trace();
    set_default_put_options(PutOptions::default());
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
                            debug!(
                                "Found term with payload in argument 5: {}",
                                &input.recipe.term
                            );
                            debug!(
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
                                debug!("MakeMessage created new payloads at step {i} in the client hello {} and removed payloads in the strict sub-terms. New paylaod: {:?}", &input.recipe, input.recipe.payloads.as_ref().unwrap());
                                break;
                            } else {
                                debug!("Failed to remove payloads in strict sub-terms when adding a payload at top level");
                                debug!("Should never happen");
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

#[cfg(all(feature = "tls13"))] // require version which supports TLS 1.3
#[test_log::test]
fn test_byte_simple() {
    let tls_registry = tls_registry();
    let mut state = create_state();
    let mut mutator_make: MakeMessage<
        StdState<
            Trace<TlsQueryMatcher>,
            InMemoryCorpus<Trace<TlsQueryMatcher>>,
            RomuDuoJrRand,
            InMemoryCorpus<Trace<TlsQueryMatcher>>,
        >,
        TLSProtocolBehavior,
    > = MakeMessage::new(
        TermConstraints {
            must_be_symbolic: true,
            ..TermConstraints::default()
        },
        &tls_registry,
        true,
        true,
    );
    let mut mutator_byte = ByteFlipMutatorDY::new(true);

    let mut ctx = TraceContext::new(&tls_registry, PutOptions::default());
    ctx.set_deterministic(true);
    let mut trace = seed_client_attacker_full.build_trace();
    set_default_put_options(PutOptions::default());
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
                debug!(
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
                            debug!(
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

#[cfg(all(feature = "tls13"))] // require version which supports TLS 1.3
#[test_log::test]
fn test_byte_interesting() {
    let tls_registry = tls_registry();
    let mut state = create_state();
    let mut mutator_make: MakeMessage<
        StdState<
            Trace<TlsQueryMatcher>,
            InMemoryCorpus<Trace<TlsQueryMatcher>>,
            RomuDuoJrRand,
            InMemoryCorpus<Trace<TlsQueryMatcher>>,
        >,
        TLSProtocolBehavior,
    > = MakeMessage::new(
        TermConstraints {
            must_be_symbolic: true,
            ..TermConstraints::default()
        },
        &tls_registry,
        true,
        true,
    );
    let mut mutator_byte_interesting = ByteInterestingMutatorDY::new(true);

    let mut ctx = TraceContext::new(&tls_registry, PutOptions::default());
    ctx.set_deterministic(true);
    let mut trace = seed_client_attacker_full.build_trace();
    set_default_put_options(PutOptions::default());
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
                    debug!(
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

    while i < MAX {
        i += 1;
        error!("Test attempt {i}");
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
                            debug!(
                                "[test_byte_interesting] ByteInterestingMutatorDY created different payloads at step {i}: {:?}",
                                payload
                            );
                            found = true;
                        }
                    }
                    if found {
                        debug!("[test_byte_interesting] We found different payload. Now evaluating e1\n {t}....",);
                        let e1 = t.evaluate(&ctx).unwrap();
                        debug!("[test_byte_interesting] Now symbolically evaluating....",);
                        let e2 = t.evaluate_symbolic(&ctx).unwrap();
                        if e1 != e2 {
                            debug!("[test_byte_interesting] Evaluation differed, good...");
                            break;
                        } else {
                            debug!("[test_byte_interesting] Should never happen!");
                        }
                    }
                }
                Action::Output(_) => {}
            }
        }
    }
    assert_ne!(i, MAX);
}

#[test_log::test]
#[ignore]
fn test_mutate_seed_cve_2021_3449() {
    let mut state = create_state();
    let _server = AgentName::first();

    forked_execution(
        move || {
            for _i in 0..5 {
                let mut attempts = 0;

                let (mut trace, _) = _seed_client_attacker12(AgentName::first());

                // Check if we can append another encrypted message

                let mut mutator = RepeatMutator::new(15, true);

                fn check_is_encrypt12(step: &Step<TlsQueryMatcher>) -> bool {
                    if let Action::Input(input) = &step.action {
                        if input.recipe.name() == fn_encrypt12.name() {
                            return true;
                        }
                    }
                    false
                }

                loop {
                    attempts += 1;
                    let mut mutate = trace.clone();
                    mutator.mutate(&mut state, &mut mutate, 0).unwrap();

                    let length = mutate.steps.len();
                    if let Some(last) = mutate.steps.get(length - 1) {
                        if check_is_encrypt12(last) {
                            if let Some(step) = mutate.steps.get(length - 2) {
                                if check_is_encrypt12(step) {
                                    trace = mutate;
                                    break;
                                }
                            }
                        }
                    }
                }
                println!("attempts 1: {}", attempts);
                attempts = 0;

                // Check if we have a client hello in last encrypted one

                let constraints = TermConstraints::default();
                let mut mutator = ReplaceReuseMutator::new(constraints, true);

                loop {
                    attempts += 1;
                    let mut mutate = trace.clone();
                    mutator.mutate(&mut state, &mut mutate, 0).unwrap();

                    if let Some(last) = mutate.steps.iter().last() {
                        match &last.action {
                            Action::Input(input) => match &input.recipe.term {
                                DYTerm::Variable(_) => {}
                                DYTerm::Application(_, subterms) => {
                                    if let Some(first_subterm) = subterms.iter().next() {
                                        if first_subterm.name() == fn_client_hello.name() {
                                            trace = mutate;
                                            break;
                                        }
                                    }
                                }
                            },
                            Action::Output(_) => {}
                        }
                    }
                }
                println!("attempts 2: {}", attempts);
                attempts = 0;

                // Test if we can replace the sequence number

                let mut mutator = ReplaceMatchMutator::new(constraints, &TLS_SIGNATURE, true);

                loop {
                    attempts += 1;
                    let mut mutate = trace.clone();
                    mutator.mutate(&mut state, &mut mutate, 0).unwrap();

                    if let Some(last) = mutate.steps.iter().last() {
                        match &last.action {
                            Action::Input(input) => match &input.recipe.term {
                                DYTerm::Variable(_) => {}
                                DYTerm::Application(_, subterms) => {
                                    if let Some(last_subterm) = subterms.iter().last() {
                                        if last_subterm.name() == fn_seq_1.name() {
                                            trace = mutate;
                                            break;
                                        }
                                    }
                                }
                            },
                            Action::Output(_) => {}
                        }
                    }
                }
                println!("attempts 3: {}", attempts);
                attempts = 0;

                // Remove sig algo

                let mut mutator = RemoveAndLiftMutator::new(constraints, true);

                loop {
                    attempts += 1;
                    let mut mutate = trace.clone();
                    let result = mutator.mutate(&mut state, &mut mutate, 0).unwrap();

                    if let MutationResult::Mutated = result {
                        if let Some(last) = mutate.steps.iter().last() {
                            match &last.action {
                                Action::Input(input) => match &input.recipe.term {
                                    DYTerm::Variable(_) => {}
                                    DYTerm::Application(_, subterms) => {
                                        if let Some(first_subterm) = subterms.iter().next() {
                                            let sig_alg_extensions = first_subterm
                                                .count_functions_by_name(
                                                    fn_signature_algorithm_extension.name(),
                                                );
                                            let support_groups_extensions = first_subterm
                                                .count_functions_by_name(
                                                    fn_support_group_extension.name(),
                                                );
                                            if sig_alg_extensions == 0
                                                && support_groups_extensions == 1
                                            {
                                                trace = mutate;
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
                println!("attempts 4: {}", attempts);
                attempts = 0;

                // Sucessfully renegotiate

                let mut mutator = ReplaceReuseMutator::new(constraints, true);

                loop {
                    attempts += 1;
                    let mut mutate = trace.clone();
                    mutator.mutate(&mut state, &mut mutate, 0).unwrap();

                    if let Some(last) = mutate.steps.iter().last() {
                        match &last.action {
                            Action::Input(input) => match &input.recipe.term {
                                DYTerm::Variable(_) => {}
                                DYTerm::Application(_, subterms) => {
                                    if let Some(first_subterm) = subterms.iter().next() {
                                        let signatures = first_subterm
                                            .count_functions_by_name(fn_sign_transcript.name());
                                        if signatures == 1 {
                                            trace = mutate;
                                            break;
                                        }
                                    }
                                }
                            },
                            Action::Output(_) => {}
                        }
                    }
                }
                println!("attempts 5: {}", attempts);

                let put_registry = tls_registry();
                let mut context = TraceContext::new(&put_registry, PutOptions::default());
                let _ = trace.execute(&mut context);
                println!("try");
            }
        },
        Some(std::time::Duration::from_secs(30)),
    )
    .expect_crash();
}
