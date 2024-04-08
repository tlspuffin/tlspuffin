use core::mem::size_of;
use std::thread::{panicking, park_timeout_ms};

use log::{debug, error};
use puffin::{
    agent::AgentName,
    algebra::{dynamic_function::DescribableFunction, Term, TermType},
    execution::{forked_execution, AssertExecution},
    fuzzer::{
        bit_mutations::*,
        harness::set_default_put_options,
        mutations::{
            trace_mutations, MakeMessage, RemoveAndLiftMutator, RepeatMutator, ReplaceMatchMutator,
            ReplaceReuseMutator,
        },
        utils::TermConstraints,
    },
    libafl::{
        bolts::{
            rands::{RomuDuoJrRand, StdRand},
            HasLen,
        },
        corpus::InMemoryCorpus,
        mutators::{MutationResult, Mutator},
        prelude::ByteFlipMutator,
        state::StdState,
    },
    put::PutOptions,
    trace::{Action, Step, Trace, TraceContext},
};

use crate::{
    protocol::TLSProtocolBehavior,
    put_registry::tls_registry,
    query::TlsQueryMatcher,
    tls::{
        fn_impl::{
            fn_client_hello, fn_encrypt12, fn_seq_1, fn_sign_transcript,
            fn_signature_algorithm_extension, fn_support_group_extension,
        },
        seeds::{
            _seed_client_attacker12, create_corpus, seed_client_attacker, seed_client_attacker_full,
        },
        trace_helper::TraceHelper,
        TLS_SIGNATURE,
    },
};

fn create_state() -> StdState<
    Trace<TlsQueryMatcher>,
    InMemoryCorpus<Trace<TlsQueryMatcher>>,
    RomuDuoJrRand,
    InMemoryCorpus<Trace<TlsQueryMatcher>>,
> {
    let rand = StdRand::with_seed(1235);
    let corpus: InMemoryCorpus<Trace<_>> = InMemoryCorpus::new();
    StdState::new(rand, corpus, InMemoryCorpus::new(), &mut (), &mut ()).unwrap()
}

#[cfg(feature = "tls13")] // require version which supports TLS 1.3
#[test]
#[test_log::test]
fn test_make_message() {
    let mut state = create_state();
    let mut mutator: MakeMessage<
        StdState<
            Trace<TlsQueryMatcher>,
            InMemoryCorpus<Trace<TlsQueryMatcher>>,
            RomuDuoJrRand,
            InMemoryCorpus<Trace<TlsQueryMatcher>>,
        >,
        TLSProtocolBehavior,
    > = MakeMessage::new(TermConstraints::default());

    let mut ctx = TraceContext::new(&TLS_PUT_REGISTRY, PutOptions::default());
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

/// Test that MakeMessage can be applied on a strict sub-term and them on a whole term, erasing all payloads of strict sub-terms
#[cfg(all(feature = "tls13", not(feature = "boringssl-binding")))]
// require version which supports TLS 1.3, removed boringssl-binding as seed_client_attacker_full cannot be executed with boringssl
#[test]
// #[test_log::test]
fn test_byte_remove_payloads() {
    let mut state = create_state();
    let mut mutator_make: MakeMessage<
        StdState<
            Trace<TlsQueryMatcher>,
            InMemoryCorpus<Trace<TlsQueryMatcher>>,
            RomuDuoJrRand,
            InMemoryCorpus<Trace<TlsQueryMatcher>>,
        >,
        TLSProtocolBehavior,
    > = MakeMessage::new(TermConstraints::default());

    let mut ctx = TraceContext::new(&TLS_PUT_REGISTRY, PutOptions::default());
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
                    if let Term::Application(fd, args) = &input.recipe.term {
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
                    if let Term::Application(fd, args) = &input.recipe.term {
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
#[test]
#[test_log::test]
fn test_byte_simple() {
    let mut state = create_state();
    let mut mutator_make: MakeMessage<
        StdState<
            Trace<TlsQueryMatcher>,
            InMemoryCorpus<Trace<TlsQueryMatcher>>,
            RomuDuoJrRand,
            InMemoryCorpus<Trace<TlsQueryMatcher>>,
        >,
        TLSProtocolBehavior,
    > = MakeMessage::new(TermConstraints::default());
    let mut mutator_byte = ByteFlipMutatorDY::new();

    let mut ctx = TraceContext::new(&TLS_PUT_REGISTRY, PutOptions::default());
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
#[test]
#[test_log::test]
fn test_byte_interesting() {
    let mut state = create_state();
    let mut mutator_make: MakeMessage<
        StdState<
            Trace<TlsQueryMatcher>,
            InMemoryCorpus<Trace<TlsQueryMatcher>>,
            RomuDuoJrRand,
            InMemoryCorpus<Trace<TlsQueryMatcher>>,
        >,
        TLSProtocolBehavior,
    > = MakeMessage::new(TermConstraints::default());
    let mut mutator_byte_interesting = ByteInterestingMutatorDY::new();

    let mut ctx = TraceContext::new(&TLS_PUT_REGISTRY, PutOptions::default());
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

#[test]
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

                let mut mutator = RepeatMutator::new(15);

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
                let mut mutator = ReplaceReuseMutator::new(constraints);

                loop {
                    attempts += 1;
                    let mut mutate = trace.clone();
                    mutator.mutate(&mut state, &mut mutate, 0).unwrap();

                    if let Some(last) = mutate.steps.iter().last() {
                        match &last.action {
                            Action::Input(input) => match &input.recipe.term {
                                Term::Variable(_) => {}
                                Term::Application(_, subterms) => {
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

                let mut mutator = ReplaceMatchMutator::new(constraints, &TLS_SIGNATURE);

                loop {
                    attempts += 1;
                    let mut mutate = trace.clone();
                    mutator.mutate(&mut state, &mut mutate, 0).unwrap();

                    if let Some(last) = mutate.steps.iter().last() {
                        match &last.action {
                            Action::Input(input) => match &input.recipe.term {
                                Term::Variable(_) => {}
                                Term::Application(_, subterms) => {
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

                let mut mutator = RemoveAndLiftMutator::new(constraints);

                loop {
                    attempts += 1;
                    let mut mutate = trace.clone();
                    let result = mutator.mutate(&mut state, &mut mutate, 0).unwrap();

                    if let MutationResult::Mutated = result {
                        if let Some(last) = mutate.steps.iter().last() {
                            match &last.action {
                                Action::Input(input) => match &input.recipe.term {
                                    Term::Variable(_) => {}
                                    Term::Application(_, subterms) => {
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

                let mut mutator = ReplaceReuseMutator::new(constraints);

                loop {
                    attempts += 1;
                    let mut mutate = trace.clone();
                    mutator.mutate(&mut state, &mut mutate, 0).unwrap();

                    if let Some(last) = mutate.steps.iter().last() {
                        match &last.action {
                            Action::Input(input) => match &input.recipe.term {
                                Term::Variable(_) => {}
                                Term::Application(_, subterms) => {
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
