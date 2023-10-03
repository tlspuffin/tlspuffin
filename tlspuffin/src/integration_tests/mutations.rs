use std::thread::panicking;
use log::{debug, error};
use puffin::algebra::TermType;
use puffin::{
    agent::AgentName,
    algebra::{dynamic_function::DescribableFunction, Term},
    fuzzer::{mutations::{ReplaceReuseMutator, RemoveAndLiftMutator, RepeatMutator, ReplaceMatchMutator},
             utils::TermConstraints,
    },
    libafl::{
        bolts::rands::{RomuDuoJrRand, StdRand},
        corpus::InMemoryCorpus,
        mutators::{MutationResult, Mutator},
        state::StdState,
    },
    put::PutOptions,
    trace::{Action, Step, Trace, TraceContext},
};
use puffin::fuzzer::harness::set_default_put_options;
use puffin::fuzzer::{mutations::MakeMessage,
                    bit_mutations::*};
use puffin::fuzzer::mutations::trace_mutations;
use puffin::libafl::prelude::ByteFlipMutator;

use crate::{
    put_registry::TLS_PUT_REGISTRY,
    query::TlsQueryMatcher,
    test_utils::expect_crash,
    tls::{
        fn_impl::{
            fn_client_hello, fn_encrypt12, fn_seq_1, fn_sign_transcript,
            fn_signature_algorithm_extension, fn_support_group_extension,
        },
        seeds::_seed_client_attacker12,
        TLS_SIGNATURE,
    },
};
use crate::protocol::TLSProtocolBehavior;
use crate::tls::seeds::{create_corpus, seed_client_attacker, seed_client_attacker_full};
use crate::tls::trace_helper::TraceHelper;

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
    let mut mutator : MakeMessage<StdState<Trace<TlsQueryMatcher>, InMemoryCorpus<Trace<TlsQueryMatcher>>, RomuDuoJrRand, InMemoryCorpus<Trace<TlsQueryMatcher>>>, TLSProtocolBehavior> = MakeMessage::new(TermConstraints::default());

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
#[cfg(feature = "tls13")] // require version which supports TLS 1.3
#[test]
#[test_log::test]
fn test_byte_remove_payloads() {
    let mut state = create_state();
    let mut mutator_make : MakeMessage<StdState<Trace<TlsQueryMatcher>, InMemoryCorpus<Trace<TlsQueryMatcher>>, RomuDuoJrRand, InMemoryCorpus<Trace<TlsQueryMatcher>>>, TLSProtocolBehavior> = MakeMessage::new(TermConstraints::default());

    let mut ctx = TraceContext::new(&TLS_PUT_REGISTRY, PutOptions::default());
    ctx.set_deterministic(true);
    let mut trace = seed_client_attacker_full.build_trace();
    set_default_put_options(PutOptions::default());

    loop {
        mutator_make.mutate(&mut state, &mut trace, 0).unwrap();

        if let Some(first) = trace.steps.get(0) {
            match &first.action {
                Action::Input(input) => {
                    if let Term::Application(fd, args) = &input.recipe.term {
                        if args.len() > 5 && input.recipe.is_symbolic() && !args[5].payloads_to_replace().is_empty() {
                            error!("Found sub-term: {:?}", args[5]);
                            error!("MakeMessage created new payloads in a strict sub-term: {:?}", args[5].payloads_to_replace());
                            break;
                        }
                    }
                },
                Action::Output(_) => {},
            }
        }
    }

    loop {
        mutator_make.mutate(&mut state, &mut trace, 0).unwrap();

            if let Some(first) = trace.steps.get(0) {
                match &first.action {
                    Action::Input(input) => {
                        if let Term::Application(fd, args) = &input.recipe.term {
                            if args.len() > 5 &&
                                !input.recipe.is_symbolic() {
                                    if args[5].payloads_to_replace().is_empty() &&
                                        input.recipe.payloads_to_replace().len() == 1
                                    {
                                        error!("MakeMessage created new payloads in the client hello {} and removed payloads in the strict sub-terms. New paylaod: {:?}", &input.recipe, input.recipe.payloads.as_ref().unwrap());
                                        break
                                    } else {
                                        panic!("Failed to remove payloads in strict sub-terms when adding a payload at top level")
                                    }
                            }
                        }
                    },
                    Action::Output(_) => {},
                }
            }
    }
}


#[cfg(feature = "tls13")] // require version which supports TLS 1.3
#[test]
#[test_log::test]
fn test_byte() {
    let mut state = create_state();
    let mut mutator_make : MakeMessage<StdState<Trace<TlsQueryMatcher>, InMemoryCorpus<Trace<TlsQueryMatcher>>, RomuDuoJrRand, InMemoryCorpus<Trace<TlsQueryMatcher>>>, TLSProtocolBehavior> = MakeMessage::new(TermConstraints::default());
    let mut mutator_byte = ByteFlipMutatorDY::new();

    let mut ctx = TraceContext::new(&TLS_PUT_REGISTRY, PutOptions::default());
    ctx.set_deterministic(true);
    let mut trace = seed_client_attacker_full.build_trace();
    set_default_put_options(PutOptions::default());

    loop {
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
            if !payloads.is_empty() {
                error!("MakeMessage created new payloads: {:?}", payloads);
                break;
                }
            }
        }

    loop {
        mutator_byte.mutate(&mut state, &mut trace, 0).unwrap();

        if let Some(first) = trace.steps.get(0) {
            match &first.action {
                Action::Input(input) => {
                    let mut found = false;
                    for payload in input.recipe.all_payloads() {
                        if payload.payload_0 != payload.payload {
                            error!("ByteFlipMutatorDY created different payloads: {:?}", payload);
                            found = true;
                        }
                    }
                    if found {break;}
                },
                Action::Output(_) => {},
            }
        }
    }
}

#[cfg(feature = "tls13")] // require version which supports TLS 1.3
#[test]
#[test_log::test]
fn test_byte_interesting() {
    let mut state = create_state();
    let mut mutator_make : MakeMessage<StdState<Trace<TlsQueryMatcher>, InMemoryCorpus<Trace<TlsQueryMatcher>>, RomuDuoJrRand, InMemoryCorpus<Trace<TlsQueryMatcher>>>, TLSProtocolBehavior> = MakeMessage::new(TermConstraints::default());
    let mut mutator_byte_interesting = ByteInterestingMutatorDY::new();

    let mut ctx = TraceContext::new(&TLS_PUT_REGISTRY, PutOptions::default());
    ctx.set_deterministic(true);
    let mut trace = seed_client_attacker_full.build_trace();
    set_default_put_options(PutOptions::default());

    loop {
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
            if !payloads.is_empty() {
                debug!("MakeMessage created new payloads: {:?}", payloads);
                break;
            }
        }
    }

    loop {
        mutator_byte_interesting.mutate(&mut state, &mut trace, 0).unwrap();

        if let Some(first) = trace.steps.get(0) {
            match &first.action {
                Action::Input(input) => {
                    let mut found = false;
                    let t =  &input.recipe;
                    for payload in t.all_payloads() {
                        if payload.payload_0 != payload.payload {
                            debug!("ByteInterestingMutatorDY created different payloads: {:?}", payload);
                            found = true;
                        }
                    }
                    let e1 = t.evaluate(&ctx).unwrap();
                    let e2 = t.clone().evaluate_symbolic(&ctx).unwrap();
                    if found && e1 != e2 {
                        break;
                    }
                },
                Action::Output(_) => {},
            }
        }
    }
}

#[test]
#[ignore]
fn test_mutate_seed_cve_2021_3449() {
    let mut state = create_state();
    let _server = AgentName::first();

    expect_crash(move || {
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
                                        if sig_alg_extensions == 0 && support_groups_extensions == 1
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
            attempts = 0;

            let mut context = TraceContext::new(&TLS_PUT_REGISTRY, PutOptions::default());
            let _ = trace.execute(&mut context);
            println!("try");
        }
    });
}
