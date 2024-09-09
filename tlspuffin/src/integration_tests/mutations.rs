use puffin::agent::AgentName;
use puffin::algebra::dynamic_function::DescribableFunction;
use puffin::algebra::Term;
use puffin::execution::{forked_execution, AssertExecution};
use puffin::fuzzer::mutations::util::TermConstraints;
use puffin::fuzzer::mutations::{
    RemoveAndLiftMutator, RepeatMutator, ReplaceMatchMutator, ReplaceReuseMutator,
};
use puffin::libafl::corpus::InMemoryCorpus;
use puffin::libafl::mutators::{MutationResult, Mutator};
use puffin::libafl::state::StdState;
use puffin::libafl_bolts::rands::{RomuDuoJrRand, StdRand};
use puffin::put::PutOptions;
use puffin::trace::{Action, Step, Trace, TraceContext};

use crate::put_registry::tls_registry;
use crate::query::TlsQueryMatcher;
use crate::tls::fn_impl::{
    fn_client_hello, fn_encrypt12, fn_seq_1, fn_sign_transcript, fn_signature_algorithm_extension,
    fn_support_group_extension,
};
use crate::tls::seeds::_seed_client_attacker12;
use crate::tls::TLS_SIGNATURE;

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

                let constraints = TermConstraints {
                    min_term_size: 0,
                    max_term_size: 300,
                };
                let mut mutator = ReplaceReuseMutator::new(constraints);

                loop {
                    attempts += 1;
                    let mut mutate = trace.clone();
                    mutator.mutate(&mut state, &mut mutate, 0).unwrap();

                    if let Some(last) = mutate.steps.iter().last() {
                        match &last.action {
                            Action::Input(input) => match &input.recipe {
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
                            Action::Input(input) => match &input.recipe {
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
                                Action::Input(input) => match &input.recipe {
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
                            Action::Input(input) => match &input.recipe {
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
