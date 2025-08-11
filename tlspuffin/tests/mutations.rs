use puffin::agent::AgentName;
use puffin::algebra::dynamic_function::DescribableFunction;
use puffin::algebra::{DYTerm, TermType};
use puffin::execution::{run_in_subprocess, TraceRunner};
use puffin::fuzzer::mutations::{
    RemoveAndLiftMutator, RepeatMutator, ReplaceMatchMutator, ReplaceReuseMutator,
};
use puffin::fuzzer::utils::TermConstraints;
use puffin::libafl::corpus::InMemoryCorpus;
use puffin::libafl::mutators::{MutationResult, Mutator};
use puffin::libafl::state::StdState;
use puffin::libafl_bolts::rands::{RomuDuoJrRand, StdRand};
use puffin::test_utils::AssertExecution;
use puffin::trace::{Action, Step, Trace};
use tlspuffin::protocol::TLSProtocolTypes;
use tlspuffin::put_registry::tls_registry;
use tlspuffin::test_utils::default_runner_for;
use tlspuffin::tls::fn_impl::{
    fn_client_hello, fn_encrypt12, fn_seq_1, fn_sign_transcript, fn_signature_algorithm_extension,
    fn_support_group_extension_make,
};
use tlspuffin::tls::seeds::_seed_client_attacker12;
use tlspuffin::tls::TLS_SIGNATURE;

fn create_state() -> StdState<
    Trace<TLSProtocolTypes>,
    InMemoryCorpus<Trace<TLSProtocolTypes>>,
    RomuDuoJrRand,
    InMemoryCorpus<Trace<TLSProtocolTypes>>,
> {
    let rand = StdRand::with_seed(1235);
    let corpus: InMemoryCorpus<Trace<_>> = InMemoryCorpus::new();
    StdState::new(rand, corpus, InMemoryCorpus::new(), &mut (), &mut ()).unwrap()
}

#[test_log::test]
#[ignore]
fn test_mutate_seed_cve_2021_3449() {
    let runner = default_runner_for(tls_registry().default().name());
    let mut state = create_state();

    run_in_subprocess(
        move || {
            for _i in 0..5 {
                let mut attempts = 0;

                let (mut trace, _) = _seed_client_attacker12(AgentName::first());

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
                                                    fn_support_group_extension_make.name(),
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

                let _ = runner.execute(trace, &mut 0);
                println!("try");
            }
        },
        std::time::Duration::from_secs(30),
    )
    .expect_crash();
}
