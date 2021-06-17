use std::ops::Deref;

use libafl::bolts::rands::{Rand, RomuDuoJrRand, RomuTrioRand, StdRand};
use libafl::corpus::InMemoryCorpus;
use libafl::mutators::{MutationResult, Mutator};
use libafl::state::StdState;
use openssl::rand::rand_bytes;

use crate::agent::AgentName;
use crate::fuzzer::mutations::{
    RemoveAndLiftMutator, RepeatMutator, ReplaceMatchMutator, ReplaceReuseMutator,
};
use crate::fuzzer::seeds::*;
use crate::openssl_binding::make_deterministic;
use crate::term::Term;
use crate::trace::{Action, InputAction, Step, Trace};

#[test]
fn test_openssl_no_randomness() {
    make_deterministic(); // his affects also other tests, which is fine as we generally prefer deterministic tests
    let mut buf1 = [0; 2];
    rand_bytes(&mut buf1).unwrap();
    assert_eq!(buf1, [70, 100]);
}

/// Checks whether repeat can repeat the last step
#[test]
fn test_repeat_cve() {
    let rand = StdRand::with_seed(1235);
    let corpus: InMemoryCorpus<Trace> = InMemoryCorpus::new();
    let mut state = StdState::new(rand, corpus, InMemoryCorpus::new(), ());
    let client = AgentName::first();
    let server = client.next();
    let _trace = seed_client_attacker12(client, server);

    let mut mutator = RepeatMutator::new();

    fn check_is_encrypt12(step: &Step) -> bool {
        if let Action::Input(input) = &step.action {
            if input.recipe.name() == "tlspuffin::tls::fn_utils::fn_encrypt12" {
                return true;
            }
        }
        false
    }

    loop {
        let mut trace = seed_client_attacker12(client, server);
        mutator.mutate(&mut state, &mut trace, 0).unwrap();

        let length = trace.steps.len();
        if let Some(last) = trace.steps.get(length - 1) {
            if check_is_encrypt12(last) {
                if let Some(step) = trace.steps.get(length - 2) {
                    if check_is_encrypt12(step) {
                        break;
                    }
                }
            }
        }

        /*write_graphviz(
            format!("mutations_preview/test_mutation_after{}.svg", i).as_str(),
            "svg",
            trace.dot_graph(true).as_str(),
        )
        .unwrap();*/
    }
}

#[test]
fn test_replace_match_cve() {
    let rand = StdRand::with_seed(1235);
    let corpus: InMemoryCorpus<Trace> = InMemoryCorpus::new();
    let mut state = StdState::new(rand, corpus, InMemoryCorpus::new(), ());
    let client = AgentName::first();
    let server = client.next();
    let _trace = seed_client_attacker12(client, server);

    let mut mutator = ReplaceMatchMutator::new();

    loop {
        let mut trace = seed_client_attacker12(client, server);
        mutator.mutate(&mut state, &mut trace, 0).unwrap();

        if let Some(last) = trace.steps.iter().last() {
            match &last.action {
                Action::Input(input) => match &input.recipe {
                    Term::Variable(_) => {}
                    Term::Application(_, subterms) => {
                        if let Some(last_subterm) = subterms.iter().last() {
                            if last_subterm.name() != "tlspuffin::tls::fn_constants::fn_seq_0" {
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

#[test]
fn test_remove_lift_removes_extensions() {
    let rand = StdRand::with_seed(1235);
    let corpus: InMemoryCorpus<Trace> = InMemoryCorpus::new();
    let mut state = StdState::new(rand, corpus, InMemoryCorpus::new(), ());
    let client = AgentName::first();
    let server = client.next();
    let _trace = seed_client_attacker12(client, server);

    let mut mutator = RemoveAndLiftMutator::new();

    // Returns the amount of extensions in the trace
    fn sum_extension_appends(trace: &Trace) -> u16 {
        trace
            .steps
            .iter()
            .map(|step| match &step.action {
                Action::Input(input) => {
                    let mut extension_appends = 0;
                    for term in input.recipe.into_iter() {
                        if let Term::Application(func, _) = term {
                            if func.name() == "tlspuffin::tls::fn_extensions::fn_client_extensions_append" {
                                extension_appends += 1;
                            }
                        }
                    }
                    extension_appends
                }
                Action::Output(_) => 0,
            })
            .sum::<u16>()
    }

    loop {
        let mut trace = seed_client_attacker12(client, server);
        let before_mutation = sum_extension_appends(&trace);
        let result = mutator.mutate(&mut state, &mut trace, 0).unwrap();

        if let MutationResult::Mutated = result {
            let after_mutation = sum_extension_appends(&trace);
            if after_mutation != before_mutation {
                break;
            }
        }
    }
}

#[test]
fn test_rand() {
    let mut rand = RomuDuoJrRand::with_seed(1337);
    assert_ne!(rand.between(0, 1), rand.between(0, 1))
}
