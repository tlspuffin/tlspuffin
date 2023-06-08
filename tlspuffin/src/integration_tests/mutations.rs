use log::trace;
use puffin::{
    agent::AgentName,
    algebra::{dynamic_function::DescribableFunction, Term},
    error::Error,
    fuzzer::mutations::{
        util::TermConstraints, GenerateMutator, RemoveAndLiftMutator, RepeatMutator,
        ReplaceMatchMutator, ReplaceReuseMutator,
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

use crate::{
    put_registry::TLS_PUT_REGISTRY,
    query::TlsQueryMatcher,
    test_utils::{expect_crash, expect_crash_result},
    tls::{
        fn_impl::{
            fn_client_hello, fn_encrypt12, fn_eve_cert, fn_eve_pkcs1_signature,
            fn_invalid_signature_algorithm, fn_seq_1, fn_sign_transcript,
            fn_signature_algorithm_extension, fn_support_group_extension,
        },
        seeds::{_seed_client_attacker12, seed_client_attacker_auth},
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

#[test]
#[ignore]
fn test_mutate_seed_cve_2021_3449() {
    let mut state = create_state();
    let _server = AgentName::first();

    expect_crash(move || {
        for _i in 0..5 {
            let mut attempts = 0;

    #[derive(Copy, Clone)]
    struct Attempts {
        repeatmutation: u32,
        replacereusemutation1: u32,
        replacematchmutation2: u32,
        removeliftmutation: u32,
        replacereusemutation3: u32,
    }

    let mut attempts = [Attempts {
        repeatmutation: 0,
        replacereusemutation1: 0,
        replacematchmutation2: 0,
        removeliftmutation: 0,
        replacereusemutation3: 0,
    }; 100];

    for i in 0..100 {
        loop {
            let mut attempt = Attempts {
                repeatmutation: 0,
                replacereusemutation1: 0,
                replacematchmutation2: 0,
                removeliftmutation: 0,
                replacereusemutation3: 0,
            };

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

            for _ in 0..10000 {
                attempt.repeatmutation += 1;
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

            // Check if we have a client hello in last encrypted one

            let constraints = TermConstraints {
                min_term_size: 0,
                max_term_size: 300,
            };
            let mut mutator = ReplaceReuseMutator::new(constraints);

            for _ in 0..10000 {
                attempt.replacereusemutation1 += 1;
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

            // Test if we can replace the sequence number

            let mut mutator = ReplaceMatchMutator::new(constraints, &TLS_SIGNATURE);

            for _ in 0..10000 {
                attempt.replacematchmutation2 += 1;
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

            // Remove sig algo

            let mut mutator = RemoveAndLiftMutator::new(constraints);

            for _ in 0..10000 {
                attempt.removeliftmutation += 1;
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

            // Sucessfully renegotiate

            let mut mutator = ReplaceReuseMutator::new(constraints);

            for _ in 0..10000 {
                attempt.replacereusemutation3 += 1;
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

            let result = expect_crash_result(move || {
                let mut context = TraceContext::new(&TLS_PUT_REGISTRY, PutOptions::default());
                let _ = trace.execute(&mut context);
            });

            if result.is_ok() {
                attempts[i] = attempt;
                break;
            }
        }
    }

    let repeatmutation = attempts
        .iter()
        .map(|a| a.repeatmutation as f64)
        .sum::<f64>() as f64
        / 100.;
    let replacereusemutation1 = attempts
        .iter()
        .map(|a| a.replacereusemutation1 as f64)
        .sum::<f64>() as f64
        / 100.;

    let replacematchmutation2 = attempts
        .iter()
        .map(|a| a.replacematchmutation2 as f64)
        .sum::<f64>() as f64
        / 100.;
    let removeliftmutation = attempts
        .iter()
        .map(|a| a.removeliftmutation as f64)
        .sum::<f64>() as f64
        / 100.;
    let replacereusemutation3 = attempts
        .iter()
        .map(|a| a.replacereusemutation3 as f64)
        .sum::<f64>() as f64
        / 100.;

    println!("{}", repeatmutation);
    println!("{}", replacereusemutation1);
    println!("{}", replacematchmutation2);
    println!("{}", removeliftmutation);
    println!("{}", replacereusemutation3);
}

#[test]
fn test_mutate_seed_cve_2022_25638() {
    let mut state = create_state();

    let constraints = TermConstraints {
        min_term_size: 0,
        max_term_size: 300,
    };

    #[derive(Copy, Clone)]
    struct Attempts {
        certificate_eve: u32,
        certificate_verify_invalid: u32,
        certificate_verify_fn_eve_pkcs1_signature: u32,
    }

    let mut attempts = [Attempts {
        certificate_eve: 0,
        certificate_verify_invalid: 0,
        certificate_verify_fn_eve_pkcs1_signature: 0,
    }; 100];

    for i in 0..100 {
        loop {
            let mut attempt = Attempts {
                certificate_eve: 0,
                certificate_verify_invalid: 0,
                certificate_verify_fn_eve_pkcs1_signature: 0,
            };

            let mut trace = seed_client_attacker_auth(AgentName::first());

            let mut mutator = ReplaceMatchMutator::new(constraints, &TLS_SIGNATURE);

            for _ in 0..10000 {
                let mut mutate = trace.clone();
                let result = mutator.mutate(&mut state, &mut mutate, 0).unwrap();
                if let MutationResult::Mutated = result {
                    attempt.certificate_eve += 1;
                }

                if let Some(certificate) = mutate.steps.get(1) {
                    match &certificate.action {
                        Action::Input(input) => {
                            if input.recipe.count_functions_by_name(fn_eve_cert.name()) == 1 {
                                trace = mutate;
                                break;
                            }
                        }
                        Action::Output(_) => {}
                    }
                }
            }

            let mut mutator = ReplaceMatchMutator::new(constraints, &TLS_SIGNATURE);

            for _ in 0..10000 {
                let mut mutate = trace.clone();
                let result = mutator.mutate(&mut state, &mut mutate, 0).unwrap();
                if let MutationResult::Mutated = result {
                    attempt.certificate_verify_invalid += 1;
                }

                if let Some(certificate) = mutate.steps.get(2) {
                    match &certificate.action {
                        Action::Input(input) => {
                            if input
                                .recipe
                                .count_functions_by_name(fn_invalid_signature_algorithm.name())
                                == 1
                            {
                                trace = mutate;
                                break;
                            }
                        }
                        Action::Output(_) => {}
                    }
                }
            }

            let mut mutator = GenerateMutator::new(0, 10000, constraints, None, &TLS_SIGNATURE);
            for _ in 0..10000 {
                attempt.certificate_verify_fn_eve_pkcs1_signature += 1;
                let mut mutate = trace.clone();
                mutator.mutate(&mut state, &mut mutate, 0).unwrap();

                if let Some(certificate_verify) = mutate.steps.get(2) {
                    match &certificate_verify.action {
                        Action::Input(input) => {
                            if input
                                .recipe
                                .count_functions_by_name(fn_eve_pkcs1_signature.name())
                                == 1
                            {
                                trace = mutate;
                                break;
                            }
                        }
                        Action::Output(_) => {}
                    }
                }
            }

            let mut context = TraceContext::new(&TLS_PUT_REGISTRY, PutOptions::default());
            if let Err(err) = trace.execute(&mut context) {
                match err {
                    Error::SecurityClaim(e) => {
                        println!("{}", e);
                        attempts[i] = attempt;
                        break;
                    }
                    _ => {}
                }
            }
        }
    }

    let certificate_eve = attempts
        .iter()
        .map(|a| a.certificate_eve as f64)
        .sum::<f64>() as f64
        / 100.;
    let certificate_verify_fn_eve_pkcs1_signature = attempts
        .iter()
        .map(|a| a.certificate_verify_fn_eve_pkcs1_signature as f64)
        .sum::<f64>() as f64
        / 100.;
    let certificate_verify_invalid = attempts
        .iter()
        .map(|a| a.certificate_verify_invalid as f64)
        .sum::<f64>() as f64
        / 100.;
    println!("{}", certificate_eve);
    println!("{}", certificate_verify_fn_eve_pkcs1_signature);
    println!("{}", certificate_verify_invalid);
}
