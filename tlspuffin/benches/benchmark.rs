use std::time::Duration;

use criterion::{criterion_group, criterion_main, Criterion};
use puffin::algebra::dynamic_function::make_dynamic;
use puffin::algebra::error::FnError;
use puffin::algebra::{Term, TermType};
use puffin::error::Error;
use puffin::execution::{Runner, TraceRunner};
use puffin::fuzzer::mutations::ReplaceReuseMutator;
use puffin::fuzzer::term_zoo::TermZoo;
use puffin::fuzzer::utils::TermConstraints;
use puffin::libafl::corpus::InMemoryCorpus;
use puffin::libafl::mutators::{MutationResult, Mutator};
use puffin::libafl::prelude::HasRand;
use puffin::libafl::state::StdState;
use puffin::libafl_bolts::prelude::Rand;
use puffin::libafl_bolts::rands::{RomuDuoJrRand, StdRand};
use puffin::protocol::EvaluatedTerm;
use puffin::trace::{Spawner, Trace, TraceContext};
use puffin::trace_helper::TraceHelper;
use puffin::{libafl, term};
use tlspuffin::protocol::{TLSProtocolBehavior, TLSProtocolTypes};
use tlspuffin::put_registry::tls_registry;
use tlspuffin::test_utils::*;
use tlspuffin::tls::fn_impl::*;
use tlspuffin::tls::seeds::*;
use tlspuffin::tls::TLS_SIGNATURE;

fn fn_benchmark_example(a: &u64) -> Result<u64, FnError> {
    Ok(*a * *a)
}

fn benchmark_dynamic(c: &mut Criterion) {
    let mut group = c.benchmark_group("op_hmac256");

    group.bench_function("fn_benchmark_example static", |b| {
        b.iter(|| fn_benchmark_example(&5))
    });

    group.bench_function("fn_benchmark_example dynamic", |b| {
        b.iter(|| {
            let (_, dynamic_fn) = make_dynamic(&fn_benchmark_example);
            let args: Vec<Box<dyn EvaluatedTerm<TLSProtocolTypes>>> = vec![Box::new(5u64)];
            dynamic_fn(&args)
        })
    });

    group.finish()
}

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

fn benchmark_mutations(c: &mut Criterion) {
    let mut group = c.benchmark_group("mutations");

    group.bench_function("ReplaceReuseMutator", |b| {
        let mut state = create_state();
        let mut mutator = ReplaceReuseMutator::new(
            TermConstraints {
                min_term_size: 0,
                max_term_size: 200,
                no_payload_in_subterm: false,
                not_inside_list: false,
                weighted_depth: false,
                ..TermConstraints::default()
            },
            true,
            true,
        );
        let mut trace = seed_client_attacker12.build_trace();

        b.iter(|| {
            mutator.mutate(&mut state, &mut trace, 0).unwrap();
        })
    });
}

fn benchmark_trace(c: &mut Criterion) {
    let mut group = c.benchmark_group("trace");

    group.bench_function("term clone", |b| {
        let client_hello: Term<TLSProtocolTypes> = term! {
              fn_client_hello(
                fn_protocol_version12,
                fn_new_random,
                fn_new_session_id,
                (fn_append_cipher_suite(
                    (fn_new_cipher_suites()),
                    // force TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
                    fn_cipher_suite12
                )),
                fn_compressions,
                (fn_client_extensions_append(
                    (fn_client_extensions_append(
                        (fn_client_extensions_append(
                            (fn_client_extensions_append(
                                (fn_client_extensions_append(
                                    (fn_client_extensions_append(
                                        fn_client_extensions_new,
                                        (fn_support_group_extension(fn_named_group_secp384r1))
                                    )),
                                    fn_signature_algorithm_extension
                                )),
                                fn_ec_point_formats_extension
                            )),
                            fn_signed_certificate_timestamp_extension
                        )),
                         // Enable Renegotiation
                        (fn_renegotiation_info_extension((fn_payload_u8(fn_empty_bytes_vec))))
                    )),
                    // Add signature cert extension
                    fn_signature_algorithm_cert_extension
                ))
            )
        };

        b.iter(|| client_hello.clone())
    });
}

fn benchmark_seeds(c: &mut Criterion) {
    let mut group = c.benchmark_group("seeds");

    let registry = tls_registry();
    let runner = Runner::new(registry.clone(), Spawner::new(registry));

    group.bench_function("seed_successful", |b| {
        let trace = seed_successful.build_trace();
        b.iter(|| runner.execute(&trace, &mut 0))
    });

    group.bench_function("seed_successful12_with_tickets", |b| {
        let trace = seed_successful12_with_tickets.build_trace();
        b.iter(|| runner.execute(&trace, &mut 0))
    });

    group.bench_function("seed_client_attacker", |b| {
        let trace = seed_client_attacker.build_trace();
        b.iter(|| runner.execute(&trace, &mut 0))
    });

    group.bench_function("seed_client_attacker12", |b| {
        let trace = seed_client_attacker12.build_trace();
        b.iter(|| runner.execute(&trace, &mut 0))
    });

    group.bench_function("seed_session_resumption_dhe", |b| {
        let trace = seed_session_resumption_dhe.build_trace();
        b.iter(|| runner.execute(&trace, &mut 0))
    });

    group.bench_function("seed_session_resumption_ke", |b| {
        let trace = seed_session_resumption_ke.build_trace();
        b.iter(|| runner.execute(&trace, &mut 0))
    });

    group.bench_function("seed_session_resumption_dhe_full", |b| {
        let trace = seed_session_resumption_dhe_full.build_trace();
        b.iter(|| runner.execute(&trace, &mut 0))
    });

    group.finish()
}

fn compute_zoo_in_generate_mutator(c: &mut Criterion) {
    let mut group = c.benchmark_group("mutations");
    let tls_registry = tls_registry();
    let spawner = Spawner::new(tls_registry.clone());
    let ctx = TraceContext::new(spawner);
    let mut i = 0;

    group.bench_function("compute_zoo_in_generate_mutator", |b| {
        b.iter(|| {
            let _ = TermZoo::<TLSProtocolBehavior>::generate(
                &ctx,
                &TLS_SIGNATURE,
                &mut StdRand::with_seed(i),
                TermConstraints::default().zoo_gen_how_many,
            );
            i = i + 1;
        })
    });
}

// Ignored as it is redundant with benchmark_test_term_payloads_mutate_eval
fn benchmark_term_payloads_eval(c: &mut Criterion) {
    let mut group = c.benchmark_group("mutations");

    let mut success_count = 0;
    let mut add_payload_fail = 0;
    let mut eval_payload_fail = 0;
    let ignored_functions = ignore_add_payload(); // currently is the same as ignore_eval()
    let mut closure = |term: &Term<TLSProtocolTypes>,
                       ctx: &TraceContext<TLSProtocolBehavior>,
                       rand2: &mut RomuDuoJrRand| {
        term.evaluate(&ctx).map(|_eval| {
            let mut term_with_payloads = term.clone();
            add_payloads_randomly(&mut term_with_payloads, rand2, &ctx);
            if term_with_payloads.all_payloads().len() == 0 {
                log::warn!("Failed to add payloads, skipping... For:\n   {term_with_payloads}");
                if !ignored_functions.contains(term.name()) {
                    add_payload_fail += 1;
                }
                return Err(Error::Term("Failed to add payloads".to_string()));
            } else {
                log::debug!("Term with payloads: {term_with_payloads}");
                // Sanity check:
                test_pay(&term_with_payloads);
                match &term_with_payloads.evaluate(&ctx) {
                    Ok(_eval) => {
                        log::debug!("Eval success!");
                        success_count += 1;
                        return Ok(());
                    }
                    Err(e) => {
                        log::error!("Eval FAILED with payloads: {term_with_payloads}.");
                        if !ignored_functions.contains(term.name()) {
                            eval_payload_fail += 1;
                        }
                        return Err(Error::Term("Failed to evaluate with payloads".to_string()));
                    }
                }
            }
        })?
    };

    let mut i = 0;

    group.bench_function("test_term_payloads_eval", |b| {
        b.iter(|| {
            let res = zoo_test(
                &mut closure,
                StdRand::with_seed(i),
                100,
                true,
                false,
                true,
                true,
                None,
                &ignored_functions,
            );
            log::error!("Step {i}");
            i += 1;
            assert!(res);
        })
    });
}

fn benchmark_test_term_payloads_mutate_eval(c: &mut Criterion) {
    let mut group = c.benchmark_group("mutations");

    let mut success_count = 0;
    let mut add_payload_fail = 0;
    let mut mutate_fail = 0;
    let mut mutate_eval_fail = 0;
    let ignored_functions = ignore_add_payload_mutate(); // currently is the same as ignore_eval()

    let mut closure = |term: &Term<TLSProtocolTypes>,
                       ctx: &TraceContext<TLSProtocolBehavior>,
                       rand2: &mut RomuDuoJrRand| {
        let mut state = create_state();
        let mut term_with_payloads = term.clone();
        add_payloads_randomly(&mut term_with_payloads, rand2, &ctx);
        if term_with_payloads.all_payloads().len() == 0 {
            log::warn!("Failed to add payloads, skipping... For:\n   {term_with_payloads}");
            if !ignored_functions.contains(term.name()) {
                add_payload_fail += 1;
            }
            return Err(Error::Term("Failed to add payloads".to_string()));
        } else {
            log::debug!("Term with payloads: {term_with_payloads}");
            // Sanity check:
            test_pay(&term_with_payloads);
            let mut tries = 0;
            while tries < 1_000 {
                let mut mutant = term_with_payloads.clone();
                tries += 1;
                let mut all_payloads = mutant.all_payloads_mut();
                let idx = state.rand_mut().between(0, (all_payloads.len() - 1) as u64) as usize;
                let payload_to_mutate = all_payloads.remove(idx);
                let payload_to_mutate_orig = payload_to_mutate.payload_0.clone();
                let payload_to_mutate = &mut payload_to_mutate.payload;
                match libafl::mutators::mutations::BitFlipMutator
                    .mutate(&mut state, payload_to_mutate, 0)
                    .unwrap()
                {
                    MutationResult::Mutated => {
                        if payload_to_mutate_orig == *payload_to_mutate {
                            log::warn!("Mutated payload is the same as original: {payload_to_mutate_orig:?} == {payload_to_mutate:?}");
                            mutate_fail += 1;
                            continue;
                        }
                        log::debug!("Success MakeMessage: adding to new inputs");
                        match &mutant.evaluate(&ctx) {
                            Ok(_eval) => {
                                log::debug!("Eval mutant success!");
                                success_count += 1;
                                return Ok(());
                            }
                            Err(e) => {
                                log::warn!("Eval FAILED with payloads: {term_with_payloads} and error {e}.");
                                if !ignored_functions.contains(term.name()) {
                                    mutate_eval_fail += 1;
                                }
                                continue;
                            }
                        }
                    }
                    MutationResult::Skipped => {
                        mutate_fail += 1;
                    }
                }
            }
            return Err(Error::Term(format!(
                "Failed to find a way to mutate {term_with_payloads}!"
            )));
        }
    };

    let mut i = 0;

    group.bench_function("test_term_payloads_mutate_eval", |b| {
        b.iter(|| {
            let res = zoo_test(
                &mut closure,
                StdRand::with_seed(i),
                100,
                true,
                false,
                true,
                true,
                None,
                &ignored_functions,
            );
            log::error!("Step {i}");
            assert!(res);
        })
    });
}

criterion_group!(
    benches,
    benchmark_dynamic,
    benchmark_trace,
    benchmark_mutations,
    benchmark_seeds,
);
criterion_group! {
    name = long_benches;
    config = Criterion::default().measurement_time(Duration::from_secs(20)).sample_size(10);
    targets =
    compute_zoo_in_generate_mutator,
//    benchmark_term_payloads_eval, subsumed by benchmark_test_term_payloads_mutate_eval
    benchmark_test_term_payloads_mutate_eval
}
criterion_main!(benches, long_benches);
