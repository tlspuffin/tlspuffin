use std::any::Any;

use criterion::{criterion_group, criterion_main, Criterion};
use puffin::{
    algebra::{dynamic_function::make_dynamic, error::FnError, Term},
    execution::{Runner, TraceRunner},
    fuzzer::mutations::{util::TermConstraints, ReplaceReuseMutator},
    libafl::{
        bolts::rands::{RomuDuoJrRand, StdRand},
        corpus::InMemoryCorpus,
        mutators::Mutator,
        state::StdState,
    },
    term,
    trace::{Spawner, Trace},
    trace_helper::TraceHelper,
};
use tlspuffin::{
    put_registry::tls_registry,
    query::TlsQueryMatcher,
    tls::{fn_impl::*, seeds::*},
};

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
            let args: Vec<Box<dyn Any>> = vec![Box::new(5)];
            dynamic_fn(&args)
        })
    });

    group.finish()
}

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

fn benchmark_mutations(c: &mut Criterion) {
    let mut group = c.benchmark_group("mutations");

    group.bench_function("ReplaceReuseMutator", |b| {
        let mut state = create_state();
        let mut mutator = ReplaceReuseMutator::new(TermConstraints {
            min_term_size: 0,
            max_term_size: 200,
        });
        let mut trace = seed_client_attacker12.build_trace();

        b.iter(|| {
            mutator.mutate(&mut state, &mut trace, 0).unwrap();
        })
    });
}

fn benchmark_trace(c: &mut Criterion) {
    let mut group = c.benchmark_group("trace");

    group.bench_function("term clone", |b| {
        let client_hello: Term<TlsQueryMatcher> = term! {
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
                        (fn_renegotiation_info_extension(fn_empty_bytes_vec))
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
        b.iter(|| runner.execute(&trace))
    });

    group.bench_function("seed_successful12_with_tickets", |b| {
        let trace = seed_successful12_with_tickets.build_trace();
        b.iter(|| runner.execute(&trace))
    });

    group.bench_function("seed_client_attacker", |b| {
        let trace = seed_client_attacker.build_trace();
        b.iter(|| runner.execute(&trace))
    });

    group.bench_function("seed_client_attacker12", |b| {
        let trace = seed_client_attacker12.build_trace();
        b.iter(|| runner.execute(&trace))
    });

    group.bench_function("seed_session_resumption_dhe", |b| {
        let trace = seed_session_resumption_dhe.build_trace();
        b.iter(|| runner.execute(&trace))
    });

    group.bench_function("seed_session_resumption_ke", |b| {
        let trace = seed_session_resumption_ke.build_trace();
        b.iter(|| runner.execute(&trace))
    });

    group.bench_function("seed_session_resumption_dhe_full", |b| {
        let trace = seed_session_resumption_dhe_full.build_trace();
        b.iter(|| runner.execute(&trace))
    });

    group.finish()
}

criterion_group!(
    benches,
    benchmark_dynamic,
    benchmark_trace,
    benchmark_mutations,
    benchmark_seeds,
);
criterion_main!(benches);
