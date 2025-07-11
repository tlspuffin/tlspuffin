use criterion::{criterion_group, criterion_main, Criterion};
use puffin::algebra::dynamic_function::make_dynamic;
use puffin::algebra::error::FnError;
use puffin::algebra::Term;
use puffin::execution::{Runner, TraceRunner};
use puffin::fuzzer::mutations::ReplaceReuseMutator;
use puffin::fuzzer::utils::TermConstraints;
use puffin::libafl::corpus::InMemoryCorpus;
use puffin::libafl::mutators::Mutator;
use puffin::libafl::state::StdState;
use puffin::libafl_bolts::rands::{RomuDuoJrRand, StdRand};
use puffin::protocol::EvaluatedTerm;
use puffin::term;
use puffin::trace::{Spawner, Trace};
use puffin::trace_helper::TraceHelper;
use tlspuffin::protocol::TLSProtocolTypes;
use tlspuffin::put_registry::tls_registry;
use tlspuffin::tls::fn_impl::*;
use tlspuffin::tls::seeds::*;

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

criterion_group!(
    benches,
    benchmark_dynamic,
    benchmark_trace,
    benchmark_mutations,
    benchmark_seeds,
);
criterion_main!(benches);
