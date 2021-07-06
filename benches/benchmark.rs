use std::any::Any;

use criterion::{criterion_group, criterion_main, Criterion};
use libafl::bolts::rands::StdRand;
use libafl::corpus::InMemoryCorpus;
use libafl::mutators::Mutator;
use libafl::state::StdState;
use ring::hmac::{Key, HMAC_SHA256};

use tlspuffin::agent::AgentName;
use tlspuffin::fuzzer::mutations::ReplaceReuseMutator;
use tlspuffin::fuzzer::seeds::*;
use tlspuffin::term;
use tlspuffin::trace::{Trace};
use tlspuffin::term::dynamic_function::make_dynamic;
use tlspuffin::tls::fn_impl::fn_hmac256;
use tlspuffin::tls::fn_impl::*;
use tlspuffin::trace::TraceContext;

fn benchmark_dynamic(c: &mut Criterion) {
    let mut group = c.benchmark_group("op_hmac256");

    group.bench_function("op_hmac256 static", |b| {
        b.iter(|| {
            let key_data = [0; 256];
            let key = Key::new(HMAC_SHA256, &key_data);
            let data = "test".as_bytes().to_vec();
            fn_hmac256(&key, &data)
        })
    });

    group.bench_function("op_hmac256 dyn", |b| {
        b.iter(|| {
            let key_data = [0; 256];
            let key = Key::new(HMAC_SHA256, &key_data);
            let data = "test".as_bytes().to_vec();
            let (_, dynamic_fn) = make_dynamic(&fn_hmac256);
            let args: Vec<Box<dyn Any>> = vec![Box::new(key), Box::new(data)];
            dynamic_fn(&args)
        })
    });

    group.finish()
}

fn benchmark_mutations(c: &mut Criterion) {
    let mut group = c.benchmark_group("mutations");

    group.bench_function("ReplaceReuseMutator", |b| {
        let rand = StdRand::with_seed(45);
        let corpus: InMemoryCorpus<Trace> = InMemoryCorpus::new();
        let mut state = StdState::new(rand, corpus, InMemoryCorpus::new(), ());
        let client = AgentName::first();
        let server = client.next();
        let mut mutator = ReplaceReuseMutator::new();
        let mut trace = seed_client_attacker12(client, server);

        b.iter(|| {
            mutator.mutate(&mut state, &mut trace, 0).unwrap();
        })
    });
}

fn benchmark_trace(c: &mut Criterion) {
    let mut group = c.benchmark_group("trace");

    group.bench_function("term clone", |b| {
        let client_hello = term! {
              fn_client_hello(
                fn_protocol_version12,
                fn_new_random,
                fn_new_session_id,
                fn_cipher_suites13,
                fn_compressions,
                (fn_client_extensions_append(
                    (fn_client_extensions_append(
                        (fn_client_extensions_append(
                            (fn_client_extensions_append(
                                fn_client_extensions_new,
                                fn_secp384r1_support_group_extension
                            )),
                            fn_signature_algorithm_extension
                        )),
                        fn_key_share_extension
                    )),
                    fn_supported_versions13_extension
                ))
            )
        };

        b.iter(|| client_hello.clone())
    });
}

fn benchmark_seeds(c: &mut Criterion) {
    let mut group = c.benchmark_group("seeds");

    group.bench_function("seed_successful", |b| {
        b.iter(|| {
            let mut ctx = TraceContext::new();
            let client = AgentName::first();
            let server = client.next();
            let trace = seed_successful(client, server);

            trace.spawn_agents(&mut ctx).unwrap();
            trace.execute(&mut ctx).unwrap();
        })
    });

    group.bench_function("seed_successful12", |b| {
        b.iter(|| {
            let mut ctx = TraceContext::new();
            let client = AgentName::first();
            let server = client.next();
            let trace = seed_successful12(client, server);

            trace.spawn_agents(&mut ctx).unwrap();
            trace.execute(&mut ctx).unwrap()
        })
    });

    group.bench_function("seed_client_attacker", |b| {
        b.iter(|| {
            let mut ctx = TraceContext::new();
            let client = AgentName::first();
            let server = client.next();
            let trace = seed_client_attacker(client, server);

            trace.spawn_agents(&mut ctx).unwrap();
            trace.execute(&mut ctx).unwrap();
        })
    });

    group.bench_function("seed_client_attacker12", |b| {
        b.iter(|| {
            let mut ctx = TraceContext::new();
            let client = AgentName::first();
            let server = client.next();
            let trace = seed_client_attacker12(client, server);

            trace.spawn_agents(&mut ctx).unwrap();
            trace.execute(&mut ctx).unwrap();
        })
    });

    group.finish()
}

criterion_group!(benches, benchmark_dynamic, benchmark_trace, benchmark_mutations, benchmark_seeds);
criterion_main!(benches);
