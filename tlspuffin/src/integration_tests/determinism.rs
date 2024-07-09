#[test_log::test]
#[cfg(all(
    feature = "tls13",
    feature = "deterministic",
    feature = "boringssl-binding", // neither OpenSSL nor WolfSSL are fully deterministic yet (time/date in tickets)
))]
fn test_deterministic_client_attacker_full() {
    use puffin::{put_registry::PutDescriptor, trace::TraceContext};

    use crate::{
        put_registry::tls_registry,
        tls::{seeds::seed_client_attacker_full, trace_helper::TraceHelper},
    };

    let put_registry = tls_registry();
    let put = PutDescriptor {
        factory: put_registry.default().name(),
        options: Default::default(),
    };

    let trace = seed_client_attacker_full.build_trace();

    let mut ctx_1 = TraceContext::new(&put_registry, put.clone());
    trace.execute(&mut ctx_1).unwrap();

    for i in 0..200 {
        println!("Attempt #{i}...");
        let mut ctx_2 = TraceContext::new(&put_registry, put.clone());
        trace.execute(&mut ctx_2).unwrap();
        assert_eq!(ctx_1, ctx_2);
    }
}
