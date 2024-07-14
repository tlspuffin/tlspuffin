#[test_log::test]
#[cfg(all(
    feature = "tls13",
    feature = "deterministic",
    feature = "boringssl-binding", // neither OpenSSL nor WolfSSL are fully deterministic yet (time/date in tickets)
))]
fn test_deterministic_client_attacker_full() {
    use crate::tls::{seeds::seed_client_attacker_full, trace_helper::TraceHelperExecutor};

    let put = crate::put_registry::tls_registry().default().name();
    let ctx1 = seed_client_attacker_full.execute_with(&put);

    for i in 0..200 {
        println!("Attempt #{i}...");
        let ctx2 = seed_client_attacker_full.execute_with(&put);
        assert_eq!(ctx1, ctx2);
    }
}
