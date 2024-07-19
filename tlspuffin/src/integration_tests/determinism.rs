use tlspuffin_macros::apply;

use crate::test_utils::test_puts;

#[apply(test_puts, filter = all(
    tls13,
    deterministic,
    boringssl_binding // neither OpenSSL nor WolfSSL are fully deterministic yet (time/date in tickets)
))]
fn test_deterministic_client_attacker_full(put: &str) {
    use crate::tls::{seeds::seed_client_attacker_full, trace_helper::TraceHelperExecutor};

    let ctx1 = seed_client_attacker_full.execute_with(put);

    for i in 0..200 {
        println!("Attempt #{i}...");
        let ctx2 = seed_client_attacker_full.execute_with(put);
        assert_eq!(ctx1, ctx2);
    }
}
