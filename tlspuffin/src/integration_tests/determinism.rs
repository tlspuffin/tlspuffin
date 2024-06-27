use tlspuffin_macros::apply;

use crate::test_utils::test_puts;

#[apply(test_puts,
    attrs = [
        ignore // neither OpenSSL nor WolfSSL are fully deterministic yet (time/date)
    ],
    filter = all(
        tls13,
        deterministic,
        not(boringssl_binding)
    )
)]
fn test_deterministic_client_attacker_full(put: &str) {
    use crate::tls::{seeds::seed_client_attacker_full, trace_helper::TraceHelperExecutor};

    let ctx1 = seed_client_attacker_full.execute_with(put);

    for i in 0..200 {
        println!("Attempt #{i}...");
        let ctx2 = seed_client_attacker_full.execute_with(put);

        pretty_assertions::assert_eq!(ctx1, ctx2);
    }
}

#[apply(test_puts, filter = all(
    tls13,
    deterministic,
    boringssl_binding
))]
fn test_deterministic_client_attacker_full_boringssl(put: &str) {
    use crate::tls::{seeds::seed_client_attacker_full_boring, trace_helper::TraceHelperExecutor};

    let ctx1 = seed_client_attacker_full_boring.execute_with(put);

    for i in 0..200 {
        println!("Attempt #{i}...");
        let ctx2 = seed_client_attacker_full_boring.execute_with(put);

        pretty_assertions::assert_eq!(ctx1, ctx2);
    }
}
