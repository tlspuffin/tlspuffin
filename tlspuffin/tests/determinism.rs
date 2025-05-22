use std::thread;
use std::time::Duration;

use tlspuffin::test_utils::prelude::*;

/*
OpenSSL is currently excuded because:
  (i) we currently don't have a working RNG reseed for the OpenSSL CPUT (see Issue #393),
  (ii) we don't have a time hook at the moment for the OpenSSL CPUT.
*/
#[cfg(not(feature = "wolfssl430"))]
#[apply(test_puts, filter = not(openssl))]
fn test_attacker_full_det_recreate(put: &str) {
    use tlspuffin::tls::seeds::seed_client_attacker_full;

    let runner = default_runner_for(put);
    let trace = seed_client_attacker_full.build_trace();

    let ctx_1 = runner.execute(&trace);

    /*
    Sleep to introduce a time difference between executions.
    This test validates determinism: even with environmental variations
    (e.g., current time), the execution trace should produce identical results.
    */
    thread::sleep(Duration::from_secs(2));
    for i in 0..200 {
        println!("Attempt #{i}...");
        let ctx_2 = runner.execute(&trace);
        assert_eq!(ctx_1, ctx_2);
    }
}
