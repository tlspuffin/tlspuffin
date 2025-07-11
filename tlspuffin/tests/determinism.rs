use std::thread;
use std::time::Duration;

use puffin::codec::CodecP;
use tlspuffin::protocol::MessageFlight;
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

    let ctx_1 = runner.execute(&trace, &mut 0);

    /*
    Sleep to introduce a time difference between executions.
    This test validates determinism: even with environmental variations
    (e.g., current time), the execution trace should produce identical results.
    */
    thread::sleep(Duration::from_secs(2));
    for i in 0..200 {
        println!("Attempt #{i}...");
        let ctx_2 = runner.execute(&trace, &mut 0);
        assert_eq!(ctx_1, ctx_2);
    }
}

/// Check PUT determinism by checking that the first flight of the server
/// (ServerHello + extensions) is the same
#[cfg(not(feature = "wolfssl430"))]
#[apply(test_puts, filter = all(tls13))]
fn test_attacker_full_det_recreate_no_tickets(put: &str) {
    use tlspuffin::tls::seeds::seed_client_attacker_full;

    fn query_type<T: 'static, 'a>(
        ctx: &'a puffin::trace::TraceContext<tlspuffin::protocol::TLSProtocolBehavior>,
    ) -> &'a T {
        if let Some(knowledge) = ctx.find_variable(
            puffin::algebra::dynamic_function::TypeShape::of::<T>(),
            &puffin::trace::Query {
                source: None,
                matcher: None,
                counter: 0,
            },
        ) {
            knowledge.as_any().downcast_ref::<T>().unwrap()
        } else {
            panic!("query failed");
        }
    }

    let runner = default_runner_for(put);
    let trace = seed_client_attacker_full.build_trace();

    let ctx_1 = runner
        .execute(&trace, &mut 0)
        .expect("failed executing trace");
    let server_hello = query_type::<MessageFlight>(&ctx_1);

    for i in 0..200 {
        println!("Attempt #{i}...");
        let ctx_2 = runner
            .execute(&trace, &mut 0)
            .expect("failed executing trace");
        let server_hello_2 = query_type::<MessageFlight>(&ctx_2);

        assert_eq!(server_hello.get_encoding(), server_hello_2.get_encoding());
    }
}
