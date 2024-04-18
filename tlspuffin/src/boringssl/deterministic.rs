use boringssl_sys::RAND_reset_for_fuzzing;

/// Reset BoringSSL PRNG
pub fn reset_rand() {
    unsafe {
        RAND_reset_for_fuzzing();
    }
}

#[cfg(test)]
mod tests {
    use puffin::{put::PutOptions, trace::TraceContext};

    use crate::{
        put_registry::tls_registry,
        tls::{seeds::seed_client_attacker_full_boring, trace_helper::TraceHelper},
    };

    // TODO: This test only works in a single threaded cargo test execution
    #[test]
    fn test_boringssl_no_randomness_full() {
        let put_registry = tls_registry();

        let trace = seed_client_attacker_full_boring.build_trace();
        let mut ctx1 = TraceContext::new(&put_registry, PutOptions::default());
        ctx1.set_deterministic(true);
        let _ = trace.execute(&mut ctx1);
        let mut ctx2 = TraceContext::new(&put_registry, PutOptions::default());
        ctx2.set_deterministic(true);
        let _ = trace.execute(&mut ctx2);

        assert_eq!(ctx1, ctx2);
    }
}
