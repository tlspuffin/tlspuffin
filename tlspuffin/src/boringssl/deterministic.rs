use boringssl_sys::RAND_reset_for_fuzzing;

/// Reset BoringSSL PRNG
pub fn reset_rand() {
    unsafe {
        RAND_reset_for_fuzzing();
    }
}

#[cfg(test)]
mod tests {
    use puffin::trace::TraceContext;
    use test_log::test;

    use crate::{
        put_registry::tls_registry,
        tls::{seeds::seed_client_attacker_full_boring, trace_helper::TraceHelper},
    };

    #[test]
    fn test_boringssl_no_randomness_full() {
        let put_registry = tls_registry();

        let trace = seed_client_attacker_full_boring.build_trace();
        let mut ctx1 = TraceContext::builder(&put_registry)
            .set_deterministic(true)
            .build();

        let _ = ctx1.execute(trace);

        let mut ctx2 = TraceContext::builder(&put_registry)
            .set_deterministic(true)
            .build();

        let _ = ctx2.execute(trace);

        assert_eq!(ctx1, ctx2);
    }
}
