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

    use crate::put_registry::tls_registry;
    use crate::tls::seeds::seed_client_attacker_full;
    use crate::tls::trace_helper::TraceHelper;

    // TODO: This test only works in a single threaded cargo test execution
    #[test_log::test]
    fn test_boringssl_no_randomness_full() {
        let put_registry = tls_registry();

        let trace = seed_client_attacker_full.build_trace();
        let mut ctx1 = TraceContext::new(&put_registry, Default::default());
        let _ = trace.execute(&mut ctx1);
        let mut ctx2 = TraceContext::new(&put_registry, Default::default());
        let _ = trace.execute(&mut ctx2);

        assert_eq!(ctx1, ctx2);
    }
}
