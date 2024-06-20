use boringssl_sys::RAND_reset_for_fuzzing;

/// Reset BoringSSL PRNG
pub fn reset_rand() {
    unsafe {
        RAND_reset_for_fuzzing();
    }
}

#[cfg(test)]
mod tests {
    use puffin::trace::{TraceContext, TraceExecutor};
    use test_log::test;

    use crate::{
        put_registry::tls_registry,
        tls::{seeds::seed_client_attacker_full_boring, trace_helper::TraceHelper},
    };

    #[test]
    fn test_boringssl_no_randomness_full() {
        let trace = seed_client_attacker_full_boring.build_trace();
        let put_registry = tls_registry();

        let ctx1 = TraceContext::builder(&put_registry).execute(&trace);
        let ctx2 = TraceContext::builder(&put_registry).execute(&trace);

        assert_eq!(ctx1, ctx2);
    }
}
