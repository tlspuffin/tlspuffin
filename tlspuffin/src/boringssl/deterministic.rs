use boringssl_sys::RAND_reset_for_fuzzing;

/// Reset BoringSSL PRNG
pub fn reset_rand() {
    unsafe {
        RAND_reset_for_fuzzing();
    }
}

#[cfg(test)]
mod tests {
    use crate::test_utils::prelude::*;
    use crate::tls::seeds::seed_client_attacker_full;

    #[test_log::test]
    fn test_boringssl_no_randomness_full() {
        let runner = default_runner_for(tls_registry().default().name());

        let trace = seed_client_attacker_full.build_trace();
        let ctx1 = runner.execute(&trace);
        let ctx2 = runner.execute(&trace);

        assert_eq!(ctx1, ctx2);
    }
}
