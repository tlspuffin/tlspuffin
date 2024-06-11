extern "C" {
    fn deterministic_rng_set();
    fn deterministic_rng_reseed(buffer: *const u8, length: libc::size_t);
}

pub fn rng_set() {
    log::debug!("setting OpenSSL in deterministic mode");
    unsafe {
        deterministic_rng_set();
    }
}

pub fn rng_reseed() {
    const DEFAULT_SEED: [u8; 8] = 42u64.to_le().to_ne_bytes();
    rng_reseed_with(&DEFAULT_SEED);
}

pub fn rng_reseed_with(buffer: &[u8]) {
    unsafe {
        deterministic_rng_reseed(buffer.as_ptr(), buffer.len());
    }
}

#[cfg(test)]
mod tests {
    use puffin::trace::TraceContext;
    use test_log::test;

    use crate::{
        put_registry::tls_registry,
        tls::{seeds::seed_client_attacker_full, trace_helper::TraceHelper},
    };

    #[test]
    #[cfg(feature = "deterministic")]
    fn test_openssl_rng_reseed_with_default_seed_has_not_changed() {
        crate::openssl::deterministic::rng_set();
        crate::openssl::deterministic::rng_reseed();

        let mut bytes = [0; 2];
        openssl::rand::rand_bytes(&mut bytes).unwrap();
        assert_eq!(bytes, [183, 96]);
    }

    #[test]
    #[cfg(feature = "deterministic")]
    fn test_openssl_rng_reseed_with_same_seed_are_identical() {
        const SEED: [u8; 8] = 789u64.to_le().to_ne_bytes();

        crate::openssl::deterministic::rng_set();

        let mut reseed1 = [0; 2];
        crate::openssl::deterministic::rng_reseed_with(&SEED);
        openssl::rand::rand_bytes(&mut reseed1).unwrap();

        let mut reseed2 = [0; 2];
        crate::openssl::deterministic::rng_reseed_with(&SEED);
        openssl::rand::rand_bytes(&mut reseed2).unwrap();

        assert_eq!(reseed1, reseed2);
    }

    #[test]
    #[cfg(feature = "deterministic")]
    fn test_openssl_rng_reseed_with_different_seeds_are_different() {
        const SEED1: [u8; 8] = 123u64.to_le().to_ne_bytes();
        const SEED2: [u8; 8] = 321u64.to_le().to_ne_bytes();

        crate::openssl::deterministic::rng_set();

        crate::openssl::deterministic::rng_reseed_with(&SEED1);
        let mut bytes_seed1 = [0; 2];
        openssl::rand::rand_bytes(&mut bytes_seed1).unwrap();

        crate::openssl::deterministic::rng_reseed_with(&SEED2);
        let mut bytes_seed2 = [0; 2];
        openssl::rand::rand_bytes(&mut bytes_seed2).unwrap();

        assert_ne!(bytes_seed1, bytes_seed2);
    }

    #[test]
    fn test_openssl_trace_execution_no_randomness() {
        let trace = seed_client_attacker_full.build_trace();
        let put_registry = tls_registry();

        let mut ctx1 = TraceContext::builder(&put_registry)
            .set_deterministic(true)
            .build();

        let _ = trace.execute(&mut ctx1);

        let mut ctx2 = TraceContext::builder(&put_registry)
            .set_deterministic(true)
            .build();

        let _ = trace.execute(&mut ctx2);

        assert_eq!(ctx1, ctx2);
    }
}
