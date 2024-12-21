#[cfg(test)]
mod tests {
    #[test_log::test]
    fn test_openssl_rng_reseed_with_default_seed_has_not_changed() {
        crate::rust_put::rand::rng_init();
        crate::rust_put::rand::rng_reseed();

        let mut bytes = [0; 2];
        openssl::rand::rand_bytes(&mut bytes).unwrap();
        assert_eq!(bytes, [183, 96]);
    }

    #[test_log::test]
    fn test_openssl_rng_reseed_with_same_seed_are_identical() {
        const SEED: [u8; 8] = 789u64.to_le().to_ne_bytes();

        crate::rust_put::rand::rng_init();

        let mut reseed1 = [0; 2];
        crate::rust_put::rand::rng_reseed_with(&SEED);
        openssl::rand::rand_bytes(&mut reseed1).unwrap();

        let mut reseed2 = [0; 2];
        crate::rust_put::rand::rng_reseed_with(&SEED);
        openssl::rand::rand_bytes(&mut reseed2).unwrap();

        assert_eq!(reseed1, reseed2);
    }

    #[test_log::test]
    fn test_openssl_rng_reseed_with_different_seeds_are_different() {
        const SEED1: [u8; 8] = 123u64.to_le().to_ne_bytes();
        const SEED2: [u8; 8] = 321u64.to_le().to_ne_bytes();

        crate::rust_put::rand::rng_init();

        crate::rust_put::rand::rng_reseed_with(&SEED1);
        let mut bytes_seed1 = [0; 2];
        openssl::rand::rand_bytes(&mut bytes_seed1).unwrap();

        crate::rust_put::rand::rng_reseed_with(&SEED2);
        let mut bytes_seed2 = [0; 2];
        openssl::rand::rand_bytes(&mut bytes_seed2).unwrap();

        assert_ne!(bytes_seed1, bytes_seed2);
    }
}
