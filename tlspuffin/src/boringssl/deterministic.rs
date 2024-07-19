#[cfg(feature = "deterministic")]
pub fn rng_reseed() {
    unsafe { boringssl_sys::RAND_reset_for_fuzzing() };
}

#[cfg(not(feature = "deterministic"))]
pub fn rng_reseed() {
    const DEFAULT_SEED: [u8; 8] = 42u64.to_le().to_ne_bytes();
    unsafe { boringssl_sys::RAND_seed(DEFAULT_SEED.as_ptr(), DEFAULT_SEED.len()) };
}
