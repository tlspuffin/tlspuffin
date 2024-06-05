extern "C" {
    fn put_rng_init();
    fn put_rng_reseed(buffer: *const u8, length: libc::size_t);
}

pub fn rng_init() {
    log::debug!("setting OpenSSL in deterministic mode");
    unsafe {
        put_rng_init();
    }
}

pub fn rng_reseed_with(buffer: &[u8]) {
    unsafe {
        put_rng_reseed(buffer.as_ptr(), buffer.len());
    }
}

pub fn rng_reseed() {
    const DEFAULT_SEED: [u8; 8] = 42u64.to_le().to_ne_bytes();
    rng_reseed_with(&DEFAULT_SEED);
}
