use log::debug;

#[cfg(feature = "deterministic")]
extern "C" {
    fn deterministic_rng_set();
    fn deterministic_rng_reseed(buffer: *const u8, length: libc::size_t);
}

#[cfg(feature = "deterministic")]
pub fn set_openssl_deterministic() {
    const SEED: [u8; 8] = 42u64.to_le().to_ne_bytes();

    debug!("setting OpenSSL in deterministic mode");
    unsafe {
        deterministic_rng_set();
        deterministic_rng_reseed(SEED.as_ptr(), SEED.len());
    }
}

#[cfg(test)]
mod tests {
    use openssl::rand::rand_bytes;

    #[test]
    #[cfg(feature = "openssl111-binding")]
    fn test_openssl_no_randomness() {
        use crate::openssl::deterministic::set_openssl_deterministic;

        for _ in 0..3 {
            set_openssl_deterministic();
            let mut buf1 = [0; 2];
            rand_bytes(&mut buf1).unwrap();
            assert_eq!(buf1, [183, 96]);
        }
    }
}
