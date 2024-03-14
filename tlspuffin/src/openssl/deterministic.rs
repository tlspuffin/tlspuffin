use std::os::raw::c_int;

use log::{trace, warn};

#[cfg(feature = "deterministic")]
extern "C" {
    fn make_openssl_deterministic();
    fn RAND_seed(buf: *mut u8, num: c_int);
    pub static mut tlspuffin_seed: u32;
}

pub fn get_seed() -> u32 {
    unsafe { return tlspuffin_seed }
}
#[cfg(feature = "deterministic")]
pub fn determinism_set_reseed_openssl() {
    trace!("Making OpenSSL fully deterministic: reset rand and reseed to a constant...");
    unsafe {
        make_openssl_deterministic();
    }
    determinism_reseed_openssl();
}

#[cfg(feature = "deterministic")]
pub fn determinism_reseed_openssl() {
    trace!(" - Reseed RAND for OpenSSL");
    unsafe {
        let mut seed: [u8; 4] = 42u32.to_le().to_ne_bytes();
        let buf = seed.as_mut_ptr();
        RAND_seed(buf, 4);
        tlspuffin_seed = 42 as u32;
    }
}

#[cfg(test)]
mod tests {
    use openssl::rand::rand_bytes;

    use crate::openssl::deterministic::{determinism_set_reseed_openssl, get_seed};

    #[test]
    #[cfg(feature = "openssl111-binding")]
    #[test]
    #[cfg(feature = "openssl111-binding")]
    fn test_openssl_no_randomness_simple() {
        assert_eq!(get_seed(), 42);
        determinism_set_reseed_openssl();
        assert_eq!(get_seed(), 42);
        let mut buf1 = [0; 2];
        rand_bytes(&mut buf1).unwrap();
        assert_eq!(buf1, [179, 16]);
        assert_ne!(get_seed(), 42);
        determinism_set_reseed_openssl();
        assert_eq!(get_seed(), 42);
    }
}
