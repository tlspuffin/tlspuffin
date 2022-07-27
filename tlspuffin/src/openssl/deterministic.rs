use std::os::raw::c_int;

use log::warn;

#[cfg(feature = "openssl111")]
extern "C" {
    fn make_openssl_deterministic();
    fn RAND_seed(buf: *mut u8, num: c_int);
}

#[cfg(feature = "openssl111")]
pub fn set_openssl_deterministic() {
    warn!("OpenSSL is no longer random!");
    unsafe {
        make_openssl_deterministic();
        let mut seed: [u8; 4] = 42u32.to_le().to_ne_bytes();
        let buf = seed.as_mut_ptr();
        RAND_seed(buf, 4);
    }
}

#[cfg(test)]
mod tests {
    use openssl::rand::rand_bytes;

    use crate::openssl::deterministic::set_openssl_deterministic;

    #[test]
    #[cfg(feature = "openssl111")]
    fn test_openssl_no_randomness() {
        set_openssl_deterministic();
        let mut buf1 = [0; 2];
        rand_bytes(&mut buf1).unwrap();
        assert_eq!(buf1, [70, 100]);
    }
}
