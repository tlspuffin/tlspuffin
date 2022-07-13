use std::os::raw::c_int;
use log::warn;

use wolfssl_sys as wolf;

// WIP
/*
#[cfg(feature = "wolfssl520")]
extern "C" {
    fn make_wolfssl_deterministic();
    fn RAND_seed(buf: *mut u8, num: c_int);
}
*/

pub fn rand_bytes(buf: &mut [u8]) -> () {
    unsafe {
        assert!(buf.len() <= c_int::max_value() as usize);
        wolf::wolfSSL_RAND_bytes(buf.as_mut_ptr(), buf.len() as c_int);
    }
}

#[cfg(feature = "wolfssl520")]
pub fn set_wolfssl_deterministic() {
    warn!("WolfSSL is no longer random!");
     unsafe {
         let methods = wolf::WOLSSL_RAND_METHOD = {
             stdlib_rand_seed,
             stdlib_rand_bytes,
             stdlib_rand_cleanup,
             stdlib_rand_add,
             stdlib_rand_bytes,
             stdlib_rand_status
         };

         wolf::wolfSSL_RAND_set_rand_method(&methods);

         let mut seed: [u8; 4] = 42u32.to_le().to_ne_bytes();
         let buf = seed.as_mut_ptr();
         wolf::wolfSSL_RAND_seed(buf as *mut u8, 4 as c_int);
    }
}
#[cfg(test)]
mod tests {

    #[test]
    fn test_wolfssl_no_randomness() {
        crate::put_registry::PUT_REGISTRY.make_deterministic(); // this affects also other tests, which is fine as we generally prefer deterministic tests
        let mut buf1 = [0; 2];
        rand_bytes(&mut buf1);
        assert_eq!(buf1, [70, 100]);
    }
}
