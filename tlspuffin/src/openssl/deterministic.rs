use std::os::raw::c_int;

use log::warn;

#[cfg(feature = "deterministic")]
extern "C" {
    fn make_openssl_deterministic();
    fn RAND_seed(buf: *mut u8, num: c_int);
}

#[cfg(feature = "deterministic")]
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
    use std::fmt::format;
    use openssl::rand::rand_bytes;
    use crate::tls::seeds::{create_corpus, seed_client_attacker_full};
    use puffin::trace::{Action, InputAction, OutputAction, Step, Trace, TraceContext};
    use crate::put_registry::TLS_PUT_REGISTRY;
    use puffin::put::PutOptions;
    use crate::tls::{
        trace_helper::TraceHelper,
    };
    #[test]
    #[cfg(feature = "openssl111-binding")]
    fn test_openssl_no_randomness_simple() {
        use crate::openssl::deterministic::set_openssl_deterministic;
        set_openssl_deterministic();
        let mut buf1 = [0; 2];
        rand_bytes(&mut buf1).unwrap();
        assert_eq!(buf1, [70, 100]);
    }

    #[test]
    fn test_openssl_no_randomness_full() {
        use crate::openssl::deterministic::set_openssl_deterministic;
        set_openssl_deterministic();

        let trace = seed_client_attacker_full.build_trace();
        let mut ctx1 = TraceContext::new(&TLS_PUT_REGISTRY, PutOptions::default());
        ctx1.set_deterministic(true);
        trace.execute(&mut ctx1);
        let mut ctx2 = TraceContext::new(&TLS_PUT_REGISTRY, PutOptions::default());
        ctx2.set_deterministic(true);
        trace.execute(&mut ctx2);

        println!("Left: {:#?}\n", ctx1);
        println!("Right: {:#?}\n", ctx2);
        assert_eq!(ctx1, ctx2);
    }
}
