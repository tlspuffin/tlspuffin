#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use std::ffi::c_void;
use std::fmt;
use std::fmt::Formatter;

include!(concat!(env!("OUT_DIR"), "/claim-interface.rs"));

pub const CLAIM_INTERFACE_H: &'static str =
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/claim-interface.h"));

impl fmt::Display for Claim {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{{ cert_rsa_key_length: {}, state: {}, master_secret: {} }}",
            self.cert_rsa_key_length, self.state, hex::encode(self.master_secret)
        )
    }
}

pub fn current_claim_safe(ssl_like_ptr: *const c_void) -> Claim {
    unsafe { current_claim(ssl_like_ptr) }
}
