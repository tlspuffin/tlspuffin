#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]


use std::fmt;
use std::ffi::c_void;

pub type TLSLike = *const c_void;

pub const CLAIM_INTERFACE_H: &'static str =
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/claim-interface.h"));

include!(concat!(env!("OUT_DIR"), "/claim-interface.rs"));

impl fmt::Display for Claim {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{{ (debug) \
                state: {:?}, \
                cert_rsa_key_length: {}, \
                available_ciphers: {}, \
                chosen_cipher: {}, \
                cipher_bits: {}, \
                master_secret: {}, \
                peer_tmp_security_bits: {}, \
            }}",
            self.typ,
            self.cert_rsa_key_length,
            self.available_ciphers.iter().map(|c| hex::encode(c.to_be_bytes())).collect::<Vec<String>>().join(", "),
            hex::encode(self.chosen_cipher.to_be_bytes()),
            self.cipher_bits,
            hex::encode(self.master_secret),
            self.peer_tmp_security_bits,
        )
    }
}