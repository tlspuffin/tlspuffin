#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use std::ffi::c_void;
use std::fmt;
use std::fmt::Formatter;

pub type TLSLike = *const c_void;

pub const CLAIM_INTERFACE_H: &'static str =
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/claim-interface.h"));

include!(concat!(env!("OUT_DIR"), "/claim-interface.rs"));

impl fmt::Display for Claim {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", &self)
    }
}

impl fmt::Display for ClaimVersion {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.data.to_be_bytes()))
    }
}

impl fmt::Display for ClaimTranscript {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.data))
    }
}

impl fmt::Display for ClaimCipher {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.data.to_be_bytes()),)
    }
}

impl fmt::Display for ClaimCertData {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:?}({}b)",
            self.key_type,
            if self.key_length == 0 {
                "?".to_string()
            } else {
                self.key_length.to_string()
            }
        )
    }
}

impl fmt::Display for ClaimCiphers {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            self.ciphers[0..self.length as usize]
                .iter()
                .map(|c| hex::encode(c.data.to_be_bytes()))
                .collect::<Vec<String>>()
                .join(", ")
        )
    }
}

impl fmt::Display for ClaimSecret {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let secret = self.secret;
        // print if any byte is set
        if secret.iter().find(|v| **v != 0).is_some() {
            write!(f, "{}", hex::encode(&secret))?;
        }

        Ok(())
    }
}

impl Eq for ClaimSecret {
}