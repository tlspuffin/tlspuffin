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
        write!(
            f,
            "{{ (debug) \
                state: {:?}, \
                write: {}, \

                cert: {}, \
                peer_cert: {}, \

                peer_tmp_type: {:?}, \
                peer_tmp_security_bits: {}, \

                chosen_cipher: {}, \
                available_ciphers: {}, \

                master_secret: {}, \
                early_secret: {}, \
                handshake_secret: {}, \
                master_secret: {}, \
                resumption_master_secret: {}, \
                client_finished_secret: {}, \
                server_finished_secret: {}, \
                server_finished_hash: {}, \
                handshake_traffic_hash: {}, \
                client_app_traffic_secret: {}, \
                server_app_traffic_secret: {}, \
                exporter_master_secret: {}, \
                early_exporter_master_secret: {}, \
            }}",
            self.typ,
            self.write,
            self.cert,
            self.peer_cert,
            self.peer_tmp_type,
            self.peer_tmp_security_bits,
            hex::encode(self.chosen_cipher.to_be_bytes()),
            self.available_ciphers,
            self.master_secret,
            self.early_secret,
            self.handshake_secret,
            self.master_secret,
            self.resumption_master_secret,
            self.client_finished_secret,
            self.server_finished_secret,
            self.server_finished_hash,
            self.handshake_traffic_hash,
            self.client_app_traffic_secret,
            self.server_app_traffic_secret,
            self.exporter_master_secret,
            self.early_exporter_master_secret,
        )
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
            self.ciphers[0..self.len as usize]
                .iter()
                .map(|c| hex::encode(c.to_be_bytes()))
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
