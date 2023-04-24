#![allow(dead_code)]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]
#![allow(clippy)]

use std::{ffi::c_void, fmt, fmt::Formatter};

pub type TLSLike = *const c_void;

pub const CLAIM_INTERFACE_H: &str =
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/claim-interface.h"));

include!(concat!(env!("OUT_DIR"), "/claim-interface.rs"));

impl fmt::Display for Claim {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "\
            typ: {},\
            write: {},\
            version: {},\
            server: {},\
            session_id: {},\
            server_random: {},\
            client_random: {},\
            cert: {},\
            peer_cert: {},\
            peer_tmp_skey_type: {},\
            peer_tmp_skey_security_bits: {},\
            tmp_skey_type: {},\
            tmp_skey_group_id: {},\
            signature_algorithm: {},\
            peer_signature_algorithm: {},\
            early_secret: {},\
            handshake_secret: {},\
            master_secret: {},\
            resumption_master_secret: {},\
            client_finished_secret: {},\
            server_finished_secret: {},\
            server_finished_hash: {},\
            handshake_traffic_hash: {},\
            client_app_traffic_secret: {},\
            server_app_traffic_secret: {},\
            exporter_master_secret: {},\
            early_exporter_master_secret: {},\
            master_secret_12: {},\
            available_ciphers: {},\
            chosen_cipher: {},\
            transcript: {},\
            ",
            self.typ,
            self.write,
            self.version,
            self.server,
            self.session_id,
            self.server_random,
            self.client_random,
            self.cert,
            self.peer_cert,
            self.peer_tmp_skey_type,
            self.peer_tmp_skey_security_bits,
            self.tmp_skey_type,
            self.tmp_skey_group_id,
            self.signature_algorithm,
            self.peer_signature_algorithm,
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
            self.master_secret_12,
            self.available_ciphers,
            self.chosen_cipher,
            self.transcript,
        )
    }
}

impl fmt::Display for ClaimVersion {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.data)
    }
}

impl fmt::Display for ClaimTranscript {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.data))
    }
}

impl fmt::Display for ClaimCipher {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.data.to_be_bytes()))
    }
}

impl fmt::Display for ClaimSessionId {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.data[0..self.length as usize]),)
    }
}

impl fmt::Display for ClaimRandom {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.data))
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

impl fmt::Display for ClaimType {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl fmt::Display for ClaimKeyType {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl fmt::Display for ClaimSecret {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let secret = self.secret;
        // print if any byte is set
        if secret.iter().any(|v| *v != 0) {
            write!(f, "{}", hex::encode(secret))?;
        }

        Ok(())
    }
}
