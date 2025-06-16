#![allow(clippy::ptr_arg)]
#![allow(dead_code)]

use puffin::algebra::error::FnError;

use crate::claims::{
    Finished, Transcript, TranscriptCertificate, TranscriptClientFinished,
    TranscriptServerFinished, TranscriptServerHello,
};
use crate::tls::rustls::hash_hs::HandshakeHash;
use crate::tls::rustls::msgs::enums::CipherSuite;
use crate::tls::rustls::msgs::handshake::Random;
use crate::tls::rustls::tls13;

pub fn fn_server_hello_transcript(claim: &TranscriptServerHello) -> Result<HandshakeHash, FnError> {
    _fn_transcript::<TranscriptServerHello>(claim)
}

pub fn fn_client_finished_transcript(
    claim: &TranscriptClientFinished,
) -> Result<HandshakeHash, FnError> {
    _fn_transcript::<TranscriptClientFinished>(claim)
}

pub fn fn_server_finished_transcript(
    claim: &TranscriptServerFinished,
) -> Result<HandshakeHash, FnError> {
    _fn_transcript::<TranscriptServerFinished>(claim)
}

pub fn fn_certificate_transcript(claim: &TranscriptCertificate) -> Result<HandshakeHash, FnError> {
    _fn_transcript::<TranscriptCertificate>(claim)
}

fn _fn_transcript<T: Transcript>(claim: &T) -> Result<HandshakeHash, FnError> {
    let algorithm = tls13::TLS13_AES_128_GCM_SHA256.hash_algorithm();

    let hash = HandshakeHash::new_override(Vec::from(claim.as_slice()), algorithm);
    Ok(hash)
}

pub fn fn_finished_get_cipher(claim: &Finished) -> Result<CipherSuite, FnError> {
    Ok(CipherSuite::from(claim.chosen_cipher))
}

pub fn fn_finished_get_secret(claim: &Finished) -> Result<Vec<u8>, FnError> {
    let mut secret = Vec::from(claim.master_secret.as_slice());
    secret.resize(48, 0);

    Ok(secret)
}

pub fn fn_finished_get_handshake_secret(claim: &Finished) -> Result<Vec<u8>, FnError> {
    let mut secret = Vec::from(claim.handshake_secret.as_slice());
    secret.resize(48, 0);

    Ok(secret)
}

pub fn fn_finished_get_server_random(claim: &Finished) -> Result<Random, FnError> {
    let mut payload = [0; 32];
    for (idx, v) in claim.server_random.iter().enumerate() {
        payload[idx] = *v;
    }
    Ok(Random(payload))
}

pub fn fn_finished_get_client_random(claim: &Finished) -> Result<Random, FnError> {
    let mut payload = [0; 32];
    for (idx, v) in claim.client_random.iter().enumerate() {
        payload[idx] = *v;
    }
    Ok(Random(payload))
}
