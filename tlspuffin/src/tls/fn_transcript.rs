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

/// This function is meant to be used in post-execution decryption recipes but not by the attacker
pub fn fn_finished_get_cipher(claim: &Finished) -> Result<CipherSuite, FnError> {
    Ok(CipherSuite::from(claim.chosen_cipher))
}

/// This function is meant to be used in post-execution decryption recipes but not by the attacker
pub fn fn_finished_get_handshake_secret(claim: &Finished) -> Result<Vec<u8>, FnError> {
    let secret = Vec::from(claim.handshake_secret.as_slice());

    Ok(secret)
}

/// This function is meant to be used in post-execution decryption recipes but not by the attacker
pub fn fn_finished_get_client_random(claim: &Finished) -> Result<Random, FnError> {
    let payload: [u8; 32] = claim.client_random[0..32].try_into().unwrap();
    Ok(Random(payload))
}
