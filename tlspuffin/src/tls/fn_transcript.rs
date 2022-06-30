#![allow(clippy::ptr_arg)]
#![allow(dead_code)]

use rustls::{hash_hs::HandshakeHash, tls13};

use crate::{
    agent::AgentName,
    claims::{
        Claim, ClaimData, ClaimDataTranscript, Transcript, TranscriptClientFinished,
        TranscriptServerFinished, TranscriptServerHello,
    },
    tls::error::FnError,
};

pub fn fn_server_hello_transcript(claim: &TranscriptServerHello) -> Result<HandshakeHash, FnError> {
    let algorithm = tls13::TLS13_AES_128_GCM_SHA256.hash_algorithm();

    let transcript = &claim.0;
    let claim_transcript = &transcript.0[..transcript.1 as usize];
    let hash = HandshakeHash::new_override(Vec::from(claim_transcript), algorithm);
    Ok(hash)
}
/*
pub fn fn_server_finished_transcript(
    claim: &TranscriptServerFinished,
) -> Result<HandshakeHash, FnError> {
    let algorithm = tls13::TLS13_AES_128_GCM_SHA256.hash_algorithm();

    let transcript = &claim.0;
    let claim_transcript = &transcript.0[..transcript.1 as usize];
    let hash = HandshakeHash::new_override(Vec::from(claim_transcript), algorithm);
    Ok(hash)
}
*/
pub fn fn_client_finished_transcript(
    claim: &TranscriptClientFinished,
) -> Result<HandshakeHash, FnError> {
    let algorithm = tls13::TLS13_AES_128_GCM_SHA256.hash_algorithm();

    let transcript = &claim.0;
    let claim_transcript = &transcript.0[..transcript.1 as usize];
    let hash = HandshakeHash::new_override(Vec::from(claim_transcript), algorithm);
    Ok(hash)
}

pub const fn_server_finished_transcript: fn(
    &TranscriptServerFinished,
) -> Result<HandshakeHash, FnError> = fn_transcript::<TranscriptServerFinished>;

pub fn fn_transcript<T: Transcript>(claim: &T) -> Result<HandshakeHash, FnError> {
    let algorithm = tls13::TLS13_AES_128_GCM_SHA256.hash_algorithm();

    let hash = HandshakeHash::new_override(Vec::from(claim.as_slice()), algorithm);
    Ok(hash)
}
