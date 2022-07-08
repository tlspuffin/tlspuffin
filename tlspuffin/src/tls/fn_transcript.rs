#![allow(clippy::ptr_arg)]
#![allow(dead_code)]

use rustls::{hash_hs::HandshakeHash, tls13};

use crate::{
    agent::AgentName,
    claims::{
        Claim, ClaimData, ClaimDataTranscript, Transcript, TranscriptCertificate,
        TranscriptClientFinished, TranscriptServerFinished, TranscriptServerHello,
    },
    tls::error::FnError,
};

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

pub fn _fn_transcript<T: Transcript>(claim: &T) -> Result<HandshakeHash, FnError> {
    let algorithm = tls13::TLS13_AES_128_GCM_SHA256.hash_algorithm();

    let hash = HandshakeHash::new_override(Vec::from(claim.as_slice()), algorithm);
    Ok(hash)
}
