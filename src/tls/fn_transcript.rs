use crate::trace::VecClaimer;
use security_claims::{ClaimType, Claim};
use rustls::hash_hs::HandshakeHash;
use crate::agent::AgentName;
use crate::tls::error::FnError;

fn into_transcript(claim: Option<&(AgentName, Claim)>, typ: ClaimType) -> Result<HandshakeHash, FnError> {
    if let Some((_, claim)) = claim {
        return Ok(HandshakeHash::new_override(Vec::from(&claim.transcript.data[..claim.transcript.length as usize])))
    }

    Err(FnError::Unknown(format!("Failed to find {:?} transcript", typ)))
}

fn find_transcript(claims: &VecClaimer, typ: ClaimType)  -> Result<HandshakeHash, FnError> {
    let claim = claims.find_last_claim(typ);
    into_transcript(claim, typ)
}

fn find_transcript_previous_handshake(claims: &VecClaimer, typ: ClaimType)  -> Result<HandshakeHash, FnError> {
    let claim = claims.find_first_claim(typ);
    into_transcript(claim, typ)
}

pub fn fn_server_hello_transcript_previous_handshake(claims: &VecClaimer) -> Result<HandshakeHash, FnError> {
    find_transcript_previous_handshake(claims, ClaimType::CLAIM_TRANSCRIPT_CH_SH)
}

pub fn fn_server_hello_transcript(claims: &VecClaimer) -> Result<HandshakeHash, FnError> {
    find_transcript(claims, ClaimType::CLAIM_TRANSCRIPT_CH_SH)
}

pub fn fn_server_finished_transcript_previous_handshake(claims: &VecClaimer) -> Result<HandshakeHash, FnError> {
    find_transcript_previous_handshake(claims, ClaimType::CLAIM_TRANSCRIPT_CH_SERVER_FIN)
}

pub fn fn_server_finished_transcript(claims: &VecClaimer) -> Result<HandshakeHash, FnError> {
    find_transcript(claims, ClaimType::CLAIM_TRANSCRIPT_CH_SERVER_FIN)
}
pub fn fn_client_finished_transcript(claims: &VecClaimer) -> Result<HandshakeHash, FnError> {
    find_transcript(claims, ClaimType::CLAIM_TRANSCRIPT_CH_CLIENT_FIN)
}
