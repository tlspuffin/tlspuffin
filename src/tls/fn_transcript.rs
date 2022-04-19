use crate::agent::AgentName;
use crate::tls::error::FnError;
use crate::trace::{AgentClaimer};
use rustls::hash_hs::HandshakeHash;
use security_claims::{Claim, ClaimType};

fn into_transcript(
    claim: Option<&(AgentName, Claim)>,
    typ: ClaimType,
) -> Result<HandshakeHash, FnError> {
    if let Some((_, claim)) = claim {
        return Ok(HandshakeHash::new_override(Vec::from(
            &claim.transcript.data[..claim.transcript.length as usize],
        )));
    }

    Err(FnError::Unknown(format!(
        "Failed to find {:?} transcript",
        typ
    )))
}

fn find_transcript(claims: &AgentClaimer, typ: ClaimType) -> Result<HandshakeHash, FnError> {
    let claim = claims.find_last_claim(typ);
    into_transcript(claim, typ)
}

pub fn fn_server_hello_transcript(claims: &AgentClaimer) -> Result<HandshakeHash, FnError> {
    find_transcript(claims, ClaimType::CLAIM_TRANSCRIPT_CH_SH)
}

pub fn fn_server_finished_transcript(claims: &AgentClaimer) -> Result<HandshakeHash, FnError> {
    find_transcript(claims, ClaimType::CLAIM_TRANSCRIPT_CH_SERVER_FIN)
}
pub fn fn_client_finished_transcript(claims: &AgentClaimer) -> Result<HandshakeHash, FnError> {
    find_transcript(claims, ClaimType::CLAIM_TRANSCRIPT_CH_CLIENT_FIN)
}
