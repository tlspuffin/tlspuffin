#![allow(clippy::ptr_arg)]
#![allow(dead_code)]

use rustls::{hash_hs::HandshakeHash, tls13};

use crate::{
    agent::AgentName,
    claims::{
        ByAgentClaimList, Claim, ClientHelloClientFinished, ClientHelloServerFinished,
        ClientHelloServerHello, SizedClaim,
    },
    tls::error::FnError,
};

fn into_transcript(
    claim: Option<&SizedClaim>,
    name: &'static str,
) -> Result<HandshakeHash, FnError> {
    if let Some(claim) = claim {
        let algorithm = tls13::TLS13_AES_128_GCM_SHA256.hash_algorithm();

        let transcript = match claim {
            SizedClaim::ClientHelloClientHello(claim) => Some(&claim.data.0),
            SizedClaim::PartialClientHelloPartialClientHello(claim) => Some(&claim.data.0),
            SizedClaim::ClientHelloServerHello(claim) => Some(&claim.data.0),
            SizedClaim::ClientHelloServerFinished(claim) => Some(&claim.data.0),
            SizedClaim::ClientHelloClientFinished(claim) => Some(&claim.data.0),
            _ => None,
        }
        .unwrap();
        let claim_transcript = &transcript.0[..transcript.1 as usize];
        let hash = HandshakeHash::new_override(Vec::from(claim_transcript), algorithm);
        return Ok(hash);
    }

    Err(FnError::Unknown(format!(
        "Failed to find {:?} transcript",
        name
    )))
}

pub fn fn_server_hello_transcript(claims: &ByAgentClaimList) -> Result<HandshakeHash, FnError> {
    into_transcript(
        claims.find_last_claim::<Claim<ClientHelloServerHello>>(),
        "fn_server_hello_transcript",
    )
}

pub fn fn_server_finished_transcript(claims: &ByAgentClaimList) -> Result<HandshakeHash, FnError> {
    into_transcript(
        claims.find_last_claim::<Claim<ClientHelloServerFinished>>(),
        "fn_server_finished_transcript",
    )
}

pub fn fn_client_finished_transcript(claims: &ByAgentClaimList) -> Result<HandshakeHash, FnError> {
    into_transcript(
        claims.find_last_claim::<Claim<ClientHelloClientFinished>>(),
        "fn_client_finished_transcript",
    )
}
