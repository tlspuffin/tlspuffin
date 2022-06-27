use foreign_types::ForeignTypeRef;
use security_claims::register::Claimer;
use wolfssl_sys as wolf;

use crate::{agent::AgentName, trace::ClaimList, wolfssl::ssl::SslRef};

pub fn claim_transcript(ssl: &mut SslRef, agent_name: AgentName, claims: &mut ClaimList) {
    unsafe {
        let ssl = ssl.as_ptr();
        let hashes = (*ssl).hsHashes;

        if hashes.is_null() {
            return;
        }

        let mut sha256 = (*hashes).hashSha256;

        let mut hash: [u8; 32] = [0; 32];
        wolf::wc_Sha256GetHash(&mut sha256 as *mut wolf::wc_Sha256, hash.as_mut_ptr());

        let mut target: [u8; 64] = [0; 64];
        target[..32].clone_from_slice(&hash);

        let state = unsafe { (*ssl).options.acceptState };

        // WARNING: The following names have been taken from wolfssl/internal.h. They can become out of date.
        match state as u32 {
            wolf::AcceptStateTls13_TLS13_ACCEPT_SECOND_REPLY_DONE => Some(security_claims::Claim {
                typ: security_claims::ClaimType::CLAIM_TRANSCRIPT_CH_SH,
                transcript: security_claims::ClaimTranscript {
                    length: 32,
                    data: target,
                },
                ..security_claims::Claim::default()
            }),
            wolf::AcceptStateTls13_TLS13_CERT_VERIFY_SENT => Some(security_claims::Claim {
                typ: security_claims::ClaimType::CLAIM_TRANSCRIPT_CH_SERVER_FIN,
                transcript: security_claims::ClaimTranscript {
                    length: 32,
                    data: target,
                },
                ..security_claims::Claim::default()
            }),
            wolf::AcceptStateTls13_TLS13_TICKET_SENT => Some(security_claims::Claim {
                typ: security_claims::ClaimType::CLAIM_TRANSCRIPT_CH_CLIENT_FIN,
                transcript: security_claims::ClaimTranscript {
                    length: 32,
                    data: target,
                },
                ..security_claims::Claim::default()
            }),
            _ => None,
        }
        .and_then(|claim| Some(claims.claim(agent_name, claim)));
    }
}
