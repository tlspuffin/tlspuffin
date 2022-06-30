use foreign_types::ForeignTypeRef;
use wolfssl_sys as wolf;

use crate::{
    agent::{AgentName, AgentType, TLSVersion},
    claims::{
        Claim, ClaimData, ClaimDataTranscript, ClaimList, TlsTranscript, TranscriptClientFinished,
        TranscriptServerFinished, TranscriptServerHello,
    },
    wolfssl::ssl::SslRef,
};

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

        let origin = AgentType::Server;
        let outbound = false;
        let protocol_version = TLSVersion::V1_3;

        // WARNING: The following names have been taken from wolfssl/internal.h. They can become out of date.
        let claim_data = match state as u32 {
            wolf::AcceptStateTls13_TLS13_ACCEPT_SECOND_REPLY_DONE => Some(ClaimData::Transcript(
                ClaimDataTranscript::ServerHello(TranscriptServerHello(TlsTranscript(target, 32))),
            )),
            wolf::AcceptStateTls13_TLS13_CERT_VERIFY_SENT => {
                Some(ClaimData::Transcript(ClaimDataTranscript::ServerFinished(
                    TranscriptServerFinished(TlsTranscript(target, 32)),
                )))
            }
            wolf::AcceptStateTls13_TLS13_TICKET_SENT => {
                Some(ClaimData::Transcript(ClaimDataTranscript::ClientFinished(
                    TranscriptClientFinished(TlsTranscript(target, 32)),
                )))
            }
            _ => None,
        };

        claim_data.map(|data| {
            claims.claim_sized(Claim {
                agent_name,
                origin,
                outbound,
                protocol_version,
                data,
            })
        });
    }
}
