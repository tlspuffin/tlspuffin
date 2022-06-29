use foreign_types::ForeignTypeRef;
use wolfssl_sys as wolf;

use crate::{
    agent::{AgentName, AgentType, TLSVersion},
    claims::{
        Claim, ClaimList, ClientHelloClientFinished, ClientHelloServerFinished,
        ClientHelloServerHello, SizedClaim, TlsTranscript,
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

        // WARNING: The following names have been taken from wolfssl/internal.h. They can become out of date.
        match state as u32 {
            wolf::AcceptStateTls13_TLS13_ACCEPT_SECOND_REPLY_DONE => {
                claims.claim_sized(SizedClaim::ClientHelloServerHello(Claim {
                    agent: agent_name,
                    origin: AgentType::Server,
                    outbound: false,
                    protocol_version: TLSVersion::V1_3,
                    data: ClientHelloServerHello(TlsTranscript(target, 32)),
                }))
            }
            wolf::AcceptStateTls13_TLS13_CERT_VERIFY_SENT => {
                claims.claim_sized(SizedClaim::ClientHelloServerFinished(Claim {
                    agent: agent_name,
                    origin: AgentType::Server,
                    outbound: false,
                    protocol_version: TLSVersion::V1_3,
                    data: ClientHelloServerFinished(TlsTranscript(target, 32)),
                }))
            }
            wolf::AcceptStateTls13_TLS13_TICKET_SENT => {
                claims.claim_sized(SizedClaim::ClientHelloClientFinished(Claim {
                    agent: agent_name,
                    origin: AgentType::Server,
                    outbound: false,
                    protocol_version: TLSVersion::V1_3,
                    data: ClientHelloClientFinished(TlsTranscript(target, 32)),
                }))
            }
            _ => {}
        };
    }
}
