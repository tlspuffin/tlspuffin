use foreign_types::ForeignTypeRef;
use puffin::{
    agent::{AgentName, AgentType, TLSVersion},
    claims::ClaimList,
};
use wolfssl_sys as wolf;

use crate::{
    claims::{
        ClaimData, ClaimDataTranscript, TlsClaim, TlsTranscript, TranscriptCertificate,
        TranscriptClientFinished, TranscriptServerFinished, TranscriptServerHello,
    },
    wolfssl::SslRef,
};

pub fn extract_current_transcript(ssl: &SslRef) -> Option<TlsTranscript> {
    unsafe {
        let ssl = ssl.as_ptr();
        let hashes = (*ssl).hsHashes;

        if hashes.is_null() {
            return None;
        }

        let mut sha256 = (*hashes).hashSha256;

        let mut hash: [u8; 32] = [0; 32];
        wolf::wc_Sha256GetHash(&mut sha256 as *mut wolf::wc_Sha256, hash.as_mut_ptr());

        let mut target: [u8; 64] = [0; 64];
        target[..32].clone_from_slice(&hash);

        Some(TlsTranscript(target, 32))
    }
}
