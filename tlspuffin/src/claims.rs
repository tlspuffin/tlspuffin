use std::{any::Any, fmt::Debug};

use puffin::{
    agent::{AgentName, AgentType, TLSVersion},
    algebra::dynamic_function::TypeShape,
    claims::Claim,
    variable_data::VariableData,
};
use smallvec::SmallVec;

#[derive(Debug, Clone)]
pub struct TlsTranscript(pub [u8; 64], pub i32);

#[derive(Debug, Clone)]
pub struct TranscriptClientHello(pub TlsTranscript);
impl Transcript for TranscriptClientHello {
    fn as_slice(&self) -> &[u8] {
        let transcript = &self.0;
        &transcript.0[..transcript.1 as usize]
    }
}
#[derive(Debug, Clone)]
pub struct TranscriptPartialClientHello(pub TlsTranscript);
impl Transcript for TranscriptPartialClientHello {
    fn as_slice(&self) -> &[u8] {
        let transcript = &self.0;
        &transcript.0[..transcript.1 as usize]
    }
}
#[derive(Debug, Clone)]
pub struct TranscriptServerHello(pub TlsTranscript);
impl Transcript for TranscriptServerHello {
    fn as_slice(&self) -> &[u8] {
        let transcript = &self.0;
        &transcript.0[..transcript.1 as usize]
    }
}
#[derive(Debug, Clone)]
pub struct TranscriptServerFinished(pub TlsTranscript);
impl Transcript for TranscriptServerFinished {
    fn as_slice(&self) -> &[u8] {
        let transcript = &self.0;
        &transcript.0[..transcript.1 as usize]
    }
}
#[derive(Debug, Clone)]
pub struct TranscriptClientFinished(pub TlsTranscript);
impl Transcript for TranscriptClientFinished {
    fn as_slice(&self) -> &[u8] {
        let transcript = &self.0;
        &transcript.0[..transcript.1 as usize]
    }
}
#[derive(Debug, Clone)]
pub struct TranscriptCertificate(pub TlsTranscript);
impl Transcript for TranscriptCertificate {
    fn as_slice(&self) -> &[u8] {
        let transcript = &self.0;
        &transcript.0[..transcript.1 as usize]
    }
}

pub trait Transcript {
    fn as_slice(&self) -> &[u8];
}

#[derive(Debug, Clone)]
pub struct ClientHello;
#[derive(Debug, Clone)]
pub struct ServerHello;
#[derive(Debug, Clone)]
pub struct Certificate;
#[derive(Debug, Clone)]
pub struct CertificateVerify;
#[derive(Debug, Clone)]
pub struct Finished {
    pub outbound: bool,

    pub client_random: SmallVec<[u8; 32]>,
    pub server_random: SmallVec<[u8; 32]>,
    pub session_id: SmallVec<[u8; 32]>,

    pub authenticate_peer: bool,
    /// DER encoded certificate. DER works, because:
    ///     DER is a subset of BER providing for exactly one way to encode an ASN.1 value.
    ///     (https://en.wikipedia.org/wiki/X.690#DER_encoding)
    pub peer_certificate: SmallVec<[u8; 32]>,

    pub master_secret: SmallVec<[u8; 32]>,

    pub chosen_cipher: u16,
    pub available_ciphers: SmallVec<[u16; 20]>,

    pub signature_algorithm: i32,
    pub peer_signature_algorithm: i32,
    /* TODO: tmp_skey_type peer_tmp_skey_type
                   // TLS 1.2
                   if let Some(server_kex) = claims.iter().find(|(_agent, claim)| {
                       claim.write == 1
                           && claim.server == 1
                           && claim.typ == ClaimType::CLAIM_SERVER_DONE
                   }) {
                       if server_kex.1.tmp_skey_type != client.peer_tmp_skey_type {
                           return Some("Mismatching ephemeral kex method");
                       }
                   } else {
                       return Some("Server Done not found in server claims");
                   }
                   // TLS 1.3
                   if client.tmp_skey_type != server.tmp_skey_type {
                       return Some("Mismatching ephemeral kex method");
                   }
    */
    /* TODO: tmp_skey_group_id
                   // TLS 1.3
                    if client.tmp_skey_group_id != server.tmp_skey_group_id {
                        return Some("Mismatching groups");
                    }
    */
}

#[derive(Debug, Clone)]
pub enum ClaimDataTranscript {
    ClientHello(TranscriptClientHello),
    PartialClientHello(TranscriptPartialClientHello),
    ServerHello(TranscriptServerHello),
    Certificate(TranscriptCertificate),
    ServerFinished(TranscriptServerFinished),
    ClientFinished(TranscriptClientFinished),
}

#[derive(Debug, Clone)]
pub enum ClaimDataMessage {
    ClientHello(ClientHello),
    ServerHello(ServerHello),
    Certificate(Certificate),
    CertificateVerify(CertificateVerify),
    Finished(Finished),
}

#[derive(Debug, Clone)]
pub enum ClaimData {
    Transcript(ClaimDataTranscript),
    Message(ClaimDataMessage),
}

#[derive(Debug, Clone)]
pub struct TlsClaim {
    pub agent_name: AgentName,
    pub origin: AgentType,
    pub protocol_version: TLSVersion,
    pub data: ClaimData,
}

impl Claim for TlsClaim {
    fn agent_name(&self) -> AgentName {
        self.agent_name
    }

    fn id(&self) -> TypeShape {
        type Message = ClaimDataMessage;
        type Transcript = ClaimDataTranscript;
        type Type = TypeShape;
        match &self.data {
            ClaimData::Message(message) => match message {
                Message::ClientHello(_) => Type::of::<ClientHello>(),
                Message::ServerHello(_) => Type::of::<ServerHello>(),
                Message::Certificate(_) => Type::of::<Certificate>(),
                Message::CertificateVerify(_) => Type::of::<CertificateVerify>(),
                Message::Finished(_) => Type::of::<Finished>(),
            },
            ClaimData::Transcript(transcript) => match transcript {
                Transcript::ClientHello(_) => Type::of::<TranscriptClientHello>(),
                Transcript::PartialClientHello(_) => Type::of::<TranscriptPartialClientHello>(),
                Transcript::ServerHello(_) => Type::of::<TranscriptServerHello>(),
                Transcript::ServerFinished(_) => Type::of::<TranscriptServerFinished>(),
                Transcript::ClientFinished(_) => Type::of::<TranscriptClientFinished>(),
                Transcript::Certificate(_) => Type::of::<TranscriptCertificate>(),
            },
        }
    }

    fn inner(&self) -> Box<dyn Any> {
        type Message = ClaimDataMessage;
        type Transcript = ClaimDataTranscript;
        match &self.data {
            ClaimData::Message(message) => match message {
                Message::ClientHello(claim) => claim.boxed_any(),
                Message::ServerHello(claim) => claim.boxed_any(),
                Message::Certificate(claim) => claim.boxed_any(),
                Message::CertificateVerify(claim) => claim.boxed_any(),
                Message::Finished(claim) => claim.boxed_any(),
            },
            ClaimData::Transcript(transcript) => match transcript {
                Transcript::ClientHello(claim) => claim.boxed_any(),
                Transcript::PartialClientHello(claim) => claim.boxed_any(),
                Transcript::ServerHello(claim) => claim.boxed_any(),
                Transcript::ServerFinished(claim) => claim.boxed_any(),
                Transcript::ClientFinished(claim) => claim.boxed_any(),
                Transcript::Certificate(claim) => claim.boxed_any(),
            },
        }
    }
}
