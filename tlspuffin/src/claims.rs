use std::{
    any,
    any::{Any, TypeId},
    cell::{Ref, RefCell, RefMut},
    fmt::{Debug, Display},
    ops::Deref,
    rc::Rc,
    slice::Iter,
    sync::Arc,
};

use itertools::Itertools;
use log::{debug, trace};
use smallvec::SmallVec;

use crate::{
    agent::{AgentName, AgentType, TLSVersion},
    algebra::dynamic_function::TypeShape,
    variable_data::VariableData,
};

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

    pub verify_peer: bool,
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
pub struct Claim {
    pub agent_name: AgentName,
    pub origin: AgentType,
    pub protocol_version: TLSVersion,
    pub data: ClaimData,
}

impl Claim {
    pub fn id(&self) -> TypeShape {
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

    pub fn clone_boxed_any(&self) -> Box<dyn Any> {
        type Message = ClaimDataMessage;
        type Transcript = ClaimDataTranscript;
        type Type = TypeShape;
        match &self.data {
            ClaimData::Message(message) => match message {
                Message::ClientHello(claim) => claim.as_any(),
                Message::ServerHello(claim) => claim.as_any(),
                Message::Certificate(claim) => claim.as_any(),
                Message::CertificateVerify(claim) => claim.as_any(),
                Message::Finished(claim) => claim.as_any(),
            },
            ClaimData::Transcript(transcript) => match transcript {
                Transcript::ClientHello(claim) => claim.as_any(),
                Transcript::PartialClientHello(claim) => claim.as_any(),
                Transcript::ServerHello(claim) => claim.as_any(),
                Transcript::ServerFinished(claim) => claim.as_any(),
                Transcript::ClientFinished(claim) => claim.as_any(),
                Transcript::Certificate(claim) => claim.as_any(),
            },
        }
    }
}

pub trait AsAny: Any {
    fn as_any(&self) -> Box<dyn any::Any>;
}

impl<T> AsAny for T
where
    T: Any + Clone,
{
    fn as_any(&self) -> Box<dyn Any> {
        Box::new(self.clone())
    }
}

pub struct Policy {
    pub func: fn(claims: &[Claim]) -> Option<&'static str>,
}

pub trait CheckViolation {
    fn check_violation(&self, policy: Policy) -> Option<&'static str>;
}

#[derive(Clone, Debug)]
pub struct ClaimList {
    claims: Vec<Claim>,
}

impl CheckViolation for ClaimList {
    fn check_violation(&self, policy: Policy) -> Option<&'static str> {
        (policy.func)(&self.claims)
    }
}

impl ClaimList {
    pub fn iter(&self) -> Iter<'_, Claim> {
        self.claims.iter()
    }

    /// finds the last claim matching `type`
    pub fn find_last_claim_by_type<T: 'static>(&self, agent_name: AgentName) -> Option<&Claim> {
        self.find_last_claim(agent_name, TypeShape::of::<T>())
    }

    pub fn find_last_claim(&self, agent_name: AgentName, shape: TypeShape) -> Option<&Claim> {
        self.claims
            .iter()
            .rev()
            .find(|claim| claim.id() == shape && claim.agent_name == agent_name)
    }

    pub fn slice(&self) -> &[Claim] {
        &self.claims
    }
}

impl ClaimList {
    pub fn log(&self) {
        debug!(
            "New Claims: {}",
            &self
                .claims
                .iter()
                .map(|claim| format!("{}", claim.type_name()))
                .join(", ")
        );
        for claim in &self.claims {
            trace!("{:?}", claim);
        }
    }
}

impl From<Vec<Claim>> for ClaimList {
    fn from(claims: Vec<Claim>) -> Self {
        Self { claims }
    }
}

impl ClaimList {
    pub fn new() -> Self {
        Self { claims: vec![] }
    }

    pub fn claim_sized(&mut self, claim: Claim) {
        self.claims.push(claim);
    }
}

#[derive(Clone)]
pub struct GlobalClaimList {
    claims: Rc<RefCell<ClaimList>>,
}

impl GlobalClaimList {
    pub fn new() -> Self {
        Self {
            claims: Rc::new(RefCell::new(ClaimList::new())),
        }
    }

    pub fn deref_borrow(&self) -> Ref<'_, ClaimList> {
        self.claims.deref().borrow()
    }

    pub fn deref_borrow_mut(&self) -> RefMut<'_, ClaimList> {
        self.claims.deref().borrow_mut()
    }
}
