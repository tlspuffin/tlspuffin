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

use crate::{
    agent::{AgentName, AgentType, TLSVersion},
    algebra::dynamic_function::TypeShape,
    variable_data::VariableData,
};

#[derive(Debug, Clone)]
pub struct TlsTranscript(pub [u8; 64], pub i32);

#[derive(Debug, Clone)]
pub struct TlsData {}

#[derive(Debug, Clone)]
pub struct TranscriptClientHello(pub TlsTranscript);
#[derive(Debug, Clone)]
pub struct TranscriptPartialClientHello(pub TlsTranscript);
#[derive(Debug, Clone)]
pub struct TranscriptServerHello(pub TlsTranscript);
#[derive(Debug, Clone)]
pub struct TranscriptServerFinished(pub TlsTranscript);
#[derive(Debug, Clone)]
pub struct TranscriptClientFinished(pub TlsTranscript);

#[derive(Debug, Clone)]
pub struct ClientHello(pub TlsData);
#[derive(Debug, Clone)]
pub struct ServerHello(pub TlsData);
#[derive(Debug, Clone)]
pub struct Certificate(pub TlsData);
#[derive(Debug, Clone)]
pub struct CertificateVerify(pub TlsData);
#[derive(Debug, Clone)]
pub struct Finished(pub TlsData);

#[derive(Debug, Clone)]
pub enum ClaimDataTranscript {
    ClientHello(TranscriptClientHello),
    PartialClientHello(TranscriptPartialClientHello),
    ServerHello(TranscriptServerHello),
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
    pub outbound: bool,
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
    pub(crate) func: fn(claims: &[Claim]) -> Option<&'static str>,
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
