use std::{
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
    variable_data::VariableData,
};

#[derive(Debug, Clone)]
pub struct TlsTranscript(pub [u8; 64], pub usize);

pub trait TlsData: 'static + Send + Sync + Debug + TlsDataClone {
    fn compare_session_id(&self, other: Self) -> bool
    where
        Self: Sized;

    fn compare_client_random(&self, other: &dyn TlsData) -> bool;

    fn compare_server_random(&self, other: &Self) -> bool
    where
        Self: Sized;

    fn get_best_cipher(&self, other: Self) -> u32
    where
        Self: Sized;

    fn as_any(&self) -> &dyn Any;
}

pub trait TlsDataClone {
    fn clone_box(&self) -> Box<dyn TlsData>;
}

impl<T> TlsDataClone for T
where
    T: 'static + TlsData + Clone,
{
    fn clone_box(&self) -> Box<dyn TlsData> {
        Box::new(self.clone())
    }
}

impl Clone for Box<dyn TlsData> {
    fn clone(&self) -> Box<dyn TlsData> {
        self.clone_box()
    }
}

#[derive(Debug, Clone)]
pub struct ClientHelloClientHello(pub TlsTranscript);
#[derive(Debug, Clone)]
pub struct PartialClientHelloPartialClientHello(pub TlsTranscript);
#[derive(Debug, Clone)]
pub struct ClientHelloServerHello(pub TlsTranscript);
#[derive(Debug, Clone)]
pub struct ClientHelloServerFinished(pub TlsTranscript);
#[derive(Debug, Clone)]
pub struct ClientHelloClientFinished(pub TlsTranscript);

#[derive(Debug, Clone)]
pub struct ClientHello(pub Box<dyn TlsData>);
#[derive(Debug, Clone)]
pub struct ServerHello(pub Box<dyn TlsData>);

#[derive(Debug, Clone)]
pub enum SizedClaim {
    ClientHelloClientHello(Claim<ClientHelloClientHello>),
    PartialClientHelloPartialClientHello(Claim<PartialClientHelloPartialClientHello>),
    ClientHelloServerHello(Claim<ClientHelloServerHello>),
    ClientHelloServerFinished(Claim<ClientHelloServerFinished>),
    ClientHelloClientFinished(Claim<ClientHelloClientFinished>),

    ClientHello(Claim<ClientHello>),
    ServerHello(Claim<ServerHello>),
}

impl SizedClaim {
    pub fn agent_name(&self) -> &AgentName {
        match self {
            SizedClaim::ClientHelloClientHello(claim) => &claim.agent,
            SizedClaim::PartialClientHelloPartialClientHello(claim) => &claim.agent,
            SizedClaim::ClientHelloServerHello(claim) => &claim.agent,
            SizedClaim::ClientHelloServerFinished(claim) => &claim.agent,
            SizedClaim::ClientHelloClientFinished(claim) => &claim.agent,
            SizedClaim::ClientHello(claim) => &claim.agent,
            SizedClaim::ServerHello(claim) => &claim.agent,
        }
    }
    pub fn id(&self) -> TypeId {
        match self {
            SizedClaim::ClientHelloClientHello(claim) => {
                TypeId::of::<Claim<ClientHelloClientHello>>()
            }
            SizedClaim::PartialClientHelloPartialClientHello(claim) => {
                TypeId::of::<Claim<PartialClientHelloPartialClientHello>>()
            }
            SizedClaim::ClientHelloServerHello(claim) => {
                TypeId::of::<Claim<ClientHelloServerHello>>()
            }
            SizedClaim::ClientHelloServerFinished(claim) => {
                TypeId::of::<Claim<ClientHelloServerFinished>>()
            }
            SizedClaim::ClientHelloClientFinished(claim) => {
                TypeId::of::<Claim<ClientHelloClientFinished>>()
            }
            SizedClaim::ClientHello(claim) => TypeId::of::<Claim<ClientHello>>(),
            SizedClaim::ServerHello(claim) => TypeId::of::<Claim<ServerHello>>(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Claim<T> {
    pub agent: AgentName,
    pub origin: AgentType,
    pub outbound: bool,
    pub protocol_version: TLSVersion,
    pub data: T,
}

impl SizedClaim {
    pub fn name(&self) -> &'static str {
        ""
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fmt::{Debug, Formatter},
        ops::Deref,
    };

    use libafl::events::ManagerKind::Any;

    use crate::claims::TlsData;

    struct DummyTlsData(u32);

    impl Debug for DummyTlsData {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            todo!()
        }
    }

    impl Clone for DummyTlsData {
        fn clone(&self) -> Self {
            todo!()
        }
    }

    impl TlsData for DummyTlsData {
        fn compare_session_id(&self, other: Self) -> bool
        where
            Self: Sized,
        {
            todo!()
        }

        fn compare_client_random(&self, other: &dyn TlsData) -> bool {
            other.as_any().downcast_ref::<Self>().unwrap().0 == self.0
        }

        fn compare_server_random(&self, other: &Self) -> bool
        where
            Self: Sized,
        {
            other.0 == self.0
        }

        fn get_best_cipher(&self, other: Self) -> u32
        where
            Self: Sized,
        {
            todo!()
        }

        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    #[test]
    pub fn test() {
        let boxed1 = Box::new(DummyTlsData(0)) as Box<dyn TlsData>;
        let boxed2 = Box::new(DummyTlsData(1)) as Box<dyn TlsData>;
        assert!(!boxed1.compare_client_random(boxed2.as_ref()));
    }

    pub fn check<T: TlsData>(boxed1: Box<dyn TlsData>, boxed2: Box<dyn TlsData>) -> bool {
        let one = boxed1.as_any().downcast_ref::<T>().unwrap();
        let two = boxed2.as_any().downcast_ref::<T>().unwrap();
        one.compare_server_random(two)
    }

    #[test]
    pub fn test1() {
        let boxed1 = Box::new(DummyTlsData(0)) as Box<dyn TlsData>;
        let boxed2 = Box::new(DummyTlsData(1)) as Box<dyn TlsData>;

        let one = boxed1.as_any().downcast_ref::<DummyTlsData>().unwrap();
        let two = boxed2.as_any().downcast_ref::<DummyTlsData>().unwrap();

        assert!(!one.compare_server_random(two));
    }

    #[test]
    pub fn test2() {
        let boxed1 = Box::new(DummyTlsData(0)) as Box<dyn TlsData>;
        let boxed2 = Box::new(DummyTlsData(1)) as Box<dyn TlsData>;

        assert!(!check::<DummyTlsData>(boxed1, boxed2));
    }
}

pub struct Policy {
    pub(crate) func: fn(claims: &[SizedClaim]) -> Option<&'static str>,
}

pub trait CheckViolation {
    fn check_violation(&self, policy: Policy) -> Option<&'static str>;
}

#[derive(Clone, Debug)]
pub struct ClaimList {
    claims: Vec<SizedClaim>,
}

impl CheckViolation for ClaimList {
    fn check_violation(&self, policy: Policy) -> Option<&'static str> {
        (policy.func)(&self.claims)
    }
}

impl ClaimList {
    pub fn iter(&self) -> Iter<'_, SizedClaim> {
        self.claims.iter()
    }

    /// finds the last claim matching `type`
    pub fn find_last_claim<T: 'static>(&self) -> Option<&SizedClaim> {
        self.claims
            .iter()
            .find(|claim| claim.id() == TypeId::of::<T>())
    }

    pub fn slice(&self) -> &[SizedClaim] {
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
                .map(|claim| format!("{}", claim.name()))
                .join(", ")
        );
        for claim in &self.claims {
            trace!("{:?}", claim);
        }
    }
}

impl From<Vec<SizedClaim>> for ClaimList {
    fn from(claims: Vec<SizedClaim>) -> Self {
        Self { claims }
    }
}

/// Claims filters by [`AgentName`]
#[derive(Clone, Debug)]
pub struct ByAgentClaimList {
    claims: ClaimList,
}

impl ByAgentClaimList {
    pub fn new(claims: &ClaimList, agent_name: AgentName) -> Option<Self> {
        let filtered = claims
            .iter()
            .filter(|claim| agent_name == *claim.agent_name())
            .cloned()
            .rev()
            .collect::<Vec<_>>();
        if filtered.is_empty() {
            None
        } else {
            Some(Self {
                claims: filtered.into(),
            })
        }
    }

    /// finds the last claim matching `type`
    pub fn find_last_claim<T: 'static>(&self) -> Option<&SizedClaim> {
        self.claims
            .iter()
            .find(|claim| claim.id() == TypeId::of::<T>())
    }
}

impl ClaimList {
    pub fn new() -> Self {
        Self { claims: vec![] }
    }

    pub fn claim_sized(&mut self, claim: SizedClaim) {
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
