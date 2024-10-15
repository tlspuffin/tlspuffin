use puffin::agent::AgentName;
use puffin::algebra::dynamic_function::TypeShape;
use puffin::claims::Claim;
use puffin::dummy_extract_knowledge;
use puffin::error::Error;
use puffin::protocol::{EvaluatedTerm, ProtocolTypes};
use puffin::trace::{Knowledge, Source};

use crate::protocol::SshProtocolTypes;

#[derive(Debug, Clone)]
pub struct SshClaimInner;
dummy_extract_knowledge!(SshProtocolTypes, Box<SshClaimInner>);

#[derive(Debug, Clone)]
pub struct SshClaim {
    agent_name: AgentName,
    inner: Box<SshClaimInner>,
}

impl Claim<SshProtocolTypes> for SshClaim {
    fn agent_name(&self) -> AgentName {
        self.agent_name
    }

    fn id(&self) -> TypeShape<SshProtocolTypes> {
        TypeShape::of::<SshClaimInner>()
    }

    fn inner(&self) -> Box<dyn EvaluatedTerm<SshProtocolTypes>> {
        Box::new(self.inner.clone())
    }
}

dummy_extract_knowledge!(SshProtocolTypes, SshClaim);
