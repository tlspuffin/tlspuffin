use std::any::Any;

use puffin::{agent::AgentName, algebra::dynamic_function::TypeShape, claims::Claim};

#[derive(Debug, Clone)]
pub struct SshClaimInner;

#[derive(Debug, Clone)]
pub struct SshClaim {
    agent_name: AgentName,
    inner: Box<SshClaimInner>,
}

impl Claim for SshClaim {
    fn agent_name(&self) -> AgentName {
        self.agent_name
    }

    fn id(&self) -> TypeShape {
        TypeShape::of::<SshClaimInner>()
    }

    fn inner(&self) -> Box<dyn Any> {
        Box::new(self.inner.clone())
    }
}
