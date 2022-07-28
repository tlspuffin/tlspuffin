use puffin::{
    algebra::{signature::Signature, AnyMatcher},
    error::Error,
    io::MessageResult,
    protocol::ProtocolBehavior,
    put_registry::PutRegistry,
    trace::Trace,
    variable_data::VariableData,
};

use crate::{
    claim::SshClaim, ssh::SSH_SIGNATURE, violation::SshSecurityViolationPolicy, SSH_PUT_REGISTRY,
};

pub struct SshProtocolBehavior {}

impl ProtocolBehavior for SshProtocolBehavior {
    type Claim = SshClaim;
    type SecurityViolationPolicy = SshSecurityViolationPolicy;
    type Message = ();
    type OpaqueMessage = ();
    type MessageDeframer = ();
    type Matcher = AnyMatcher;

    fn signature() -> &'static Signature {
        &SSH_SIGNATURE
    }

    fn registry() -> &'static PutRegistry<Self>
    where
        Self: Sized,
    {
        &SSH_PUT_REGISTRY
    }

    fn create_corpus() -> Vec<(Trace<Self::Matcher>, &'static str)> {
        vec![] // TODO
    }

    fn extract_query_matcher(
        message_result: &MessageResult<Self::Message, Self::OpaqueMessage>,
    ) -> Self::Matcher {
        todo!()
    }

    fn extract_knowledge(message: &Self::Message) -> Result<Vec<Box<dyn VariableData>>, Error> {
        todo!()
    }
}
