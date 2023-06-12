use std::io::Read;

use puffin::{
    algebra::{signature::Signature, AnyMatcher},
    error::Error,
    protocol::{
        MessageResult, OpaqueProtocolMessage, ProtocolBehavior, ProtocolMessage,
        ProtocolMessageDeframer,
    },
    put_registry::PutRegistry,
    trace::Trace,
    variable_data::VariableData,
};

use crate::{
    claim::SshClaim,
    ssh::{
        deframe::SshMessageDeframer,
        message::{
            KexEcdhInitMessage, KexEcdhReplyMessage, KexInitMessage, RawSshMessage, SshMessage,
        },
        SSH_SIGNATURE,
    },
    violation::SshSecurityViolationPolicy,
    SSH_PUT_REGISTRY,
};

#[derive(Clone)]
pub struct SshProtocolBehavior {}

impl ProtocolBehavior for SshProtocolBehavior {
    type Claim = SshClaim;
    type SecurityViolationPolicy = SshSecurityViolationPolicy;
    type ProtocolMessage = SshMessage;
    type OpaqueProtocolMessage = RawSshMessage;
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

    fn create_corpus_obj() -> Vec<(Trace<Self::Matcher>, &'static str)> {
        vec![] // TODO
    }
}
