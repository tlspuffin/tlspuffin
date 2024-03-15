use puffin::{
    algebra::{signature::Signature, AnyMatcher},
    protocol::ProtocolBehavior,
    trace::Trace,
};

use crate::{
    claim::SshClaim,
    ssh::{
        message::{RawSshMessage, SshMessage},
        SSH_SIGNATURE,
    },
    violation::SshSecurityViolationPolicy,
};

#[derive(Clone, Debug, PartialEq)]
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

    fn create_corpus() -> Vec<(Trace<Self::Matcher>, &'static str)> {
        vec![] // TODO
    }
}
