use std::{
    any::{Any, TypeId},
    io::Read,
};

use puffin::{
    algebra::{signature::Signature, AnyMatcher, ConcreteMessage},
    codec,
    error::{Error, Error::Term},
    protocol::{ProtocolBehavior, ProtocolMessage},
    put_registry::PutRegistry,
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

    fn any_get_encoding(message: &Box<dyn Any>) -> Result<ConcreteMessage, Error> {
        match message
            .downcast_ref::<SshMessage>()
            .map(|b| codec::Encode::get_encoding(&b.create_opaque()))
        {
            Some(cm) => Ok(cm),
            None => message
                .downcast_ref::<RawSshMessage>()
                .map(|b| codec::Encode::get_encoding(b))
                .ok_or(Term(
                    "[any_get_encoding] Unable to encode (Raw)SshMessage".to_string(),
                )),
        }
    }

    fn try_read_bytes(bitstring: ConcreteMessage, ty: TypeId) -> Result<Box<dyn Any>, Error> {
        todo!()
    }
}
