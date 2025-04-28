// The OPC UA protocol.

use core::any::TypeId;

use opcua::puffin::claims::OpcuaClaim;
use opcua::core::comms::tcp_codec::Message;
use opcua::puffin::messages::{MessageFlight, ServiceMessage, ServiceMessageFlight};
use opcua::puffin::types::OpcuaProtocolTypes;
use opcua::puffin::violations::OpcuaSecurityViolationPolicy;

use puffin::error::Error;
use puffin::protocol::{EvaluatedTerm, ProtocolBehavior};
use puffin::put::PutDescriptor;
use puffin::trace::Trace;

use crate::put_registry::opcua_registry;

#[derive(Clone, Debug, PartialEq)]
pub struct OpcuaProtocolBehavior;

impl ProtocolBehavior for OpcuaProtocolBehavior {
    type Claim = OpcuaClaim;
    type OpaqueProtocolMessage = Message;
    type OpaqueProtocolMessageFlight = MessageFlight;
    type ProtocolMessage = ServiceMessage;
    type ProtocolMessageFlight = ServiceMessageFlight;
    type ProtocolTypes = OpcuaProtocolTypes;
    type SecurityViolationPolicy = OpcuaSecurityViolationPolicy;

    fn create_corpus(put: PutDescriptor) -> Vec<(Trace<Self::ProtocolTypes>, &'static str)> {
        crate::opcua::seeds::create_corpus(
            opcua_registry()
                .find_by_id(put.factory)
                .expect("missing PUT in OPC UA registry"),
        )
    }

    fn try_read_bytes(
        _bitstring: &[u8],
        _ty: TypeId,
    ) -> Result<Box<dyn EvaluatedTerm<Self::ProtocolTypes>>, Error> {
        //try_read_bytes(bitstring, ty)
        Err(Error::Term(
            "try_read_bytes not implemented yet for OPC UA".to_owned(),
        ))
    }
}
