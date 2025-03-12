// OPC UA protocol

use core::any::TypeId;

//use puffin::agent::{AgentDescriptor, AgentName, ProtocolDescriptorConfig};
use puffin::algebra::signature::Signature;
//use puffin::algebra::Matcher;
use puffin::error::Error;
use puffin::protocol::{
    EvaluatedTerm, Extractable, OpaqueProtocolMessage, OpaqueProtocolMessageFlight,
    ProtocolBehavior, ProtocolMessage, ProtocolMessageDeframer, ProtocolMessageFlight,
    ProtocolTypes,
};
use puffin::put::PutDescriptor;
use puffin::trace::Trace; // {Knowledge, Source, Trace};
//use puffin::{atom_extract_knowledge, codec, dummy_extract_knowledge};

use serde::{Deserialize, Serialize};

use crate::opcua::OPCUA_SIGNATURE;



#[derive(Clone, Debug, Hash, Serialize, Deserialize)]
pub struct OPCProtocolTypes;

impl ProtocolTypes for OPCProtocolTypes {
    //type Matcher = OPCQueryMatcher;
    //type PUTConfig = OPCDescriptorConfig;

    fn signature() -> &'static Signature<Self> {
        &OPCUA_SIGNATURE
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct OPCProtocolBehavior;

impl ProtocolBehavior for OPCProtocolBehavior {
    //type Claim = TlsClaim;
    //type OpaqueProtocolMessage = OpaqueMessage;
    type OpaqueProtocolMessageFlight = OpaqueMessageFlight;
    type ProtocolMessage = Message;
    type ProtocolMessageFlight = MessageFlight;
    type ProtocolTypes = OPCProtocolTypes;
    //type SecurityViolationPolicy = OPCSecurityViolationPolicy;

    fn create_corpus(put: PutDescriptor) -> Vec<(Trace<Self::ProtocolTypes>, &'static str)> {
        crate::opcua::seeds::create_corpus(
            tls_registry()
                .find_by_id(put.factory)
                .expect("missing PUT in TLS registry"),
        )
    }

    fn try_read_bytes(
        bitstring: &[u8],
        ty: TypeId,
    ) -> Result<Box<dyn EvaluatedTerm<Self::ProtocolTypes>>, Error> {
        try_read_bytes(bitstring, ty)
    }
}