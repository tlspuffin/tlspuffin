// The OPC UA protocol

use core::any::TypeId;
use std::fmt;
use std::io::Read;

use puffin::agent::{AgentDescriptor, AgentName, ProtocolDescriptorConfig};
use puffin::algebra::signature::Signature;
use puffin::algebra::Matcher;
use puffin::claims::SecurityViolationPolicy;
use puffin::codec::{Codec, CodecP, Reader};
use puffin::error::Error;
use puffin::protocol::{
    EvaluatedTerm, Extractable, OpaqueProtocolMessage, OpaqueProtocolMessageFlight,
    ProtocolBehavior, ProtocolMessage, ProtocolMessageDeframer, ProtocolMessageFlight,
    ProtocolTypes,
};
use puffin::put::PutDescriptor;
use puffin::trace::{Knowledge, Source, Trace};
use puffin::{codec, dummy_codec, dummy_extract_knowledge, dummy_extract_knowledge_codec};
use serde::{Deserialize, Serialize};

use crate::claims::OpcuaClaim;
use crate::messages::{
    OpcuaSecurityViolationPolicy, TestMessage, TestMessageFlight, TestOpaqueMessage,
    TestOpaqueMessageFlight,
};
use crate::opcua::OPCUA_SIGNATURE;
use crate::put_registry::opcua_registry;
use crate::types::OpcuaProtocolTypes;

#[derive(Clone, Debug, PartialEq)]
pub struct OpcuaProtocolBehavior;

impl ProtocolBehavior for OpcuaProtocolBehavior {
    type Claim = OpcuaClaim;
    type OpaqueProtocolMessage = TestOpaqueMessage;
    type OpaqueProtocolMessageFlight = TestOpaqueMessageFlight;
    type ProtocolMessage = TestMessage;
    type ProtocolMessageFlight = TestMessageFlight;
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
