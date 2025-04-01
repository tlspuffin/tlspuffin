use puffin::trace::Source;
use crate::claims::OpcuaClaim;
use puffin::claims::SecurityViolationPolicy;
use puffin::protocol::ProtocolMessageDeframer;
use puffin::codec;
use puffin::protocol::ProtocolMessage;
use puffin::protocol::ProtocolTypes;
use puffin::trace::Knowledge;
use puffin::protocol::Extractable;
use puffin::codec::{CodecP, Reader};
use puffin::dummy_codec;
use puffin::dummy_extract_knowledge;
use std::convert::TryFrom;
use std::fmt;
use std::io::Read;
use puffin::dummy_extract_knowledge_codec;
use puffin::error::Error;
use puffin::protocol::OpaqueProtocolMessage;
use crate::types::OpcuaProtocolTypes;
use puffin::protocol::ProtocolMessageFlight;
use puffin::protocol::OpaqueProtocolMessageFlight;
use puffin::codec::Codec;

// Messages: we might eventually want to move this to the opcua-mapper package
pub struct TestOpaqueMessage;

impl Clone for TestOpaqueMessage {
    fn clone(&self) -> Self {
        panic!("Not implemented for test stub");
    }
}

impl fmt::Debug for TestOpaqueMessage {
    fn fmt(&self, _f: &mut fmt::Formatter<'_>) -> std::fmt::Result {
        panic!("Not implemented for test stub");
    }
}

impl CodecP for TestOpaqueMessage {
    fn encode(&self, _bytes: &mut Vec<u8>) {
        panic!("Not implemented for test stub");
    }

    fn read(&mut self, _: &mut Reader) -> Result<(), Error> {
        panic!("Not implemented for test stub");
    }
}

impl OpaqueProtocolMessage<OpcuaProtocolTypes> for TestOpaqueMessage {
    fn debug(&self, _info: &str) {
        panic!("Not implemented for test stub");
    }
}

dummy_extract_knowledge!(OpcuaProtocolTypes, TestOpaqueMessage);

pub struct TestMessage;

impl Clone for TestMessage {
    fn clone(&self) -> Self {
        panic!("Not implemented for test stub");
    }
}

impl fmt::Debug for TestMessage {
    fn fmt(&self, _f: &mut fmt::Formatter<'_>) -> std::fmt::Result {
        panic!("Not implemented for test stub");
    }
}

impl ProtocolMessage<OpcuaProtocolTypes, TestOpaqueMessage> for TestMessage {
    fn create_opaque(&self) -> TestOpaqueMessage {
        panic!("Not implemented for test stub");
    }

    fn debug(&self, _info: &str) {
        panic!("Not implemented for test stub");
    }
}

dummy_extract_knowledge_codec!(OpcuaProtocolTypes, TestMessage);

pub struct TestMessageDeframer;

impl ProtocolMessageDeframer<OpcuaProtocolTypes> for TestMessageDeframer {
    type OpaqueProtocolMessage = TestOpaqueMessage;

    fn pop_frame(&mut self) -> Option<TestOpaqueMessage> {
        panic!("Not implemented for test stub");
    }

    fn read(&mut self, _rd: &mut dyn Read) -> std::io::Result<usize> {
        panic!("Not implemented for test stub");
    }
}

pub struct OpcuaSecurityViolationPolicy;
impl SecurityViolationPolicy for OpcuaSecurityViolationPolicy {
    type C = OpcuaClaim;

    fn check_violation(_claims: &[OpcuaClaim]) -> Option<&'static str> {
        panic!("Not implemented yet for OPC UA");
    }
}

#[derive(Debug, Clone)]
pub struct TestMessageFlight;

impl
ProtocolMessageFlight<
    OpcuaProtocolTypes,
    TestMessage,
    TestOpaqueMessage,
    TestOpaqueMessageFlight,
> for TestMessageFlight
{
    fn new() -> Self {
        Self {}
    }

    fn push(&mut self, _msg: TestMessage) {
        panic!("Not implemented for test stub");
    }

    fn debug(&self, _info: &str) {
        panic!("Not implemented for test stub");
    }
}

impl TryFrom<TestOpaqueMessageFlight> for TestMessageFlight {
    type Error = ();

    fn try_from(_value: TestOpaqueMessageFlight) -> Result<Self, Self::Error> {
        Ok(Self)
    }
}

dummy_extract_knowledge_codec!(OpcuaProtocolTypes, TestMessageFlight);

impl From<TestMessage> for TestMessageFlight {
    fn from(_value: TestMessage) -> Self {
        Self {}
    }
}

#[derive(Debug, Clone, Default)]
pub struct TestOpaqueMessageFlight;

impl OpaqueProtocolMessageFlight<OpcuaProtocolTypes, TestOpaqueMessage> for TestOpaqueMessageFlight {
    fn new() -> Self {
        Self {}
    }

    fn push(&mut self, _msg: TestOpaqueMessage) {
        panic!("Not implemented for test stub");
    }

    fn debug(&self, _info: &str) {
        panic!("Not implemented for test stub");
    }
}

dummy_extract_knowledge!(OpcuaProtocolTypes, TestOpaqueMessageFlight);

impl From<TestOpaqueMessage> for TestOpaqueMessageFlight {
    fn from(_value: TestOpaqueMessage) -> Self {
        Self {}
    }
}

impl Codec for TestOpaqueMessageFlight {
    fn encode(&self, _bytes: &mut Vec<u8>) {
        panic!("Not implemented for test stub");
    }

    fn read(_: &mut Reader) -> Option<Self> {
        panic!("Not implemented for test stub");
    }
}

impl From<TestMessageFlight> for TestOpaqueMessageFlight {
    fn from(_value: TestMessageFlight) -> Self {
        Self {}
    }
}
