// The OPC UA protocol

use core::any::TypeId;
use std::fmt;
use std::io::Read;

use puffin::agent::{AgentDescriptor, AgentName, ProtocolDescriptorConfig};
use puffin::algebra::signature::Signature;
use puffin::algebra::Matcher;
use puffin::error::Error;
use puffin::protocol::{
    EvaluatedTerm, Extractable, OpaqueProtocolMessage, OpaqueProtocolMessageFlight,
    ProtocolBehavior, ProtocolMessage, ProtocolMessageDeframer, ProtocolMessageFlight,
    ProtocolTypes,
};

use puffin::claims::SecurityViolationPolicy;
use puffin::codec::{Codec, CodecP, Reader};
use puffin::{codec, dummy_extract_knowledge, dummy_extract_knowledge_codec, dummy_codec};
use puffin::put::PutDescriptor;
use puffin::trace::{Knowledge, Source, Trace};

use serde::{Deserialize, Serialize};

use crate::claims::OpcuaClaim;
use crate::put_registry::opcua_registry;
use crate::opcua::OPCUA_SIGNATURE;


// PUT configuration descriptor:

#[derive(Serialize, Deserialize, Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum AgentType {
    Server,
    Client,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, Eq, PartialEq, Hash)]
pub enum OpcuaVersion {
    V1_4, // only RSA
    V1_5, // with ECC
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, Eq, PartialEq, Hash)]
pub enum ChannelMode {
    None,   // unsecure channel
    Sign,   // sign-only
    Encrypt,// sign and encrypt
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, Eq, PartialEq, Hash)]
pub enum SessionSecurity {
    /// No Application Authentication, i.e. the server is configured 
    /// to accept all client certificates and only use them for message security.
    SNoAA,
    SSec, // Client Application Authentication
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, Eq, PartialEq, Hash)]
pub enum UserToken {
    Anonymous,
    Password,
    Certificate,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq, Hash)]
pub struct OpcuaDescriptorConfig {
    pub kind: AgentType,
    pub version: OpcuaVersion,
    pub mode: ChannelMode,
    pub check: SessionSecurity, /// Default: SSec.
    pub login: UserToken,
    /// List of available OPC UA ciphers
    pub cipher_string: String,
}

impl OpcuaDescriptorConfig {
    pub fn new_client(name: AgentName, mode: ChannelMode, login: UserToken) -> AgentDescriptor<Self> {
        let protocol_config = Self {
            kind: AgentType::Client,
            mode,
            login,
            ..Self::default()
        };

        AgentDescriptor {
            name,
            protocol_config,
        }
    }

    pub fn new_server(name: AgentName, mode: ChannelMode, login: UserToken) -> AgentDescriptor<Self> {
        let protocol_config = Self {
            kind: AgentType::Server,
            mode,
            login,
            ..Self::default()
        };

        AgentDescriptor {
            name,
            protocol_config,
        }
    }
}

impl ProtocolDescriptorConfig for OpcuaDescriptorConfig {
    fn is_reusable_with(&self, _other: &Self) -> bool {false}
}

impl Default for OpcuaDescriptorConfig {
    fn default() -> Self {
        Self {
            kind: AgentType::Server,
            version: OpcuaVersion::V1_4,
            mode: ChannelMode::Sign,
            check: SessionSecurity::SSec,
            login: UserToken::Certificate,
            cipher_string: String::from("ALL"),
        }
    }
}


// Query Matcher:

#[derive(Debug, Deserialize, Serialize, Clone, Copy, Hash, Eq, PartialEq)]
pub enum OpcuaQueryMatcher {
    Hello,   // HEL
    Open,    // OPN
    Message, // MSG
    Close,   // CLO
}

impl Matcher for OpcuaQueryMatcher {
    fn matches(&self, matcher: &Self) -> bool {
        match matcher {
            _ => false,
        }
    }

    fn specificity(&self) -> u32 {
        match self {
            _ => 0,
        }
    }
}


// Protocol Types:

#[derive(Clone, Debug, Hash, Serialize, Deserialize)]
pub struct OpcuaProtocolTypes;

impl ProtocolTypes for OpcuaProtocolTypes {
    type Matcher = OpcuaQueryMatcher;
    type PUTConfig = OpcuaDescriptorConfig;

    fn signature() -> &'static Signature<Self> {
        &OPCUA_SIGNATURE
    }
}

impl std::fmt::Display for OpcuaProtocolTypes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "")
    }
}

// Messages:
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


// Protocol Behavior:

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
        Err(Error::Term("try_read_bytes not implemented yet for OPC UA".to_owned()))
    }
}