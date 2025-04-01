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
use crate::messages::OpcuaSecurityViolationPolicy;
use puffin::claims::SecurityViolationPolicy;
use puffin::codec::{Codec, CodecP, Reader};
use puffin::{codec, dummy_extract_knowledge, dummy_extract_knowledge_codec, dummy_codec};
use puffin::put::PutDescriptor;
use puffin::trace::{Knowledge, Source, Trace};

use serde::{Deserialize, Serialize};
use crate::messages::{TestMessage, TestMessageFlight, TestOpaqueMessage, TestOpaqueMessageFlight};
use crate::claims::OpcuaClaim;
use crate::put_registry::opcua_registry;
use crate::opcua::OPCUA_SIGNATURE;

// Types: we will eventually want to move this to the opcua-mapper package

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
