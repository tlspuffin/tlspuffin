use crate::puffin::types::OpcuaProtocolTypes;
use crate::types::{AcknowledgeMessage, ErrorMessage, HelloMessage, ReverseHelloMessage, MessageChunk};

use extractable_macro::Extractable;
use puffin::codec::{Codec, CodecP, Reader};
use puffin::error::Error;
use puffin::protocol::{
    Extractable, OpaqueProtocolMessage, OpaqueProtocolMessageFlight, ProtocolMessage,
    ProtocolMessageDeframer, ProtocolMessageFlight, ProtocolTypes,
};
use puffin::trace::{Knowledge, Source};
use puffin::{codec, dummy_codec, dummy_extract_knowledge, dummy_extract_knowledge_codec};

use std::convert::TryFrom;
use std::fmt;
use std::io::Read;

/// This enum type defines all [`OpaqueProtocolMessage`], i.e. UA Connection Protocol messages,
/// and chunks of UA Secure Channel messages that are Signed and/or Encrypted.
/// These messages are opaque in the sense that they may need to be decrypted, but knowledge
/// can be learned from them, especially if they are not encrypted.
/// The [`OpaqueProtocolMessageFlight`] is used for exchanges with the PUT.
#[derive(Debug, Clone, Extractable)]
#[extractable(OpcuaProtocolTypes)]
pub enum UatcpMessage {
    Hello(HelloMessage),
    Acknowledge(AcknowledgeMessage),
    Error(ErrorMessage),
    Reverse(ReverseHelloMessage),
    Chunk(#[extractable_ignore] MessageChunk),
}

impl CodecP for UatcpMessage {
    fn encode(&self, bytes: &mut Vec<u8>) {
        match *self {
            UatcpMessage::Hello(ref h) => h.encode(bytes),
            UatcpMessage::Acknowledge(ref a) => a.encode(bytes),
            UatcpMessage::Error(ref e) => e.encode(bytes),
            UatcpMessage::Reverse(ref r) => r.encode(bytes),
            UatcpMessage::Chunk(ref c) => c.encode(bytes),
        }
    }

    fn read(&mut self, _: &mut Reader) -> Result<(), Error> {
        panic!("Not implemented for test stub");
    }
}

impl OpaqueProtocolMessage<OpcuaProtocolTypes> for UatcpMessage {
    fn debug(&self, _info: &str) {
        panic!("Not implemented for test stub");
    }
}

/// This enum type defines all [`ProtocolMessage`],
/// i.e. all possible OPC UA services before security is applied to them
pub enum Message {}

impl Clone for Message {
    fn clone(&self) -> Self {
        panic!("Not implemented for test stub");
    }
}

impl fmt::Debug for Message {
    fn fmt(&self, _f: &mut fmt::Formatter<'_>) -> std::fmt::Result {
        panic!("Not implemented for test stub");
    }
}

impl ProtocolMessage<OpcuaProtocolTypes, UatcpMessage> for Message {
    fn create_opaque(&self) -> UatcpMessage {
        panic!("Not implemented for test stub");
    }

    fn debug(&self, _info: &str) {
        panic!("Not implemented for test stub");
    }
}

dummy_extract_knowledge_codec!(OpcuaProtocolTypes, Message);

pub struct MessageDeframer;

impl ProtocolMessageDeframer<OpcuaProtocolTypes> for MessageDeframer {
    type OpaqueProtocolMessage = UatcpMessage;

    fn pop_frame(&mut self) -> Option<UatcpMessage> {
        panic!("Not implemented for test stub");
    }

    fn read(&mut self, _rd: &mut dyn Read) -> std::io::Result<usize> {
        panic!("Not implemented for test stub");
    }
}

// Should not be useful...
#[derive(Debug, Clone)]
pub struct MessageFlight;

impl ProtocolMessageFlight<OpcuaProtocolTypes, Message, UatcpMessage, UatcpMessageFlight>
    for MessageFlight
{
    fn new() -> Self {
        Self {}
    }

    fn push(&mut self, _msg: Message) {
        panic!("Not implemented for test stub");
    }

    fn debug(&self, _info: &str) {
        panic!("Not implemented for test stub");
    }
}

impl TryFrom<UatcpMessageFlight> for MessageFlight {
    type Error = ();

    fn try_from(_value: UatcpMessageFlight) -> Result<Self, Self::Error> {
        Ok(Self)
    }
}

dummy_extract_knowledge_codec!(OpcuaProtocolTypes, MessageFlight);

impl From<Message> for MessageFlight {
    fn from(_value: Message) -> Self {
        Self {}
    }
}

/// All chunks of a complete UA TCP message are grouped into an [`OpaqueProtocolMessageFlight`]
/// that can be exchanged with the target (PUT)
#[derive(Debug, Clone, Default)]
pub struct UatcpMessageFlight {
    messages: Vec<UatcpMessage>,
}

impl OpaqueProtocolMessageFlight<OpcuaProtocolTypes, UatcpMessage> for UatcpMessageFlight {
    fn new() -> Self {
        Self { messages: vec![] }
    }

    fn push(&mut self, msg: UatcpMessage) {
        self.messages.push(msg);
    }

    fn debug(&self, info: &str) {
        log::debug!("{}: {:?}", info, self);
    }
}

dummy_extract_knowledge!(OpcuaProtocolTypes, UatcpMessageFlight);

impl From<UatcpMessage> for UatcpMessageFlight {
    fn from(value: UatcpMessage) -> Self {
        Self {
            messages: vec![value],
        }
    }
}

impl Codec for UatcpMessageFlight {
    fn encode(&self, bytes: &mut Vec<u8>) {
        for msg in &self.messages {
            msg.encode(bytes)
        }
    }

    fn read(_: &mut Reader) -> Option<Self> {
        panic!("Not implemented for test stub");
    }
}

impl From<MessageFlight> for UatcpMessageFlight {
    fn from(_value: MessageFlight) -> Self {
        panic!("Not implemented for test stub");
    }
}
