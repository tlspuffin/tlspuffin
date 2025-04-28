use crate::core::comms::tcp_codec::Message;
use crate::puffin::types::OpcuaProtocolTypes;
use crate::types::{OpenSecureChannelRequest, OpenSecureChannelResponse};

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
//use std::fmt;
use std::io::Read;

/// The enum type [`crate::core::comms::tcp_codec::Message`] defines
/// all [`OpaqueProtocolMessage`], i.e. UA Connection Protocol messages,
/// and chunks of UA Secure Channel messages that are Signed and/or Encrypted.
/// These messages are opaque in the sense that chunks may be encrypted.
/// Yet, knowledge can be learned from them if they are not encrypted.
/// The [`OpaqueProtocolMessageFlight`] is used for exchanges with the PUT.
impl CodecP for Message {
    fn encode(&self, bytes: &mut Vec<u8>) {
        match *self {
            Message::Hello(ref h) => h.encode(bytes),
            Message::Acknowledge(ref a) => a.encode(bytes),
            Message::Error(ref e) => e.encode(bytes),
            Message::Reverse(ref r) => r.encode(bytes),
            Message::Chunk(ref c) => bytes.extend_from_slice(&c.data) //c.encode(bytes) will panic!
        }
    }

    fn read(&mut self, _: &mut Reader) -> Result<(), Error> {
        panic!("Not implemented for test stub");
    }
}

impl OpaqueProtocolMessage<OpcuaProtocolTypes> for Message {
    fn debug(&self, _info: &str) {
        panic!("Not implemented for test stub");
    }
}

/**
The enum type [`crate::core::supported_message::SupportedMessage`] defines all [`ProtocolMessage`],
i.e. all possible OPC UA service requests before security is applied to them,
and all possible responses after security has been removed from them.
/!\ We use here a simplified enum type, for a first try, called a [`ServiceMessage`]
*/
#[derive(Debug, PartialEq, Clone, Extractable)]
#[extractable(OpcuaProtocolTypes)]
pub enum ServiceMessage {
    // /!\ The trait is not implemented for Box<...>!
    // /!\ We may have to add the SecureChannel data.
    OpenSecureChannelRequest(OpenSecureChannelRequest),
    OpenSecureChannelResponse(OpenSecureChannelResponse),
}

impl CodecP for ServiceMessage {
    fn encode(&self, bytes: &mut Vec<u8>) {
        match *self {
            ServiceMessage::OpenSecureChannelRequest(ref r) =>
               r.encode(bytes),
            ServiceMessage::OpenSecureChannelResponse(ref r) =>
               r.encode(bytes),
        }
    }

    fn read(&mut self, _: &mut Reader) -> Result<(), Error> {
        panic!("Not implemented for test stub");
    }
}

// /!\ a ServiceMessage may be encoded as a MessageFlight and not
//     only as a single message.
impl ProtocolMessage<OpcuaProtocolTypes, Message> for ServiceMessage {
    fn create_opaque(&self) -> Message {
        panic!("Not implemented for test stub");
    }

    fn debug(&self, _info: &str) {
        panic!("Not implemented for test stub");
    }
}

pub struct MessageDeframer;

impl ProtocolMessageDeframer<OpcuaProtocolTypes> for MessageDeframer {
    type OpaqueProtocolMessage = Message;

    fn pop_frame(&mut self) -> Option<Message> {
        panic!("Not implemented for test stub");
    }

    fn read(&mut self, _rd: &mut dyn Read) -> std::io::Result<usize> {
        panic!("Not implemented for test stub");
    }
}

// Should not be useful...
#[derive(Debug, Clone)]
pub struct ServiceMessageFlight {
   pub messages: Vec<ServiceMessage>
}

impl ProtocolMessageFlight<OpcuaProtocolTypes, ServiceMessage, Message, MessageFlight>
    for ServiceMessageFlight
{
    fn new() -> Self {
        Self { messages: vec![]}
    }

    fn push(&mut self, msg: ServiceMessage) {
        self.messages.push(msg);
    }

    fn debug(&self, _info: &str) {
        panic!("Not implemented for test stub");
    }
}

impl TryFrom<MessageFlight> for ServiceMessageFlight {
    type Error = ();

    fn try_from(_value: MessageFlight) -> Result<Self, Self::Error> {
        Ok(Self{ messages: vec![]})
    }
}

dummy_extract_knowledge_codec!(OpcuaProtocolTypes, ServiceMessageFlight);

impl From<ServiceMessage> for ServiceMessageFlight {
    fn from(value: ServiceMessage) -> Self {
        Self{ messages: vec![value] }
    }
}

/// All chunks of a complete UA TCP message are grouped into an [`OpaqueProtocolMessageFlight`]
/// that can be exchanged with the target (PUT)
#[derive(Debug, Clone, Default)]
pub struct MessageFlight {
    messages: Vec<Message>,
}

impl MessageFlight {
    // Creates a flight of messages from the encoded chunks of a message issued by a secure channel.
    // fn from_sc_message(&mut self, chunks: &Vec<MessageChunk>) {
    //     self.messages.clear();
    //     for msg_chunk in chunks {
    //         self.messages.push(Message::Chunk(msg_chunk.clone()))
    //     }
    // }
}

impl OpaqueProtocolMessageFlight<OpcuaProtocolTypes, Message> for MessageFlight {
    fn new() -> Self {
        Self { messages: vec![] }
    }

    fn push(&mut self, msg: Message) {
        self.messages.push(msg);
    }

    fn debug(&self, info: &str) {
        log::debug!("{}: {:?}", info, self);
    }
}

dummy_extract_knowledge!(OpcuaProtocolTypes, MessageFlight);

impl From<Message> for MessageFlight {
    fn from(value: Message) -> Self {
        Self {
            messages: vec![value],
        }
    }
}

impl Codec for MessageFlight {
    fn encode(&self, bytes: &mut Vec<u8>) {
        for msg in &self.messages {
            msg.encode(bytes)
        }
    }

    fn read(_: &mut Reader) -> Option<Self> {
        panic!("Not implemented for test stub");
    }
}

impl From<ServiceMessageFlight> for MessageFlight {
    fn from(_value: ServiceMessageFlight) -> Self {
        panic!("Not implemented for test stub");
    }
}
