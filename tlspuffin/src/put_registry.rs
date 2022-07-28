use puffin::{
    agent::{AgentDescriptor, AgentName},
    algebra::{signature::Signature, Matcher},
    error::Error,
    io::MessageResult,
    protocol::{Message, MessageDeframer, OpaqueMessage, ProtocolBehavior},
    put::{Put, PutDescriptor, PutName},
    put_registry::{Factory, PutRegistry},
    trace::Trace,
    variable_data::VariableData,
};

use crate::{
    claims::TlsClaim,
    debug::{debug_message_with_info, debug_opaque_message_with_info},
    extraction::extract_knowledge,
    query::TlsQueryMatcher,
    tls::{
        rustls, rustls::msgs, seeds::create_corpus, violation::TlsSecurityViolationPolicy,
        TLS_SIGNATURE,
    },
};

impl Message<msgs::message::OpaqueMessage> for msgs::message::Message {
    fn create_opaque(&self) -> msgs::message::OpaqueMessage {
        msgs::message::PlainMessage::from(self.clone()).into_unencrypted_opaque()
    }
    fn debug(&self, info: &str) {
        debug_message_with_info(info, self);
    }
}

impl MessageDeframer<msgs::message::Message, msgs::message::OpaqueMessage>
    for msgs::deframer::MessageDeframer
{
    fn new() -> Self {
        msgs::deframer::MessageDeframer::new()
    }
    fn pop_frame(&mut self) -> Option<msgs::message::OpaqueMessage> {
        self.frames.pop_front()
    }
    fn encode(&self) -> Vec<u8> {
        let mut buffer: Vec<u8> = Vec::new();
        for message in &self.frames {
            buffer.append(&mut message.clone().encode());
        }
        buffer
    }
    fn read(&mut self, rd: &mut dyn std::io::Read) -> std::io::Result<usize> {
        self.read(rd)
    }
}

impl OpaqueMessage<msgs::message::Message> for msgs::message::OpaqueMessage {
    fn encode(&self) -> Vec<u8> {
        self.clone().encode()
    }

    fn into_message(self) -> Result<msgs::message::Message, Error> {
        use std::convert::TryFrom;
        crate::tls::rustls::msgs::message::Message::try_from(self.into_plain_message())
            .map_err(|err| Error::Stream("Failed to create message".to_string()))
    }

    fn debug(&self, info: &str) {
        debug_opaque_message_with_info(info, self);
    }
}

impl Matcher for msgs::enums::HandshakeType {
    fn matches(&self, matcher: &Self) -> bool {
        matcher == self
    }

    fn specificity(&self) -> u32 {
        1
    }
}

#[derive(Clone)]
pub struct TLSProtocolBehavior;

impl ProtocolBehavior for TLSProtocolBehavior {
    type Claim = TlsClaim;
    type SecurityViolationPolicy = TlsSecurityViolationPolicy;
    type Message = msgs::message::Message;
    type OpaqueMessage = msgs::message::OpaqueMessage;
    type MessageDeframer = msgs::deframer::MessageDeframer;

    type Matcher = TlsQueryMatcher;

    fn extract_knowledge(message: &Self::Message) -> Result<Vec<Box<dyn VariableData>>, Error> {
        extract_knowledge(message)
    }

    fn signature() -> &'static Signature {
        &TLS_SIGNATURE
    }

    fn registry() -> &'static PutRegistry<Self> {
        &TLS_PUT_REGISTRY
    }

    fn create_corpus() -> Vec<(Trace<Self::Matcher>, &'static str)> {
        Vec::from(create_corpus())
    }

    fn extract_query_matcher(
        message_result: &MessageResult<Self::Message, Self::OpaqueMessage>,
    ) -> Self::Matcher {
        TlsQueryMatcher::try_from(message_result).unwrap()
    }
}

pub const OPENSSL111_PUT: PutName = PutName(['O', 'P', 'E', 'N', 'S', 'S', 'L', '1', '1', '1']);
pub const WOLFSSL520_PUT: PutName = PutName(['W', 'O', 'L', 'F', 'S', 'S', 'L', '5', '2', '0']);
pub const TCP_CLIENT_PUT: PutName = PutName(['T', 'C', 'P', 'C', 'L', 'I', 'E', 'N', 'T', '_']);
pub const TCP_SERVER_PUT: PutName = PutName(['T', 'C', 'P', 'S', 'E', 'R', 'V', 'E', 'R', '_']);

pub const TLS_PUT_REGISTRY: PutRegistry<TLSProtocolBehavior> = PutRegistry {
    factories: &[
        crate::tcp::new_tcp_client_factory,
        crate::tcp::new_tcp_server_factory,
        #[cfg(feature = "openssl-binding")]
        crate::openssl::new_openssl_factory,
        #[cfg(feature = "wolfssl-binding")]
        crate::wolfssl::new_wolfssl_factory,
    ],
};

pub const CURRENT_PUT_NAME: PutName = {
    cfg_if::cfg_if! {
        if #[cfg(feature = "openssl-binding")] {
            OPENSSL111_PUT
        } else if #[cfg(feature = "wolfssl-binding")] {
            WOLFSSL520_PUT
        } else {
            puffin::put_registry::DUMMY_PUT
        }
    }
};

pub fn current_put() -> PutDescriptor {
    PutDescriptor {
        name: CURRENT_PUT_NAME,
        ..PutDescriptor::default()
    }
}
