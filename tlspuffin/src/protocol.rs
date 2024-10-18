use core::any::{Any, TypeId};

use log::debug;
use puffin::{
    algebra::{signature::Signature, ConcreteMessage, Matcher},
    codec::{Codec, Reader},
    error::Error,
    protocol::{
        ExtractKnowledge, OpaqueProtocolMessage, OpaqueProtocolMessageFlight, ProtocolBehavior,
        ProtocolMessage, ProtocolMessageDeframer, ProtocolMessageFlight,
    },
    trace::{Knowledge, Source, Trace},
    variable_data::VariableData,
};

use crate::{
    claims::TlsClaim,
    debug::{debug_message_with_info, debug_opaque_message_with_info},
    query::TlsQueryMatcher,
    tls::{
        rustls::msgs::{
            self,
            alert::AlertMessagePayload,
            base::Payload,
            ccs::ChangeCipherSpecPayload,
            deframer::MessageDeframer,
            handshake::{
                CertificatePayload, ClientHelloPayload, ECDHEServerKeyExchange,
                HandshakeMessagePayload, HandshakePayload, NewSessionTicketPayload,
                ServerHelloPayload, ServerKeyExchangePayload,
            },
            heartbeat::HeartbeatPayload,
            message::{any_get_encoding, try_read_bytes, Message, MessagePayload, OpaqueMessage},
        },
        seeds::create_corpus,
        violation::TlsSecurityViolationPolicy,
        TLS_SIGNATURE,
    },
};

#[derive(Debug, Clone)]
pub struct MessageFlight {
    pub messages: Vec<Message>,
}

impl ProtocolMessageFlight<TlsQueryMatcher, Message, OpaqueMessage, OpaqueMessageFlight>
    for MessageFlight
{
    fn new() -> Self {
        Self { messages: vec![] }
    }

    fn push(&mut self, msg: Message) {
        self.messages.push(msg);
    }

    fn debug(&self, info: &str) {
        debug!("{}: {:?}", info, self);
    }
}

impl From<Message> for MessageFlight {
    fn from(value: Message) -> Self {
        Self {
            messages: vec![value],
        }
    }
}

#[derive(Debug, Clone)]
pub struct OpaqueMessageFlight {
    pub messages: Vec<OpaqueMessage>,
}

impl OpaqueProtocolMessageFlight<TlsQueryMatcher, OpaqueMessage> for OpaqueMessageFlight {
    fn new() -> Self {
        Self { messages: vec![] }
    }

    fn push(&mut self, msg: OpaqueMessage) {
        self.messages.push(msg);
    }

    fn debug(&self, info: &str) {
        debug!("{}: {:?}", info, self);
    }
}

impl Codec for OpaqueMessageFlight {
    fn encode(&self, bytes: &mut Vec<u8>) {
        for msg in &self.messages {
            msg.encode(bytes);
        }
    }

    fn read(reader: &mut Reader) -> Option<Self> {
        let mut deframer = MessageDeframer::new();
        let mut flight = Self::new();

        let _ = deframer.read(&mut reader.rest());
        while let Some(msg) = deframer.pop_frame() {
            flight.push(msg);
            // continue to read the buffer
            let _ = deframer.read(&mut reader.rest());
        }

        Some(flight)
    }
}

impl From<MessageFlight> for OpaqueMessageFlight {
    fn from(value: MessageFlight) -> Self {
        Self {
            messages: value.messages.iter().map(|m| m.create_opaque()).collect(),
        }
    }
}

impl TryFrom<OpaqueMessageFlight> for MessageFlight {
    type Error = ();

    fn try_from(value: OpaqueMessageFlight) -> Result<Self, Self::Error> {
        let flight = Self {
            messages: value
                .messages
                .iter()
                .filter_map(|m| (*m).clone().try_into().ok())
                .collect(),
        };

        if flight.messages.len() == 0 {
            Err(())
        } else {
            Ok(flight)
        }
    }
}

impl From<OpaqueMessage> for OpaqueMessageFlight {
    fn from(value: OpaqueMessage) -> Self {
        Self {
            messages: vec![value],
        }
    }
}

impl ProtocolMessage<TlsQueryMatcher, OpaqueMessage> for Message {
    fn create_opaque(&self) -> OpaqueMessage {
        msgs::message::PlainMessage::from(self.clone()).into_unencrypted_opaque()
    }
    fn debug(&self, info: &str) {
        debug_message_with_info(info, self);
    }
}

impl ExtractKnowledge<TlsQueryMatcher> for MessageFlight {
    fn extract_knowledge(
        &self,
        knowledges: &mut Vec<Knowledge<TlsQueryMatcher>>,
        matcher: Option<TlsQueryMatcher>,
        source: &Source,
    ) -> Result<(), Error> {
        knowledges.push(Knowledge {
            source: source.clone(),
            matcher,
            data: Box::new(self.clone()),
        });

        for msg in &self.messages {
            msg.extract_knowledge(knowledges, matcher, source)?;
        }
        Ok(())
    }
}

impl ExtractKnowledge<TlsQueryMatcher> for OpaqueMessageFlight {
    fn extract_knowledge(
        &self,
        knowledges: &mut Vec<Knowledge<TlsQueryMatcher>>,
        matcher: Option<TlsQueryMatcher>,
        source: &Source,
    ) -> Result<(), Error> {
        knowledges.push(Knowledge {
            source: source.clone(),
            matcher,
            data: Box::new(self.clone()),
        });
        for msg in &self.messages {
            msg.extract_knowledge(knowledges, matcher, source)?;
        }
        Ok(())
    }
}

impl ExtractKnowledge<TlsQueryMatcher> for Message {
    /// Extracts knowledge from a [`crate::tls::rustls::msgs::message::Message`].
    /// Only plaintext messages yield more knowledge than their binary payload.
    /// If a message is an ApplicationData (TLS 1.3) or an encrypted Heartbeet
    /// or Handhake message (TLS 1.2), then only the message itself and the
    /// binary payload is returned.
    fn extract_knowledge(
        &self,
        knowledges: &mut Vec<Knowledge<TlsQueryMatcher>>,
        _: Option<TlsQueryMatcher>,
        source: &Source,
    ) -> Result<(), Error> {
        let matcher = match &self.payload {
            MessagePayload::Alert(_) => Some(TlsQueryMatcher::Alert),
            MessagePayload::Handshake(hs) => Some(TlsQueryMatcher::Handshake(Some(hs.typ))),
            MessagePayload::ChangeCipherSpec(_) => None,
            MessagePayload::ApplicationData(_) => Some(TlsQueryMatcher::ApplicationData),
            MessagePayload::Heartbeat(_) => Some(TlsQueryMatcher::Heartbeat),
            MessagePayload::TLS12EncryptedHandshake(_) => Some(TlsQueryMatcher::Handshake(None)),
        };

        knowledges.push(Knowledge {
            source: source.clone(),
            matcher,
            data: Box::new(self.clone()),
        });

        self.payload
            .extract_knowledge(knowledges, matcher, source)?;
        Ok(())
    }
}

impl ExtractKnowledge<TlsQueryMatcher> for MessagePayload {
    fn extract_knowledge(
        &self,
        knowledges: &mut Vec<Knowledge<TlsQueryMatcher>>,
        matcher: Option<TlsQueryMatcher>,
        source: &Source,
    ) -> Result<(), Error> {
        knowledges.push(Knowledge {
            source: source.clone(),
            matcher,
            data: Box::new(self.clone()),
        });
        match &self {
            MessagePayload::Alert(alert) => alert.extract_knowledge(knowledges, matcher, source)?,
            MessagePayload::Handshake(hs) => hs.extract_knowledge(knowledges, matcher, source)?,
            MessagePayload::ChangeCipherSpec(ccs) => {
                ccs.extract_knowledge(knowledges, matcher, source)?
            }
            MessagePayload::ApplicationData(opaque) => {
                opaque.extract_knowledge(knowledges, matcher, source)?
            }
            MessagePayload::Heartbeat(h) => h.extract_knowledge(knowledges, matcher, source)?,
            MessagePayload::TLS12EncryptedHandshake(tls12encrypted) => {
                tls12encrypted.extract_knowledge(knowledges, matcher, source)?
            }
        }
        Ok(())
    }
}

impl ExtractKnowledge<TlsQueryMatcher> for ChangeCipherSpecPayload {
    fn extract_knowledge(
        &self,
        knowledges: &mut Vec<Knowledge<TlsQueryMatcher>>,
        matcher: Option<TlsQueryMatcher>,
        source: &Source,
    ) -> Result<(), Error> {
        knowledges.push(Knowledge {
            source: source.clone(),
            matcher,
            data: Box::new(self.clone()),
        });

        Ok(())
    }
}
impl ExtractKnowledge<TlsQueryMatcher> for HeartbeatPayload {
    fn extract_knowledge(
        &self,
        knowledges: &mut Vec<Knowledge<TlsQueryMatcher>>,
        matcher: Option<TlsQueryMatcher>,
        source: &Source,
    ) -> Result<(), Error> {
        knowledges.push(Knowledge {
            source: source.clone(),
            matcher,
            data: Box::new(self.clone()),
        });
        knowledges.push(Knowledge {
            source: source.clone(),
            matcher,
            data: Box::new(self.payload.0.clone()),
        });
        Ok(())
    }
}

impl ExtractKnowledge<TlsQueryMatcher> for AlertMessagePayload {
    fn extract_knowledge(
        &self,
        knowledges: &mut Vec<Knowledge<TlsQueryMatcher>>,
        matcher: Option<TlsQueryMatcher>,
        source: &Source,
    ) -> Result<(), Error> {
        knowledges.push(Knowledge {
            source: source.clone(),
            matcher,
            data: Box::new(self.clone()),
        });
        knowledges.push(Knowledge {
            source: source.clone(),
            matcher,
            data: Box::new(self.description),
        });
        knowledges.push(Knowledge {
            source: source.clone(),
            matcher,
            data: Box::new(self.level),
        });
        Ok(())
    }
}

impl ExtractKnowledge<TlsQueryMatcher> for HandshakeMessagePayload {
    fn extract_knowledge(
        &self,
        knowledges: &mut Vec<Knowledge<TlsQueryMatcher>>,
        matcher: Option<TlsQueryMatcher>,
        source: &Source,
    ) -> Result<(), Error> {
        knowledges.push(Knowledge {
            source: source.clone(),
            matcher,
            data: Box::new(self.clone()),
        });
        knowledges.push(Knowledge {
            source: source.clone(),
            matcher,
            data: Box::new(self.typ),
        });
        self.payload
            .extract_knowledge(knowledges, matcher, source)?;
        Ok(())
    }
}

impl ExtractKnowledge<TlsQueryMatcher> for HandshakePayload {
    fn extract_knowledge(
        &self,
        knowledges: &mut Vec<Knowledge<TlsQueryMatcher>>,
        matcher: Option<TlsQueryMatcher>,
        source: &Source,
    ) -> Result<(), Error> {
        knowledges.push(Knowledge {
            source: source.clone(),
            matcher,
            data: Box::new(self.clone()),
        });
        match &self {
            HandshakePayload::HelloRequest => {}
            HandshakePayload::ClientHello(ch) => {
                ch.extract_knowledge(knowledges, matcher, source)?;
            }
            HandshakePayload::ServerHello(sh) => {
                sh.extract_knowledge(knowledges, matcher, source)?;
            }
            HandshakePayload::Certificate(c) => {
                c.extract_knowledge(knowledges, matcher, source)?;
            }
            HandshakePayload::ServerKeyExchange(ske) => {
                ske.extract_knowledge(knowledges, matcher, source)?;
            }
            HandshakePayload::ServerHelloDone => {}
            HandshakePayload::ClientKeyExchange(cke) => {
                cke.extract_knowledge(knowledges, matcher, source)?;
            }
            HandshakePayload::NewSessionTicket(ticket) => {
                ticket.extract_knowledge(knowledges, matcher, source)?;
            }
            _ => return Err(Error::Extraction()),
        }
        Ok(())
    }
}

impl ExtractKnowledge<TlsQueryMatcher> for CertificatePayload {
    fn extract_knowledge(
        &self,
        knowledges: &mut Vec<Knowledge<TlsQueryMatcher>>,
        matcher: Option<TlsQueryMatcher>,
        source: &Source,
    ) -> Result<(), Error> {
        knowledges.push(Knowledge {
            source: source.clone(),
            matcher,
            data: Box::new(self.clone()),
        });
        knowledges.push(Knowledge {
            source: source.clone(),
            matcher,
            data: Box::new(self.0.clone()),
        });
        Ok(())
    }
}

impl ExtractKnowledge<TlsQueryMatcher> for ServerKeyExchangePayload {
    fn extract_knowledge(
        &self,
        knowledges: &mut Vec<Knowledge<TlsQueryMatcher>>,
        matcher: Option<TlsQueryMatcher>,
        source: &Source,
    ) -> Result<(), Error> {
        knowledges.push(Knowledge {
            source: source.clone(),
            matcher,
            data: Box::new(self.clone()),
        });
        match self {
            ServerKeyExchangePayload::ECDHE(ecdhe) => {
                // this path wont be taken because we do not know the key exchange algorithm
                // in advance
                ecdhe.extract_knowledge(knowledges, matcher, source)?;
            }
            ServerKeyExchangePayload::Unknown(unknown) => {
                unknown.extract_knowledge(knowledges, matcher, source)?;
            }
        }
        Ok(())
    }
}

impl ExtractKnowledge<TlsQueryMatcher> for ECDHEServerKeyExchange {
    fn extract_knowledge(
        &self,
        knowledges: &mut Vec<Knowledge<TlsQueryMatcher>>,
        matcher: Option<TlsQueryMatcher>,
        source: &Source,
    ) -> Result<(), Error> {
        knowledges.push(Knowledge {
            source: source.clone(),
            matcher,
            data: Box::new(self.clone()),
        });
        Ok(())
    }
}

impl ExtractKnowledge<TlsQueryMatcher> for Payload {
    fn extract_knowledge(
        &self,
        knowledges: &mut Vec<Knowledge<TlsQueryMatcher>>,
        matcher: Option<TlsQueryMatcher>,
        source: &Source,
    ) -> Result<(), Error> {
        knowledges.push(Knowledge {
            source: source.clone(),
            matcher,
            data: Box::new(self.clone()),
        });
        knowledges.push(Knowledge {
            source: source.clone(),
            matcher,
            data: Box::new(self.0.clone()),
        });
        Ok(())
    }
}

impl ExtractKnowledge<TlsQueryMatcher> for ClientHelloPayload {
    fn extract_knowledge(
        &self,
        knowledges: &mut Vec<Knowledge<TlsQueryMatcher>>,
        matcher: Option<TlsQueryMatcher>,
        source: &Source,
    ) -> Result<(), Error> {
        knowledges.push(Knowledge {
            source: source.clone(),
            matcher,
            data: Box::new(self.clone()),
        });
        knowledges.push(Knowledge {
            source: source.clone(),
            matcher,
            data: Box::new(self.random),
        });
        knowledges.push(Knowledge {
            source: source.clone(),
            matcher,
            data: Box::new(self.session_id),
        });
        knowledges.push(Knowledge {
            source: source.clone(),
            matcher,
            data: Box::new(self.client_version),
        });
        knowledges.push(Knowledge {
            source: source.clone(),
            matcher,
            data: Box::new(self.extensions.clone()),
        });
        knowledges.push(Knowledge {
            source: source.clone(),
            matcher,
            data: Box::new(self.compression_methods.clone()),
        });
        knowledges.push(Knowledge {
            source: source.clone(),
            matcher,
            data: Box::new(self.cipher_suites.clone()),
        });
        // we add both the Vec<T> and below the Wrapper(T) too
        knowledges.push(Knowledge {
            source: source.clone(),
            matcher,
            data: Box::new(self.extensions.0.clone()),
        });
        knowledges.push(Knowledge {
            source: source.clone(),
            matcher,
            data: Box::new(self.compression_methods.0.clone()),
        });
        knowledges.push(Knowledge {
            source: source.clone(),
            matcher,
            data: Box::new(self.cipher_suites.0.clone()),
        });
        knowledges.extend(self.extensions.0.iter().map(|extension| Knowledge {
            source: source.clone(),
            matcher,
            data: Box::new(extension.clone()) as Box<dyn VariableData>,
        }));
        knowledges.extend(
            self.compression_methods
                .0
                .iter()
                .map(|compression| Knowledge {
                    source: source.clone(),
                    matcher,
                    data: Box::new(*compression) as Box<dyn VariableData>,
                }),
        );
        knowledges.extend(self.cipher_suites.0.iter().map(|cipher_suite| Knowledge {
            source: source.clone(),
            matcher,
            data: Box::new(*cipher_suite) as Box<dyn VariableData>,
        }));
        Ok(())
    }
}

impl ExtractKnowledge<TlsQueryMatcher> for NewSessionTicketPayload {
    fn extract_knowledge(
        &self,
        knowledges: &mut Vec<Knowledge<TlsQueryMatcher>>,
        matcher: Option<TlsQueryMatcher>,
        source: &Source,
    ) -> Result<(), Error> {
        knowledges.push(Knowledge {
            source: source.clone(),
            matcher,
            data: Box::new(self.clone()),
        });
        knowledges.push(Knowledge {
            source: source.clone(),
            matcher,
            data: Box::new(self.lifetime_hint as u64),
        });
        knowledges.push(Knowledge {
            source: source.clone(),
            matcher,
            data: Box::new(self.ticket.0.clone()),
        });
        Ok(())
    }
}

impl ExtractKnowledge<TlsQueryMatcher> for ServerHelloPayload {
    fn extract_knowledge(
        &self,
        knowledges: &mut Vec<Knowledge<TlsQueryMatcher>>,
        matcher: Option<TlsQueryMatcher>,
        source: &Source,
    ) -> Result<(), Error> {
        knowledges.push(Knowledge {
            source: source.clone(),
            matcher,
            data: Box::new(self.clone()),
        });
        knowledges.push(Knowledge {
            source: source.clone(),
            matcher,
            data: Box::new(self.random),
        });
        knowledges.push(Knowledge {
            source: source.clone(),
            matcher,
            data: Box::new(self.session_id),
        });
        knowledges.push(Knowledge {
            source: source.clone(),
            matcher,
            data: Box::new(self.cipher_suite),
        });
        knowledges.push(Knowledge {
            source: source.clone(),
            matcher,
            data: Box::new(self.compression_method),
        });
        knowledges.push(Knowledge {
            source: source.clone(),
            matcher,
            data: Box::new(self.legacy_version),
        });
        // we add both the Vec<T> and below the Wrapper(T) too
        knowledges.push(Knowledge {
            source: source.clone(),
            matcher,
            data: Box::new(self.extensions.0.clone()),
        });
        knowledges.push(Knowledge {
            source: source.clone(),
            matcher,
            data: Box::new(self.extensions.clone()),
        });
        knowledges.extend(self.extensions.0.iter().map(|extension| Knowledge {
            source: source.clone(),
            matcher,
            data: Box::new(extension.clone()) as Box<dyn VariableData>,
        }));
        Ok(())
    }
}

impl ProtocolMessageDeframer<TlsQueryMatcher> for MessageDeframer {
    type OpaqueProtocolMessage = OpaqueMessage;

    fn pop_frame(&mut self) -> Option<OpaqueMessage> {
        self.frames.pop_front()
    }
    fn read(&mut self, rd: &mut dyn std::io::Read) -> std::io::Result<usize> {
        self.read(rd)
    }
}

impl OpaqueProtocolMessage<TlsQueryMatcher> for OpaqueMessage {
    fn debug(&self, info: &str) {
        debug_opaque_message_with_info(info, self);
    }
}

impl ExtractKnowledge<TlsQueryMatcher> for OpaqueMessage {
    fn extract_knowledge(
        &self,
        knowledges: &mut Vec<Knowledge<TlsQueryMatcher>>,
        matcher: Option<TlsQueryMatcher>,
        source: &Source,
    ) -> Result<(), Error> {
        knowledges.push(Knowledge {
            source: source.clone(),
            matcher,
            data: Box::new(self.clone()),
        });
        Ok(())
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

#[derive(Clone, Debug, PartialEq)]
pub struct TLSProtocolBehavior;

impl ProtocolBehavior for TLSProtocolBehavior {
    type Claim = TlsClaim;
    type SecurityViolationPolicy = TlsSecurityViolationPolicy;
    type ProtocolMessage = Message;
    type OpaqueProtocolMessage = OpaqueMessage;
    type Matcher = TlsQueryMatcher;
    type ProtocolMessageFlight = MessageFlight;
    type OpaqueProtocolMessageFlight = OpaqueMessageFlight;

    fn signature() -> &'static Signature {
        &TLS_SIGNATURE
    }

    fn create_corpus() -> Vec<(Trace<Self::Matcher>, &'static str)> {
        create_corpus()
    }

    fn any_get_encoding(message: &Box<dyn Any>) -> Result<ConcreteMessage, Error> {
        any_get_encoding(message)
    }

    fn try_read_bytes(bitstring: &[u8], ty: TypeId) -> Result<Box<dyn Any>, Error> {
        try_read_bytes(bitstring, ty)
    }
}
