use std::fmt::Display;

use puffin::algebra::signature::Signature;
use puffin::algebra::Matcher;
use puffin::codec::{Codec, Reader};
use puffin::error::Error;
use puffin::protocol::{
    ExtractKnowledge, OpaqueProtocolMessage, OpaqueProtocolMessageFlight, ProtocolBehavior,
    ProtocolMessage, ProtocolMessageDeframer, ProtocolMessageFlight, ProtocolTypes,
};
use puffin::trace::{Knowledge, Source, Trace};

use crate::claims::TlsClaim;
use crate::debug::{debug_message_with_info, debug_opaque_message_with_info};
use crate::query::TlsQueryMatcher;
use crate::tls::rustls::msgs::alert::AlertMessagePayload;
use crate::tls::rustls::msgs::base::Payload;
use crate::tls::rustls::msgs::ccs::ChangeCipherSpecPayload;
use crate::tls::rustls::msgs::deframer::MessageDeframer;
use crate::tls::rustls::msgs::handshake::{
    CertificatePayload, ClientHelloPayload, ECDHEServerKeyExchange, HandshakeMessagePayload,
    HandshakePayload, NewSessionTicketPayload, ServerHelloPayload, ServerKeyExchangePayload,
};
use crate::tls::rustls::msgs::heartbeat::HeartbeatPayload;
use crate::tls::rustls::msgs::message::{Message, MessagePayload, OpaqueMessage};
use crate::tls::rustls::msgs::{self};
use crate::tls::seeds::create_corpus;
use crate::tls::violation::TlsSecurityViolationPolicy;
use crate::tls::TLS_SIGNATURE;

#[derive(Debug, Clone)]
pub struct MessageFlight {
    pub messages: Vec<Message>,
}

impl ProtocolMessageFlight<TLSProtocolTypes, Message, OpaqueMessage, OpaqueMessageFlight>
    for MessageFlight
{
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

impl OpaqueProtocolMessageFlight<TLSProtocolTypes, OpaqueMessage> for OpaqueMessageFlight {
    fn new() -> Self {
        Self { messages: vec![] }
    }

    fn push(&mut self, msg: OpaqueMessage) {
        self.messages.push(msg);
    }

    fn debug(&self, info: &str) {
        log::debug!("{}: {:?}", info, self);
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

        if flight.messages.is_empty() {
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

impl ProtocolMessage<TLSProtocolTypes, OpaqueMessage> for Message {
    fn create_opaque(&self) -> OpaqueMessage {
        msgs::message::PlainMessage::from(self.clone()).into_unencrypted_opaque()
    }

    fn debug(&self, info: &str) {
        debug_message_with_info(info, self);
    }
}

impl ExtractKnowledge<TLSProtocolTypes> for MessageFlight {
    fn extract_knowledge<'a>(
        &'a self,
        knowledges: &mut Vec<Knowledge<'a, TLSProtocolTypes>>,
        matcher: Option<TlsQueryMatcher>,
        source: &'a Source,
    ) -> Result<(), Error> {
        knowledges.push(Knowledge {
            source,
            matcher,
            data: self,
        });

        for msg in &self.messages {
            msg.extract_knowledge(knowledges, matcher, source)?;
        }
        Ok(())
    }
}

impl ExtractKnowledge<TLSProtocolTypes> for OpaqueMessageFlight {
    fn extract_knowledge<'a>(
        &'a self,
        knowledges: &mut Vec<Knowledge<'a, TLSProtocolTypes>>,
        matcher: Option<TlsQueryMatcher>,
        source: &'a Source,
    ) -> Result<(), Error> {
        knowledges.push(Knowledge {
            source,
            matcher,
            data: self,
        });
        for msg in &self.messages {
            msg.extract_knowledge(knowledges, matcher, source)?;
        }
        Ok(())
    }
}

impl ExtractKnowledge<TLSProtocolTypes> for Message {
    /// Extracts knowledge from a [`crate::tls::rustls::msgs::message::Message`].
    /// Only plaintext messages yield more knowledge than their binary payload.
    /// If a message is an ApplicationData (TLS 1.3) or an encrypted Heartbeet
    /// or Handhake message (TLS 1.2), then only the message itself and the
    /// binary payload is returned.
    fn extract_knowledge<'a>(
        &'a self,
        knowledges: &mut Vec<Knowledge<'a, TLSProtocolTypes>>,
        _: Option<TlsQueryMatcher>,
        source: &'a Source,
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
            source,
            matcher,
            data: self,
        });

        self.payload
            .extract_knowledge(knowledges, matcher, source)?;
        Ok(())
    }
}

impl ExtractKnowledge<TLSProtocolTypes> for MessagePayload {
    fn extract_knowledge<'a>(
        &'a self,
        knowledges: &mut Vec<Knowledge<'a, TLSProtocolTypes>>,
        matcher: Option<TlsQueryMatcher>,
        source: &'a Source,
    ) -> Result<(), Error> {
        knowledges.push(Knowledge {
            source,
            matcher,
            data: self,
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

impl ExtractKnowledge<TLSProtocolTypes> for ChangeCipherSpecPayload {
    fn extract_knowledge<'a>(
        &'a self,
        knowledges: &mut Vec<Knowledge<'a, TLSProtocolTypes>>,
        matcher: Option<TlsQueryMatcher>,
        source: &'a Source,
    ) -> Result<(), Error> {
        knowledges.push(Knowledge {
            source,
            matcher,
            data: self,
        });

        Ok(())
    }
}

impl ExtractKnowledge<TLSProtocolTypes> for HeartbeatPayload {
    fn extract_knowledge<'a>(
        &'a self,
        knowledges: &mut Vec<Knowledge<'a, TLSProtocolTypes>>,
        matcher: Option<TlsQueryMatcher>,
        source: &'a Source,
    ) -> Result<(), Error> {
        knowledges.push(Knowledge {
            source,
            matcher,
            data: self,
        });
        knowledges.push(Knowledge {
            source,
            matcher,
            data: &self.payload.0,
        });
        Ok(())
    }
}

impl ExtractKnowledge<TLSProtocolTypes> for AlertMessagePayload {
    fn extract_knowledge<'a>(
        &'a self,
        knowledges: &mut Vec<Knowledge<'a, TLSProtocolTypes>>,
        matcher: Option<TlsQueryMatcher>,
        source: &'a Source,
    ) -> Result<(), Error> {
        knowledges.push(Knowledge {
            source,
            matcher,
            data: self,
        });
        knowledges.push(Knowledge {
            source,
            matcher,
            data: &self.description,
        });
        knowledges.push(Knowledge {
            source,
            matcher,
            data: &self.level,
        });
        Ok(())
    }
}

impl ExtractKnowledge<TLSProtocolTypes> for HandshakeMessagePayload {
    fn extract_knowledge<'a>(
        &'a self,
        knowledges: &mut Vec<Knowledge<'a, TLSProtocolTypes>>,
        matcher: Option<TlsQueryMatcher>,
        source: &'a Source,
    ) -> Result<(), Error> {
        knowledges.push(Knowledge {
            source,
            matcher,
            data: self,
        });
        knowledges.push(Knowledge {
            source,
            matcher,
            data: &self.typ,
        });
        self.payload
            .extract_knowledge(knowledges, matcher, source)?;
        Ok(())
    }
}

impl ExtractKnowledge<TLSProtocolTypes> for HandshakePayload {
    fn extract_knowledge<'a>(
        &'a self,
        knowledges: &mut Vec<Knowledge<'a, TLSProtocolTypes>>,
        matcher: Option<TlsQueryMatcher>,
        source: &'a Source,
    ) -> Result<(), Error> {
        knowledges.push(Knowledge {
            source,
            matcher,
            data: self,
        });
        match &self {
            HandshakePayload::HelloRequest | HandshakePayload::HelloRetryRequest(_) => {}
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
            _ => {
                log::error!("failed extraction: {self:?}");
                return Err(Error::Extraction());
            }
        }
        Ok(())
    }
}

impl ExtractKnowledge<TLSProtocolTypes> for CertificatePayload {
    fn extract_knowledge<'a>(
        &'a self,
        knowledges: &mut Vec<Knowledge<'a, TLSProtocolTypes>>,
        matcher: Option<TlsQueryMatcher>,
        source: &'a Source,
    ) -> Result<(), Error> {
        knowledges.push(Knowledge {
            source,
            matcher,
            data: self,
        });
        knowledges.push(Knowledge {
            source,
            matcher,
            data: &self.0,
        });
        Ok(())
    }
}

impl ExtractKnowledge<TLSProtocolTypes> for ServerKeyExchangePayload {
    fn extract_knowledge<'a>(
        &'a self,
        knowledges: &mut Vec<Knowledge<'a, TLSProtocolTypes>>,
        matcher: Option<TlsQueryMatcher>,
        source: &'a Source,
    ) -> Result<(), Error> {
        knowledges.push(Knowledge {
            source,
            matcher,
            data: self,
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

impl ExtractKnowledge<TLSProtocolTypes> for ECDHEServerKeyExchange {
    fn extract_knowledge<'a>(
        &'a self,
        knowledges: &mut Vec<Knowledge<'a, TLSProtocolTypes>>,
        matcher: Option<TlsQueryMatcher>,
        source: &'a Source,
    ) -> Result<(), Error> {
        knowledges.push(Knowledge {
            source,
            matcher,
            data: self,
        });
        Ok(())
    }
}

impl ExtractKnowledge<TLSProtocolTypes> for Payload {
    fn extract_knowledge<'a>(
        &'a self,
        knowledges: &mut Vec<Knowledge<'a, TLSProtocolTypes>>,
        matcher: Option<TlsQueryMatcher>,
        source: &'a Source,
    ) -> Result<(), Error> {
        knowledges.push(Knowledge {
            source,
            matcher,
            data: self,
        });
        knowledges.push(Knowledge {
            source,
            matcher,
            data: &self.0,
        });
        Ok(())
    }
}

impl ExtractKnowledge<TLSProtocolTypes> for ClientHelloPayload {
    fn extract_knowledge<'a>(
        &'a self,
        knowledges: &mut Vec<Knowledge<'a, TLSProtocolTypes>>,
        matcher: Option<TlsQueryMatcher>,
        source: &'a Source,
    ) -> Result<(), Error> {
        knowledges.push(Knowledge {
            source,
            matcher,
            data: self,
        });
        knowledges.push(Knowledge {
            source,
            matcher,
            data: &self.random,
        });
        knowledges.push(Knowledge {
            source,
            matcher,
            data: &self.session_id,
        });
        knowledges.push(Knowledge {
            source,
            matcher,
            data: &self.client_version,
        });
        knowledges.push(Knowledge {
            source,
            matcher,
            data: &self.extensions,
        });
        knowledges.push(Knowledge {
            source,
            matcher,
            data: &self.compression_methods,
        });
        knowledges.push(Knowledge {
            source,
            matcher,
            data: &self.cipher_suites,
        });

        knowledges.extend(self.extensions.iter().map(|extension| Knowledge {
            source,
            matcher,
            data: extension,
        }));
        knowledges.extend(
            self.compression_methods
                .iter()
                .map(|compression| Knowledge {
                    source,
                    matcher,
                    data: compression,
                }),
        );
        knowledges.extend(self.cipher_suites.iter().map(|cipher_suite| Knowledge {
            source,
            matcher,
            data: cipher_suite,
        }));
        Ok(())
    }
}

impl ExtractKnowledge<TLSProtocolTypes> for NewSessionTicketPayload {
    fn extract_knowledge<'a>(
        &'a self,
        knowledges: &mut Vec<Knowledge<'a, TLSProtocolTypes>>,
        matcher: Option<TlsQueryMatcher>,
        source: &'a Source,
    ) -> Result<(), Error> {
        knowledges.push(Knowledge {
            source,
            matcher,
            data: self,
        });
        knowledges.push(Knowledge {
            source,
            matcher,
            data: &self.lifetime_hint,
        });
        knowledges.push(Knowledge {
            source,
            matcher,
            data: &self.ticket.0,
        });
        Ok(())
    }
}

impl ExtractKnowledge<TLSProtocolTypes> for ServerHelloPayload {
    fn extract_knowledge<'a>(
        &'a self,
        knowledges: &mut Vec<Knowledge<'a, TLSProtocolTypes>>,
        matcher: Option<TlsQueryMatcher>,
        source: &'a Source,
    ) -> Result<(), Error> {
        knowledges.push(Knowledge {
            source,
            matcher,
            data: self,
        });
        knowledges.push(Knowledge {
            source,
            matcher,
            data: &self.random,
        });
        knowledges.push(Knowledge {
            source,
            matcher,
            data: &self.session_id,
        });
        knowledges.push(Knowledge {
            source,
            matcher,
            data: &self.cipher_suite,
        });
        knowledges.push(Knowledge {
            source,
            matcher,
            data: &self.compression_method,
        });
        knowledges.push(Knowledge {
            source,
            matcher,
            data: &self.legacy_version,
        });
        knowledges.push(Knowledge {
            source,
            matcher,
            data: &self.extensions,
        });
        knowledges.extend(self.extensions.iter().map(|extension| Knowledge {
            source,
            matcher,
            data: extension,
        }));
        Ok(())
    }
}

impl ProtocolMessageDeframer<TLSProtocolTypes> for MessageDeframer {
    type OpaqueProtocolMessage = OpaqueMessage;

    fn pop_frame(&mut self) -> Option<OpaqueMessage> {
        self.frames.pop_front()
    }

    fn read(&mut self, rd: &mut dyn std::io::Read) -> std::io::Result<usize> {
        self.read(rd)
    }
}

impl OpaqueProtocolMessage<TLSProtocolTypes> for OpaqueMessage {
    fn debug(&self, info: &str) {
        debug_opaque_message_with_info(info, self);
    }
}

impl ExtractKnowledge<TLSProtocolTypes> for OpaqueMessage {
    fn extract_knowledge<'a>(
        &'a self,
        knowledges: &mut Vec<Knowledge<'a, TLSProtocolTypes>>,
        matcher: Option<TlsQueryMatcher>,
        source: &'a Source,
    ) -> Result<(), Error> {
        knowledges.push(Knowledge {
            source,
            matcher,
            data: self,
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

#[derive(Clone, Debug, Hash)]
pub struct TLSProtocolTypes;

impl ProtocolTypes for TLSProtocolTypes {
    type Matcher = TlsQueryMatcher;

    fn signature() -> &'static Signature {
        &TLS_SIGNATURE
    }
}

impl Display for TLSProtocolTypes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "")
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct TLSProtocolBehavior;

impl ProtocolBehavior for TLSProtocolBehavior {
    type Claim = TlsClaim;
    type OpaqueProtocolMessage = OpaqueMessage;
    type OpaqueProtocolMessageFlight = OpaqueMessageFlight;
    type ProtocolMessage = Message;
    type ProtocolMessageFlight = MessageFlight;
    type ProtocolTypes = TLSProtocolTypes;
    type SecurityViolationPolicy = TlsSecurityViolationPolicy;

    fn create_corpus() -> Vec<(Trace<Self::ProtocolTypes>, &'static str)> {
        create_corpus()
    }
}
