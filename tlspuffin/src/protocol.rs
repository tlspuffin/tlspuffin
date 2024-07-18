use log::debug;
use puffin::{
    algebra::{signature::Signature, Matcher},
    codec::{Codec, Reader},
    protocol::{
        ExtractKnowledge, OpaqueProtocolMessage, OpaqueProtocolMessageFlight, ProtocolBehavior,
        ProtocolMessage, ProtocolMessageDeframer, ProtocolMessageFlight,
    },
    trace::{Extractable, Knowledge, KnowledgeStackItem, Source, Trace},
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
            message::{Message, MessagePayload, OpaqueMessage},
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
    fn extract_knowledge<'a>(
        &'a self,
        matcher: Option<TlsQueryMatcher>,
        source: &'a Source,
    ) -> Vec<puffin::trace::KnowledgeStackItem<'a, TlsQueryMatcher>> {
        let mut k = Vec::with_capacity(1 + self.messages.len());
        k.push(KnowledgeStackItem::Knowledge(Knowledge {
            source,
            matcher,
            data: self,
        }));

        for msg in &self.messages {
            k.push(KnowledgeStackItem::Extractable(Extractable {
                source,
                matcher,
                data: msg,
            }))
        }

        k
    }
}

impl ExtractKnowledge<TlsQueryMatcher> for OpaqueMessageFlight {
    fn extract_knowledge<'a>(
        &'a self,
        matcher: Option<TlsQueryMatcher>,
        source: &'a Source,
    ) -> Vec<puffin::trace::KnowledgeStackItem<'a, TlsQueryMatcher>> {
        let mut k = Vec::with_capacity(1 + self.messages.len());
        k.push(KnowledgeStackItem::Knowledge(Knowledge {
            source,
            matcher,
            data: self,
        }));

        for msg in &self.messages {
            k.push(KnowledgeStackItem::Extractable(Extractable {
                source,
                matcher,
                data: msg,
            }))
        }

        k
    }
}

impl ExtractKnowledge<TlsQueryMatcher> for Message {
    fn extract_knowledge<'a>(
        &'a self,
        _matcher: Option<TlsQueryMatcher>,
        source: &'a Source,
    ) -> Vec<puffin::trace::KnowledgeStackItem<'a, TlsQueryMatcher>> {
        let matcher = match &self.payload {
            MessagePayload::Alert(_) => Some(TlsQueryMatcher::Alert),
            MessagePayload::Handshake(hs) => Some(TlsQueryMatcher::Handshake(Some(hs.typ))),
            MessagePayload::ChangeCipherSpec(_) => None,
            MessagePayload::ApplicationData(_) => Some(TlsQueryMatcher::ApplicationData),
            MessagePayload::Heartbeat(_) => Some(TlsQueryMatcher::Heartbeat),
            MessagePayload::TLS12EncryptedHandshake(_) => Some(TlsQueryMatcher::Handshake(None)),
        };

        vec![
            KnowledgeStackItem::Knowledge(Knowledge {
                source,
                matcher,
                data: self,
            }),
            KnowledgeStackItem::Extractable(Extractable {
                source,
                matcher,
                data: &self.payload,
            }),
        ]
    }
}

impl ExtractKnowledge<TlsQueryMatcher> for MessagePayload {
    fn extract_knowledge<'a>(
        &'a self,
        matcher: Option<TlsQueryMatcher>,
        source: &'a Source,
    ) -> Vec<puffin::trace::KnowledgeStackItem<'a, TlsQueryMatcher>> {
        vec![
            KnowledgeStackItem::Knowledge(Knowledge {
                source,
                matcher,
                data: self,
            }),
            KnowledgeStackItem::Extractable(Extractable {
                source,
                matcher,
                data: match &self {
                    MessagePayload::Alert(alert) => alert,
                    MessagePayload::Handshake(hs) => hs,
                    MessagePayload::ChangeCipherSpec(ccs) => ccs,
                    MessagePayload::ApplicationData(opaque) => opaque,
                    MessagePayload::Heartbeat(h) => h,
                    MessagePayload::TLS12EncryptedHandshake(tls12encrypted) => tls12encrypted,
                },
            }),
        ]
    }
}

impl ExtractKnowledge<TlsQueryMatcher> for ChangeCipherSpecPayload {
    fn extract_knowledge<'a>(
        &'a self,
        matcher: Option<TlsQueryMatcher>,
        source: &'a Source,
    ) -> Vec<puffin::trace::KnowledgeStackItem<'a, TlsQueryMatcher>> {
        vec![KnowledgeStackItem::Knowledge(Knowledge {
            source,
            matcher,
            data: self,
        })]
    }
}
impl ExtractKnowledge<TlsQueryMatcher> for HeartbeatPayload {
    fn extract_knowledge<'a>(
        &'a self,
        matcher: Option<TlsQueryMatcher>,
        source: &'a Source,
    ) -> Vec<puffin::trace::KnowledgeStackItem<'a, TlsQueryMatcher>> {
        vec![
            KnowledgeStackItem::Knowledge(Knowledge {
                source,
                matcher,
                data: self,
            }),
            KnowledgeStackItem::Knowledge(Knowledge {
                source,
                matcher,
                data: &self.payload.0,
            }),
        ]
    }
}

impl ExtractKnowledge<TlsQueryMatcher> for AlertMessagePayload {
    fn extract_knowledge<'a>(
        &'a self,
        matcher: Option<TlsQueryMatcher>,
        source: &'a Source,
    ) -> Vec<puffin::trace::KnowledgeStackItem<'a, TlsQueryMatcher>> {
        vec![
            KnowledgeStackItem::Knowledge(Knowledge {
                source,
                matcher,
                data: self,
            }),
            KnowledgeStackItem::Knowledge(Knowledge {
                source,
                matcher,
                data: &self.description,
            }),
            KnowledgeStackItem::Knowledge(Knowledge {
                source,
                matcher,
                data: &self.level,
            }),
        ]
    }
}

impl ExtractKnowledge<TlsQueryMatcher> for HandshakeMessagePayload {
    fn extract_knowledge<'a>(
        &'a self,
        matcher: Option<TlsQueryMatcher>,
        source: &'a Source,
    ) -> Vec<puffin::trace::KnowledgeStackItem<'a, TlsQueryMatcher>> {
        vec![
            KnowledgeStackItem::Knowledge(Knowledge {
                source,
                matcher,
                data: self,
            }),
            KnowledgeStackItem::Knowledge(Knowledge {
                source,
                matcher,
                data: &self.typ,
            }),
            KnowledgeStackItem::Extractable(Extractable {
                source,
                matcher,
                data: &self.payload,
            }),
        ]
    }
}

impl ExtractKnowledge<TlsQueryMatcher> for HandshakePayload {
    fn extract_knowledge<'a>(
        &'a self,
        matcher: Option<TlsQueryMatcher>,
        source: &'a Source,
    ) -> Vec<puffin::trace::KnowledgeStackItem<'a, TlsQueryMatcher>> {
        let mut k = Vec::with_capacity(2);
        k.push(KnowledgeStackItem::Knowledge(Knowledge {
            source,
            matcher,
            data: self,
        }));

        if let Some(x) = match &self {
            HandshakePayload::HelloRequest => None,
            HandshakePayload::ClientHello(ch) => Some(ch as &dyn ExtractKnowledge<TlsQueryMatcher>),
            HandshakePayload::ServerHello(sh) => Some(sh as &dyn ExtractKnowledge<TlsQueryMatcher>),
            HandshakePayload::Certificate(c) => Some(c as &dyn ExtractKnowledge<TlsQueryMatcher>),
            HandshakePayload::ServerKeyExchange(ske) => {
                Some(ske as &dyn ExtractKnowledge<TlsQueryMatcher>)
            }
            HandshakePayload::ServerHelloDone => None,
            HandshakePayload::ClientKeyExchange(cke) => {
                Some(cke as &dyn ExtractKnowledge<TlsQueryMatcher>)
            }
            HandshakePayload::NewSessionTicket(ticket) => {
                Some(ticket as &dyn ExtractKnowledge<TlsQueryMatcher>)
            }
            _ => None,
        } {
            k.push(KnowledgeStackItem::Extractable(Extractable {
                source,
                matcher,
                data: x,
            }));
        }
        k
    }
}

impl ExtractKnowledge<TlsQueryMatcher> for CertificatePayload {
    fn extract_knowledge<'a>(
        &'a self,
        matcher: Option<TlsQueryMatcher>,
        source: &'a Source,
    ) -> Vec<puffin::trace::KnowledgeStackItem<'a, TlsQueryMatcher>> {
        vec![
            KnowledgeStackItem::Knowledge(Knowledge {
                source,
                matcher,
                data: self,
            }),
            KnowledgeStackItem::Knowledge(Knowledge {
                source,
                matcher,
                data: &self.0,
            }),
        ]
    }
}

impl ExtractKnowledge<TlsQueryMatcher> for ServerKeyExchangePayload {
    fn extract_knowledge<'a>(
        &'a self,
        matcher: Option<TlsQueryMatcher>,
        source: &'a Source,
    ) -> Vec<puffin::trace::KnowledgeStackItem<'a, TlsQueryMatcher>> {
        vec![
            KnowledgeStackItem::Knowledge(Knowledge {
                source,
                matcher,
                data: self,
            }),
            KnowledgeStackItem::Extractable(Extractable {
                source,
                matcher,
                data: match self {
                    ServerKeyExchangePayload::ECDHE(ecdhe) => ecdhe,
                    ServerKeyExchangePayload::Unknown(unknown) => unknown,
                },
            }),
        ]
    }
}

impl ExtractKnowledge<TlsQueryMatcher> for ECDHEServerKeyExchange {
    fn extract_knowledge<'a>(
        &'a self,
        matcher: Option<TlsQueryMatcher>,
        source: &'a Source,
    ) -> Vec<puffin::trace::KnowledgeStackItem<'a, TlsQueryMatcher>> {
        vec![KnowledgeStackItem::Knowledge(Knowledge {
            source,
            matcher,
            data: self,
        })]
    }
}

impl ExtractKnowledge<TlsQueryMatcher> for Payload {
    fn extract_knowledge<'a>(
        &'a self,
        matcher: Option<TlsQueryMatcher>,
        source: &'a Source,
    ) -> Vec<puffin::trace::KnowledgeStackItem<'a, TlsQueryMatcher>> {
        vec![
            KnowledgeStackItem::Knowledge(Knowledge {
                source,
                matcher,
                data: self,
            }),
            KnowledgeStackItem::Knowledge(Knowledge {
                source,
                matcher,
                data: &self.0,
            }),
        ]
    }
}

impl ExtractKnowledge<TlsQueryMatcher> for ClientHelloPayload {
    fn extract_knowledge<'a>(
        &'a self,
        matcher: Option<TlsQueryMatcher>,
        source: &'a Source,
    ) -> Vec<puffin::trace::KnowledgeStackItem<'a, TlsQueryMatcher>> {
        let mut k = Vec::with_capacity(
            7 + self.extensions.len() + self.compression_methods.len() + self.cipher_suites.len(),
        );
        k.push(KnowledgeStackItem::Knowledge(Knowledge {
            source,
            matcher,
            data: self,
        }));
        k.push(KnowledgeStackItem::Knowledge(Knowledge {
            source,
            matcher,
            data: &self.random,
        }));
        k.push(KnowledgeStackItem::Knowledge(Knowledge {
            source,
            matcher,
            data: &self.session_id,
        }));
        k.push(KnowledgeStackItem::Knowledge(Knowledge {
            source,
            matcher,
            data: &self.client_version,
        }));
        k.push(KnowledgeStackItem::Knowledge(Knowledge {
            source,
            matcher,
            data: &self.extensions,
        }));
        k.push(KnowledgeStackItem::Knowledge(Knowledge {
            source,
            matcher,
            data: &self.compression_methods,
        }));
        k.push(KnowledgeStackItem::Knowledge(Knowledge {
            source,
            matcher,
            data: &self.cipher_suites,
        }));

        k.extend(self.extensions.iter().map(|extension| {
            KnowledgeStackItem::Knowledge(Knowledge {
                source,
                matcher,
                data: extension,
            })
        }));
        k.extend(self.compression_methods.iter().map(|compression| {
            KnowledgeStackItem::Knowledge(Knowledge {
                source,
                matcher,
                data: compression,
            })
        }));
        k.extend(self.cipher_suites.iter().map(|cipher_suite| {
            KnowledgeStackItem::Knowledge(Knowledge {
                source,
                matcher,
                data: cipher_suite,
            })
        }));
        k
    }
}

impl ExtractKnowledge<TlsQueryMatcher> for NewSessionTicketPayload {
    fn extract_knowledge<'a>(
        &'a self,
        matcher: Option<TlsQueryMatcher>,
        source: &'a Source,
    ) -> Vec<puffin::trace::KnowledgeStackItem<'a, TlsQueryMatcher>> {
        vec![
            KnowledgeStackItem::Knowledge(Knowledge {
                source,
                matcher,
                data: self,
            }),
            KnowledgeStackItem::Knowledge(Knowledge {
                source,
                matcher,
                data: &self.lifetime_hint,
            }),
            KnowledgeStackItem::Knowledge(Knowledge {
                source,
                matcher,
                data: &self.ticket.0,
            }),
        ]
    }
}

impl ExtractKnowledge<TlsQueryMatcher> for ServerHelloPayload {
    fn extract_knowledge<'a>(
        &'a self,
        matcher: Option<TlsQueryMatcher>,
        source: &'a Source,
    ) -> Vec<puffin::trace::KnowledgeStackItem<'a, TlsQueryMatcher>> {
        let mut k = Vec::with_capacity(7 + self.extensions.len());
        k.push(KnowledgeStackItem::Knowledge(Knowledge {
            source,
            matcher,
            data: self,
        }));
        k.push(KnowledgeStackItem::Knowledge(Knowledge {
            source,
            matcher,
            data: &self.random,
        }));
        k.push(KnowledgeStackItem::Knowledge(Knowledge {
            source,
            matcher,
            data: &self.session_id,
        }));
        k.push(KnowledgeStackItem::Knowledge(Knowledge {
            source,
            matcher,
            data: &self.cipher_suite,
        }));
        k.push(KnowledgeStackItem::Knowledge(Knowledge {
            source,
            matcher,
            data: &self.compression_method,
        }));
        k.push(KnowledgeStackItem::Knowledge(Knowledge {
            source,
            matcher,
            data: &self.legacy_version,
        }));
        k.push(KnowledgeStackItem::Knowledge(Knowledge {
            source,
            matcher,
            data: &self.extensions,
        }));
        k.extend(self.extensions.iter().map(|extension| {
            KnowledgeStackItem::Knowledge(Knowledge {
                source,
                matcher,
                data: extension,
            })
        }));
        k
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
    fn extract_knowledge<'a>(
        &'a self,
        matcher: Option<TlsQueryMatcher>,
        source: &'a Source,
    ) -> Vec<puffin::trace::KnowledgeStackItem<'a, TlsQueryMatcher>> {
        vec![KnowledgeStackItem::Knowledge(Knowledge {
            source,
            matcher,
            data: self,
        })]
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
}
