use log::debug;
use puffin::{
    algebra::{signature::Signature, Matcher},
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
        rustls::{
            msgs,
            msgs::{
                deframer::MessageDeframer,
                handshake::{HandshakePayload, ServerKeyExchangePayload},
                message::{Message, MessagePayload, OpaqueMessage},
            },
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
        match &self.payload {
            MessagePayload::Alert(alert) => {
                let matcher = TlsQueryMatcher::Alert;

                knowledges.push(Knowledge {
                    source: source.clone(),
                    matcher: Some(matcher),
                    data: Box::new(self.clone()),
                });
                knowledges.push(Knowledge {
                    source: source.clone(),
                    matcher: Some(matcher),
                    data: Box::new(alert.description),
                });
                knowledges.push(Knowledge {
                    source: source.clone(),
                    matcher: Some(matcher),
                    data: Box::new(alert.level),
                });
            }
            MessagePayload::Handshake(hs) => {
                let matcher = TlsQueryMatcher::Handshake(Some(hs.typ));
                knowledges.push(Knowledge {
                    source: source.clone(),
                    matcher: Some(matcher),
                    data: Box::new(self.clone()),
                });
                match &hs.payload {
                    HandshakePayload::HelloRequest => {
                        knowledges.push(Knowledge {
                            source: source.clone(),
                            matcher: Some(matcher),
                            data: Box::new(hs.typ),
                        });
                    }
                    HandshakePayload::ClientHello(ch) => {
                        knowledges.push(Knowledge {
                            source: source.clone(),
                            matcher: Some(matcher),
                            data: Box::new(hs.typ),
                        });
                        knowledges.push(Knowledge {
                            source: source.clone(),
                            matcher: Some(matcher),
                            data: Box::new(ch.random),
                        });
                        knowledges.push(Knowledge {
                            source: source.clone(),
                            matcher: Some(matcher),
                            data: Box::new(ch.session_id),
                        });
                        knowledges.push(Knowledge {
                            source: source.clone(),
                            matcher: Some(matcher),
                            data: Box::new(ch.client_version),
                        });
                        knowledges.push(Knowledge {
                            source: source.clone(),
                            matcher: Some(matcher),
                            data: Box::new(ch.extensions.clone()),
                        });
                        knowledges.push(Knowledge {
                            source: source.clone(),
                            matcher: Some(matcher),
                            data: Box::new(ch.compression_methods.clone()),
                        });
                        knowledges.push(Knowledge {
                            source: source.clone(),
                            matcher: Some(matcher),
                            data: Box::new(ch.cipher_suites.clone()),
                        });

                        knowledges.extend(ch.extensions.iter().map(|extension| Knowledge {
                            source: source.clone(),
                            matcher: Some(matcher),
                            data: Box::new(extension.clone()) as Box<dyn VariableData>,
                        }));
                        knowledges.extend(ch.compression_methods.iter().map(|compression| {
                            Knowledge {
                                source: source.clone(),
                                matcher: Some(matcher),
                                data: Box::new(*compression) as Box<dyn VariableData>,
                            }
                        }));
                        knowledges.extend(ch.cipher_suites.iter().map(|cipher_suite| Knowledge {
                            source: source.clone(),
                            matcher: Some(matcher),
                            data: Box::new(*cipher_suite) as Box<dyn VariableData>,
                        }));
                    }
                    HandshakePayload::ServerHello(sh) => {
                        knowledges.push(Knowledge {
                            source: source.clone(),
                            matcher: Some(matcher),
                            data: Box::new(hs.typ),
                        });
                        knowledges.push(Knowledge {
                            source: source.clone(),
                            matcher: Some(matcher),
                            data: Box::new(sh.random),
                        });
                        knowledges.push(Knowledge {
                            source: source.clone(),
                            matcher: Some(matcher),
                            data: Box::new(sh.session_id),
                        });
                        knowledges.push(Knowledge {
                            source: source.clone(),
                            matcher: Some(matcher),
                            data: Box::new(sh.cipher_suite),
                        });
                        knowledges.push(Knowledge {
                            source: source.clone(),
                            matcher: Some(matcher),
                            data: Box::new(sh.compression_method),
                        });
                        knowledges.push(Knowledge {
                            source: source.clone(),
                            matcher: Some(matcher),
                            data: Box::new(sh.legacy_version),
                        });
                        knowledges.push(Knowledge {
                            source: source.clone(),
                            matcher: Some(matcher),
                            data: Box::new(sh.extensions.clone()),
                        });

                        knowledges.extend(sh.extensions.iter().map(|extension| Knowledge {
                            source: source.clone(),
                            matcher: Some(matcher),
                            data: Box::new(extension.clone()) as Box<dyn VariableData>,
                        }));
                    }
                    HandshakePayload::Certificate(c) => {
                        knowledges.push(Knowledge {
                            source: source.clone(),
                            matcher: Some(matcher),
                            data: Box::new(c.0.clone()),
                        });
                    }
                    HandshakePayload::ServerKeyExchange(ske) => match ske {
                        ServerKeyExchangePayload::ECDHE(ecdhe) => {
                            // this path wont be taken because we do not know the key exchange algorithm
                            // in advance
                            knowledges.push(Knowledge {
                                source: source.clone(),
                                matcher: Some(matcher),
                                data: Box::new(ecdhe.clone()),
                            });
                        }
                        ServerKeyExchangePayload::Unknown(unknown) => {
                            knowledges.push(Knowledge {
                                source: source.clone(),
                                matcher: Some(matcher),
                                data: Box::new(unknown.0.clone()),
                            });
                        }
                    },
                    HandshakePayload::ServerHelloDone => {}
                    HandshakePayload::ClientKeyExchange(cke) => {
                        knowledges.push(Knowledge {
                            source: source.clone(),
                            matcher: Some(matcher),
                            data: Box::new(cke.0.clone()),
                        });
                    }
                    HandshakePayload::NewSessionTicket(ticket) => {
                        knowledges.push(Knowledge {
                            source: source.clone(),
                            matcher: Some(matcher),
                            data: Box::new(ticket.lifetime_hint as u64),
                        });
                        knowledges.push(Knowledge {
                            source: source.clone(),
                            matcher: Some(matcher),
                            data: Box::new(ticket.ticket.0.clone()),
                        });
                    }
                    _ => return Err(Error::Extraction()),
                }
            }
            MessagePayload::ChangeCipherSpec(_ccs) => {}
            MessagePayload::ApplicationData(opaque) => {
                let matcher = TlsQueryMatcher::ApplicationData;
                knowledges.push(Knowledge {
                    source: source.clone(),
                    matcher: Some(matcher),
                    data: Box::new(self.clone()),
                });
                knowledges.push(Knowledge {
                    source: source.clone(),
                    matcher: Some(matcher),
                    data: Box::new(opaque.0.clone()),
                });
            }
            MessagePayload::Heartbeat(h) => {
                let matcher = TlsQueryMatcher::Heartbeat;
                knowledges.push(Knowledge {
                    source: source.clone(),
                    matcher: Some(matcher),
                    data: Box::new(self.clone()),
                });
                knowledges.push(Knowledge {
                    source: source.clone(),
                    matcher: Some(matcher),
                    data: Box::new(h.payload.0.clone()),
                });
            }
            MessagePayload::TLS12EncryptedHandshake(tls12encrypted) => {
                let matcher = TlsQueryMatcher::Handshake(None);
                knowledges.push(Knowledge {
                    source: source.clone(),
                    matcher: Some(matcher),
                    data: Box::new(self.clone()),
                });
                knowledges.push(Knowledge {
                    source: source.clone(),
                    matcher: Some(matcher),
                    data: Box::new(tls12encrypted.0.clone()),
                });
            }
        }
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
}
