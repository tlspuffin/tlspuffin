use puffin::algebra::ConcreteMessage;
use puffin::{
    algebra::{signature::Signature, Matcher},
    error::Error,
    protocol::{OpaqueProtocolMessage, ProtocolBehavior, ProtocolMessage, ProtocolMessageDeframer},
    put_registry::PutRegistry,
    trace::Trace,
    variable_data::VariableData,
};
use std::any::{Any, TypeId};

use crate::tls::rustls::msgs::message::{any_get_encoding, try_read_bytes};
use crate::{
    claims::TlsClaim,
    debug::{debug_message_with_info, debug_opaque_message_with_info},
    put_registry::TLS_PUT_REGISTRY,
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

impl ProtocolMessage<OpaqueMessage> for Message {
    fn create_opaque(&self) -> OpaqueMessage {
        msgs::message::PlainMessage::from(self.clone()).into_unencrypted_opaque()
    }
    fn debug(&self, info: &str) {
        debug_message_with_info(info, self);
    }

    /// Extracts knowledge from a [`rustls::msgs::message::Message`]. Only plaintext messages yield more
    /// knowledge than their binary payload. If a message is an ApplicationData (TLS 1.3) or an encrypted
    /// Heartbeet or Handhake message (TLS 1.2), then only the message itself and the binary payload is
    /// returned.
    fn extract_knowledge(&self) -> Result<Vec<Box<dyn VariableData>>, Error> {
        Ok(match &self.payload {
            MessagePayload::Alert(alert) => {
                vec![
                    Box::new(self.clone()),
                    Box::new(alert.description),
                    Box::new(alert.level),
                ]
            }
            MessagePayload::Handshake(hs) => {
                match &hs.payload {
                    HandshakePayload::HelloRequest => {
                        vec![Box::new(self.clone()), Box::new(hs.typ)]
                    }
                    HandshakePayload::ClientHello(ch) => {
                        let vars: Vec<Box<dyn VariableData>> = vec![
                            Box::new(self.clone()),
                            Box::new(hs.typ),
                            Box::new(ch.random),
                            Box::new(ch.session_id),
                            Box::new(ch.client_version),
                            Box::new(ch.extensions.clone()),
                            Box::new(ch.compression_methods.clone()),
                            Box::new(ch.cipher_suites.clone()),
                        ];

                        let extensions = ch
                            .extensions
                            .iter()
                            .map(|extension| Box::new(extension.clone()) as Box<dyn VariableData>);
                        let compression_methods = ch
                            .compression_methods
                            .iter()
                            .map(|compression| Box::new(*compression) as Box<dyn VariableData>);
                        let cipher_suites = ch
                            .cipher_suites
                            .iter()
                            .map(|cipher_suite| Box::new(*cipher_suite) as Box<dyn VariableData>);

                        vars.into_iter()
                            .chain(extensions) // also add all extensions individually
                            .chain(compression_methods)
                            .chain(cipher_suites)
                            .collect::<Vec<Box<dyn VariableData>>>()
                    }
                    HandshakePayload::ServerHello(sh) => {
                        let vars: Vec<Box<dyn VariableData>> = vec![
                            Box::new(self.clone()),
                            Box::new(hs.typ),
                            Box::new(sh.random),
                            Box::new(sh.session_id),
                            Box::new(sh.cipher_suite),
                            Box::new(sh.compression_method),
                            Box::new(sh.legacy_version),
                            Box::new(sh.extensions.clone()),
                        ];

                        let server_extensions = sh.extensions.iter().map(|extension| {
                            Box::new(extension.clone()) as Box<dyn VariableData>
                            // it is important to cast here: https://stackoverflow.com/questions/48180008/how-can-i-box-the-contents-of-an-iterator-of-a-type-that-implements-a-trait
                        });

                        vars.into_iter()
                            .chain(server_extensions)
                            .collect::<Vec<Box<dyn VariableData>>>()
                    }
                    HandshakePayload::Certificate(c) => {
                        vec![Box::new(self.clone()), Box::new(c.0.clone())]
                    }
                    HandshakePayload::ServerKeyExchange(ske) => match ske {
                        ServerKeyExchangePayload::ECDHE(ecdhe) => {
                            // this path wont be taken because we do not know the key exchange algorithm
                            // in advance
                            vec![Box::new(self.clone()), Box::new(ecdhe.clone())]
                        }
                        ServerKeyExchangePayload::Unknown(unknown) => {
                            vec![Box::new(self.clone()), Box::new(unknown.0.clone())]
                        }
                    },
                    HandshakePayload::ServerHelloDone => {
                        vec![Box::new(self.clone())]
                    }
                    HandshakePayload::ClientKeyExchange(cke) => {
                        vec![Box::new(self.clone()), Box::new(cke.0.clone())]
                    }
                    HandshakePayload::NewSessionTicket(ticket) => {
                        vec![
                            Box::new(self.clone()),
                            Box::new(ticket.lifetime_hint as u64),
                            Box::new(ticket.ticket.0.clone()),
                        ]
                    }
                    _ => return Err(Error::Extraction()),
                }
            }
            MessagePayload::ChangeCipherSpec(_ccs) => {
                vec![]
            }
            MessagePayload::ApplicationData(opaque) => {
                vec![Box::new(self.clone()), Box::new(opaque.0.clone())]
            }
            MessagePayload::Heartbeat(h) => {
                vec![Box::new(self.clone()), Box::new(h.payload.clone())]
            }
            MessagePayload::TLS12EncryptedHandshake(tls12encrypted) => {
                vec![Box::new(self.clone()), Box::new(tls12encrypted.0.clone())]
            }
        })
    }
}

impl ProtocolMessageDeframer for MessageDeframer {
    type OpaqueProtocolMessage = OpaqueMessage;

    fn pop_frame(&mut self) -> Option<OpaqueMessage> {
        self.frames.pop_front()
    }
    fn read(&mut self, rd: &mut dyn std::io::Read) -> std::io::Result<usize> {
        self.read(rd)
    }
}

impl OpaqueProtocolMessage for OpaqueMessage {
    fn debug(&self, info: &str) {
        debug_opaque_message_with_info(info, self);
    }

    fn extract_knowledge(&self) -> Result<Vec<Box<dyn VariableData>>, Error> {
        Ok(vec![Box::new(self.clone())])
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
    type ProtocolMessage = Message;
    type OpaqueProtocolMessage = OpaqueMessage;
    type Matcher = TlsQueryMatcher;

    fn signature() -> &'static Signature {
        &TLS_SIGNATURE
    }

    fn registry() -> &'static PutRegistry<Self> {
        &TLS_PUT_REGISTRY
    }

    fn create_corpus() -> Vec<(Trace<Self::Matcher>, &'static str)> {
        create_corpus()
    }

    fn any_get_encoding(message: &Box<dyn Any>) -> Result<ConcreteMessage, Error> {
        any_get_encoding(message)
    }

    fn try_read_bytes(bitstring: ConcreteMessage, ty: TypeId) -> Result<Box<dyn Any>, Error> {
        Ok(try_read_bytes(bitstring, ty)?)
    }
}
