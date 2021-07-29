//! Definition of the VariableData trait. A VariableData can contain any data which has a `'static`
//! type. This is true for [`rustls::msgs::message::Message`] for example.

use std::any::{Any, TypeId};

use crate::error::Error;
use rustls::msgs::handshake::ServerKeyExchangePayload;
use rustls::{
    internal::msgs::{
        enums::Compression,
        handshake::{ClientExtension, HandshakePayload, ServerExtension},
        message::{Message, MessagePayload},
    },
    CipherSuite,
};

pub trait VariableData {
    fn clone_box(&self) -> Box<dyn VariableData>;
    fn clone_box_any(&self) -> Box<dyn Any>;
    fn type_id(&self) -> TypeId;
    fn type_name(&self) -> &'static str;
}

/// A VariableData is cloneable and has a `'static` type. This data type is used throughout
/// tlspuffin to handle data of dynamic size.
impl<T: 'static> VariableData for T
where
    T: Clone,
{
    fn clone_box(&self) -> Box<dyn VariableData> {
        Box::new(self.clone())
    }

    fn clone_box_any(&self) -> Box<dyn Any> {
        Box::new(self.clone())
    }

    fn type_id(&self) -> TypeId {
        Any::type_id(self)
    }

    fn type_name(&self) -> &'static str {
        std::any::type_name::<T>()
    }
}

/// Extracts knowledge from a [`rustls::msgs::message::Message`]. Only plaintext messages yield more
/// knowledge than their binary payload. If a message is an ApplicationData (TLS 1.3) or an encrypted
/// Heartbeet or Handhake message (TLS 1.2), then only the message itself and the binary payload is
/// returned.
pub fn extract_knowledge(message: &Message) -> Result<Vec<Box<dyn VariableData>>, Error> {
    Ok(match &message.payload {
        MessagePayload::Alert(alert) => {
            vec![
                Box::new(message.clone()),
                Box::new(alert.description.clone()),
                Box::new(alert.level.clone()),
            ]
        }
        MessagePayload::Handshake(hs) => {
            match &hs.payload {
                HandshakePayload::HelloRequest => {
                    vec![Box::new(message.clone()), Box::new(hs.typ.clone())]
                }
                HandshakePayload::ClientHello(ch) => {
                    let vars: Vec<Box<dyn VariableData>> = vec![
                        Box::new(message.clone()),
                        Box::new(hs.typ.clone()),
                        Box::new(ch.random.clone()),
                        Box::new(ch.session_id.clone()),
                        Box::new(ch.client_version.clone()),
                        Box::new(ch.extensions.clone()),
                        Box::new(ch.compression_methods.clone()),
                        Box::new(ch.cipher_suites.clone()),
                    ];

                    let extensions = ch.extensions.iter().map(|extension: &ClientExtension| {
                        Box::new(extension.clone()) as Box<dyn VariableData>
                    });
                    let compression_methods =
                        ch.compression_methods
                            .iter()
                            .map(|compression: &Compression| {
                                Box::new(compression.clone()) as Box<dyn VariableData>
                            });
                    let cipher_suites =
                        ch.cipher_suites.iter().map(|cipher_suite: &CipherSuite| {
                            Box::new(cipher_suite.clone()) as Box<dyn VariableData>
                        });

                    vars.into_iter()
                        .chain(extensions) // also add all extensions individually
                        .chain(compression_methods)
                        .chain(cipher_suites)
                        .collect::<Vec<Box<dyn VariableData>>>()
                }
                HandshakePayload::ServerHello(sh) => {
                    let vars: Vec<Box<dyn VariableData>> = vec![
                        Box::new(message.clone()),
                        hs.typ.clone_box(),
                        Box::new(sh.random.clone()),
                        Box::new(sh.session_id.clone()),
                        Box::new(sh.cipher_suite.clone()),
                        Box::new(sh.compression_method.clone()),
                        Box::new(sh.legacy_version.clone()),
                        Box::new(sh.extensions.clone()),
                    ];

                    let server_extensions =
                        sh.extensions.iter().map(|extension: &ServerExtension| {
                            Box::new(extension.clone()) as Box<dyn VariableData>
                            // it is important to cast here: https://stackoverflow.com/questions/48180008/how-can-i-box-the-contents-of-an-iterator-of-a-type-that-implements-a-trait
                        });

                    vars.into_iter()
                        .chain(server_extensions)
                        .collect::<Vec<Box<dyn VariableData>>>()
                }
                HandshakePayload::Certificate(c) => {
                    vec![Box::new(message.clone()), Box::new(c.clone())]
                }
                HandshakePayload::ServerKeyExchange(ske) => match ske {
                    ServerKeyExchangePayload::ECDHE(ecdhe) => {
                        // this path wont be taken because we do not know the key exchange algorithm
                        // in advance
                        vec![Box::new(message.clone()), Box::new(ecdhe.clone())]
                    }
                    ServerKeyExchangePayload::Unknown(unknown) => {
                        vec![Box::new(message.clone()), Box::new(unknown.0.clone())]
                    }
                },
                HandshakePayload::ServerHelloDone => {
                    vec![Box::new(message.clone())]
                }
                HandshakePayload::ClientKeyExchange(cke) => {
                    vec![Box::new(message.clone()), Box::new(cke.0.clone())]
                }
                HandshakePayload::NewSessionTicket(ticket) => {
                    vec![
                        Box::new(message.clone()),
                        Box::new(ticket.lifetime_hint as u64),
                        Box::new(ticket.ticket.0.clone()),
                    ]
                }
                _ => return Err(Error::Extraction(message.payload.content_type())),
            }
        }
        MessagePayload::ChangeCipherSpec(_ccs) => {
            vec![]
        }
        MessagePayload::ApplicationData(opaque) => {
            vec![Box::new(message.clone()), Box::new(opaque.0.clone())]
        }
        MessagePayload::Heartbeat(h) => {
            vec![Box::new(message.clone()), Box::new(h.payload.clone())]
        }
        MessagePayload::TLS12EncryptedHandshake(tls12encrypted) => {
            vec![
                Box::new(message.clone()),
                Box::new(tls12encrypted.0.clone()),
            ]
        }
    })
}
