use std::any::{Any, TypeId};

use dyn_clone::DynClone;
use rand;
use rand::random;
use rand::seq::SliceRandom;
use rustls::internal::msgs::base::PayloadU16;
use rustls::internal::msgs::enums::{Compression, NamedGroup, ServerNameType};
use rustls::internal::msgs::handshake::{ClientExtension, KeyShareEntry, Random, ServerExtension, SessionID, HandshakePayload};
use rustls::internal::msgs::handshake::{ServerName, ServerNamePayload};
use rustls::{CipherSuite, ProtocolVersion, SignatureScheme};

use crate::agent::AgentName;
use crate::term::Variable;
use rustls::internal::msgs::message::{Message, MessagePayload};

pub trait AsAny {
    fn as_any(&self) -> &dyn Any;
}

impl<T: Any> AsAny for T {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

pub trait VariableData: AsAny {
    fn clone_box(&self) -> Box<dyn VariableData>;
    fn clone_any_box(&self) -> Box<dyn Any>;
    fn get_type_id(&self) -> TypeId;
}

impl<T: 'static> VariableData for T
where
    T: Clone,
{
    fn clone_box(&self) -> Box<dyn VariableData> {
        Box::new(self.clone())
    }

    fn clone_any_box(&self) -> Box<dyn Any> {
        Box::new(self.clone())
    }

    fn get_type_id(&self) -> TypeId
    {
        self.type_id()
    }
}


pub fn extract_variables(message: &Message) -> Vec<Box<dyn VariableData>> {
    match &message.payload {
        MessagePayload::Alert(alert) => {
            vec![
                Box::new(alert.description.clone()),
                Box::new(alert.level.clone()),
            ]
        }
        MessagePayload::Handshake(hs) => {
            match &hs.payload {
                HandshakePayload::HelloRequest => {
                    vec![Box::new(hs.typ.clone())]
                }
                HandshakePayload::ClientHello(ch) => {
                    let vars: Vec<Box<dyn VariableData>> = vec![
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
                        hs.typ.clone_box(),
                        Box::new(sh.random.clone()),
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
                HandshakePayload::HelloRetryRequest(_) => {
                    todo!()
                }
                HandshakePayload::Certificate(c) => {
                    vec![Box::new(c.clone())]
                }
                HandshakePayload::CertificateTLS13(c) => {
                    // todo ... this is the first message which is not cloneable...
                    /*                    let entries = c.entries.iter().map(|entry: &CertificateEntry| {
                        Box::new(CertificateEntry {
                            cert: entry.cert.clone(),
                            exts: entry.exts.clone()
                        }) as Box<dyn VariableData>
                    });

                    let vars: Vec<Box<dyn VariableData>> =
                        vec![Box::new(c.context.clone()), Box::new(entries)];*/

                    todo!()
                }
                HandshakePayload::ServerKeyExchange(_) => {
                    todo!()
                }
                HandshakePayload::CertificateRequest(_) => {
                    todo!()
                }
                HandshakePayload::CertificateRequestTLS13(_) => {
                    todo!()
                }
                HandshakePayload::CertificateVerify(_) => {
                    todo!()
                }
                HandshakePayload::ServerHelloDone => {
                    todo!()
                }
                HandshakePayload::EarlyData => {
                    todo!()
                }
                HandshakePayload::EndOfEarlyData => {
                    todo!()
                }
                HandshakePayload::ClientKeyExchange(_) => {
                    todo!()
                }
                HandshakePayload::NewSessionTicket(_) => {
                    todo!()
                }
                HandshakePayload::NewSessionTicketTLS13(_) => {
                    todo!()
                }
                HandshakePayload::EncryptedExtensions(ee) => {
                    todo!()
                }
                HandshakePayload::KeyUpdate(_) => {
                    todo!()
                }
                HandshakePayload::Finished(fin) => {
                    todo!()
                }
                HandshakePayload::CertificateStatus(_) => {
                    todo!()
                }
                HandshakePayload::MessageHash(_) => {
                    todo!()
                }
                HandshakePayload::Unknown(_) => {
                    todo!()
                }
            }
        }
        MessagePayload::ChangeCipherSpec(ccs) => {
            vec![]
        }
        MessagePayload::Opaque(opaque) => {
            vec![Box::new(opaque.clone())]
        }
    }
}