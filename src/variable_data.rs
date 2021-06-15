use std::any::Any;

use rustls::internal::msgs::handshake::ServerKeyExchangePayload;
use rustls::{
    internal::msgs::{
        enums::Compression,
        handshake::{ClientExtension, HandshakePayload, ServerExtension},
        message::{Message, MessagePayload},
    },
    CipherSuite,
};

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
    fn clone_box_any(&self) -> Box<dyn Any>;
}

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
}

pub fn extract_variables(message: &Message) -> Vec<Box<dyn VariableData>> {
    match &message.payload {
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
                HandshakePayload::HelloRetryRequest(_) => {
                    todo!()
                }
                HandshakePayload::Certificate(c) => {
                    vec![Box::new(message.clone()), Box::new(c.clone())]
                }
                HandshakePayload::CertificateTLS13(_c) => {
                    todo!()
                }
                HandshakePayload::ServerKeyExchange(ske) => match ske {
                    ServerKeyExchangePayload::ECDHE(ecdhe) => {
                        vec![Box::new(message.clone()), Box::new(ecdhe.clone())]
                    }
                    ServerKeyExchangePayload::Unknown(unknown) => {
                        vec![Box::new(message.clone()), Box::new(unknown.0.clone())]
                    }
                },
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
                    vec![Box::new(message.clone())]
                }
                HandshakePayload::EarlyData => {
                    todo!()
                }
                HandshakePayload::EndOfEarlyData => {
                    todo!()
                }
                HandshakePayload::ClientKeyExchange(cke) => {
                    vec![Box::new(message.clone()), Box::new(cke.0.clone())]
                }
                HandshakePayload::NewSessionTicket(ticket) => {
                    vec![
                        Box::new(message.clone()),
                        Box::new(ticket.lifetime_hint),
                        Box::new(ticket.ticket.clone()),
                    ]
                }
                HandshakePayload::NewSessionTicketTLS13(_) => {
                    todo!()
                }
                HandshakePayload::EncryptedExtensions(_ee) => {
                    todo!()
                }
                HandshakePayload::KeyUpdate(_) => {
                    todo!()
                }
                HandshakePayload::Finished(_fin) => {
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
        MessagePayload::ChangeCipherSpec(_ccs) => {
            vec![]
        }
        MessagePayload::ApplicationData(opaque) => {
            vec![Box::new(message.clone()), Box::new(opaque.0.clone())]
        }
        MessagePayload::Heartbeat(_) => {
            todo!()
        }
    }
}
