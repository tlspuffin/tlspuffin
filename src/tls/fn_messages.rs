use rustls::internal::msgs::enums::{AlertDescription, AlertLevel};
use rustls::internal::msgs::message::OpaqueMessage;
use rustls::msgs::alert::AlertMessagePayload;

use rustls::{
    internal::msgs::{
        base::Payload,
        ccs::ChangeCipherSpecPayload,
        enums::{
            Compression,
            ContentType::{Handshake},
            HandshakeType, ServerNameType,
        },
        handshake::{
            CertificatePayload, ClientExtension, ClientHelloPayload, HandshakeMessagePayload,
            HandshakePayload, HandshakePayload::Certificate, KeyShareEntry, Random,
            ServerExtension, ServerHelloPayload, ServerKeyExchangePayload, ServerName,
            ServerNamePayload, SessionID,
        },
        message::{Message, MessagePayload},
    },
    kx, tls12, CipherSuite, NoKeyLog, ProtocolVersion, SignatureScheme, SupportedCipherSuite,
    ALL_KX_GROUPS,
};
use HandshakePayload::EncryptedExtensions;
use super::NoneError;

// ----
// TLS 1.3 Message constructors (Return type is message)
// ----

pub fn fn_alert_close_notify() -> Result<Message, NoneError> {
    Ok(Message {
        version: ProtocolVersion::TLSv1_2, // todo this is not controllable
        payload: MessagePayload::Alert(AlertMessagePayload {
            level: AlertLevel::Warning,
            description: AlertDescription::CloseNotify,
        }),
    })
}

pub fn fn_client_hello(
    client_version: &ProtocolVersion,
    random: &Random,
    session_id: &SessionID,
    cipher_suites: &Vec<CipherSuite>,
    compression_methods: &Vec<Compression>,
    extensions: &Vec<ClientExtension>,
) -> Result<Message, NoneError> {
    Ok(Message {
        version: ProtocolVersion::TLSv1_2, // todo this is not controllable
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::ClientHello,
            payload: HandshakePayload::ClientHello(ClientHelloPayload {
                client_version: client_version.clone(),
                random: random.clone(),
                session_id: session_id.clone(),
                cipher_suites: cipher_suites.clone(),
                compression_methods: compression_methods.clone(),
                extensions: extensions.clone(),
            }),
        }),
    })
}

pub fn fn_server_hello(
    legacy_version: &ProtocolVersion,
    random: &Random,
    session_id: &SessionID,
    cipher_suite: &CipherSuite,
    compression_method: &Compression,
    extensions: &Vec<ServerExtension>,
) -> Result<Message, NoneError> {
    Ok(Message {
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::ServerHello,
            payload: HandshakePayload::ServerHello(ServerHelloPayload {
                legacy_version: legacy_version.clone(),
                random: random.clone(),
                session_id: session_id.clone(),
                cipher_suite: cipher_suite.clone(),
                compression_method: compression_method.clone(),
                extensions: extensions.clone(),
            }),
        }),
    })
}

pub fn fn_change_cipher_spec() -> Result<Message, NoneError> {
    Ok(Message {
        version: ProtocolVersion::TLSv1_2, // todo this is not controllable
        payload: MessagePayload::ChangeCipherSpec(ChangeCipherSpecPayload {}),
    })
}

pub fn fn_application_data(data: &Vec<u8>) -> Result<Message, NoneError> {
    Ok(Message {
        version: ProtocolVersion::TLSv1_2, // todo this is not controllable
        payload: MessagePayload::ApplicationData(Payload::new(data.clone())),
    })
}

// ----
// TLS 1.3 Unused
// ----

pub fn fn_encrypted_certificate(
    server_extensions: &Vec<ServerExtension>,
) -> Result<Message, NoneError> {
    Ok(Message {
        version: ProtocolVersion::TLSv1_2, // todo this is not controllable
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::EncryptedExtensions,
            payload: EncryptedExtensions(server_extensions.clone()),
        }),
    })
}

pub fn fn_certificate(certificate: &CertificatePayload) -> Result<Message, NoneError> {
    Ok(Message {
        version: ProtocolVersion::TLSv1_2, // todo this is not controllable
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::Certificate,
            payload: Certificate(certificate.clone()),
        }),
    })
}

// ----
// seed_client_attacker()
// ----

pub fn fn_finished(verify_data: &Vec<u8>) -> Result<Message, NoneError> {
    Ok(Message {
        version: ProtocolVersion::TLSv1_3, // todo this is not controllable
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::Finished,
            payload: HandshakePayload::Finished(Payload::new(verify_data.clone())),
        }),
    })
}

// ----
// TLS 1.2, all used in seed_successful12
// ----

pub fn fn_server_certificate(certs: &CertificatePayload) -> Result<Message, NoneError> {
    Ok(Message {
        version: ProtocolVersion::TLSv1_2, // todo this is not controllable
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::Certificate,
            payload: HandshakePayload::Certificate(certs.clone()),
        }),
    })
}

pub fn fn_server_key_exchange(data: &Vec<u8>) -> Result<Message, NoneError> {
    Ok(Message {
        version: ProtocolVersion::TLSv1_2, // todo this is not controllable
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::ServerKeyExchange,
            payload: HandshakePayload::ServerKeyExchange(ServerKeyExchangePayload::Unknown(
                Payload::new(data.clone()),
            )),
        }),
    })
}

pub fn fn_server_hello_done() -> Result<Message, NoneError> {
    Ok(Message {
        version: ProtocolVersion::TLSv1_2, // todo this is not controllable
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::ServerHelloDone,
            payload: HandshakePayload::ServerHelloDone,
        }),
    })
}

pub fn fn_client_key_exchange(data: &Vec<u8>) -> Result<Message, NoneError> {
    Ok(Message {
        version: ProtocolVersion::TLSv1_2, // todo this is not controllable
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::ClientKeyExchange,
            payload: HandshakePayload::ClientKeyExchange(Payload::new(data.clone())),
        }),
    })
}

pub fn fn_change_cipher_spec12() -> Result<Message, NoneError> {
    Ok(Message {
        version: ProtocolVersion::TLSv1_2, // todo this is not controllable
        payload: MessagePayload::ChangeCipherSpec(ChangeCipherSpecPayload),
    })
}

pub fn fn_opaque_handshake_message(data: &Vec<u8>) -> Result<OpaqueMessage, NoneError> {
    Ok(OpaqueMessage {
        typ: Handshake,
        version: ProtocolVersion::TLSv1_2, // todo this is not controllable
        payload: Payload::new(data.clone()),
    })
}

// ----
// seed_client_attacker12()
// ----

pub fn fn_finished12(data: &Vec<u8>) -> Result<Message, NoneError> {
    Ok(Message {
        version: ProtocolVersion::TLSv1_2, // todo this is not controllable
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::Finished,
            payload: HandshakePayload::Finished(Payload::new(data.clone())),
        }),
    })
}
