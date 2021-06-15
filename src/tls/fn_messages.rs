//! Extensions according to IANA:
//! https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-7
//!
//! In the source code all IDs are available, but implementations are missing.
//! Return type is `Message`
//!

use rustls::internal::msgs::enums::*;
use rustls::internal::msgs::handshake::{CertificateEntry, CertificateStatus, HelloRetryExtension};
use rustls::internal::msgs::message::OpaqueMessage;
use rustls::msgs::alert::AlertMessagePayload;
use rustls::msgs::base::{PayloadU16, PayloadU24, PayloadU8};
use rustls::{
    internal::msgs::{
        base::Payload,
        ccs::ChangeCipherSpecPayload,
        handshake::*,
        heartbeat::HeartbeatPayload,
        message::{Message, MessagePayload},
    },
    kx, tls12, CipherSuite, NoKeyLog, ProtocolVersion, SignatureScheme, SupportedCipherSuite,
    ALL_KX_GROUPS,
};
use HandshakePayload::EncryptedExtensions;

use crate::nyi_fn;

use super::error::FnError;

/// Used in TLS 1.2 as is has encrypted handshake messages
pub fn fn_opaque_handshake_message(data: &Vec<u8>) -> Result<OpaqueMessage, FnError> {
    Ok(OpaqueMessage {
        typ: ContentType::Handshake,
        version: ProtocolVersion::TLSv1_2,
        payload: Payload::new(data.clone()),
    })
}

// ----
// Alert Message constructors
// https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-6
// ----

pub fn fn_alert_close_notify() -> Result<Message, FnError> {
    Ok(Message {
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::Alert(AlertMessagePayload {
            level: AlertLevel::Warning,
            description: AlertDescription::CloseNotify,
        }),
    })
}

// ----
// CCS Message constructors
// ----

pub fn fn_change_cipher_spec() -> Result<Message, FnError> {
    Ok(Message {
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::ChangeCipherSpec(ChangeCipherSpecPayload {}),
    })
}
// ----
// ApplicationData Message constructors
// ----

pub fn fn_application_data(data: &Vec<u8>) -> Result<Message, FnError> {
    Ok(Message {
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::ApplicationData(Payload::new(data.clone())),
    })
}

// ----
// Heartbeats Message constructors
// https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#heartbeat-message-types
// ----

// todo
pub fn fn_heartbeat() -> Result<Message, FnError> {
    Ok(Message {
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::Heartbeat(HeartbeatPayload {
            typ: HeartbeatMessageType::Request,
            payload: PayloadU16::new(vec![1,3]),
            fake_length: Some(16384)
        }),
    })
}

// ----
// Handshake Message constructors
// ----

/// HelloRequest/hello_request_RESERVED => 0x00,
pub fn fn_hello_request() -> Result<Message, FnError> {
    Ok(Message {
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::HelloRequest,
            payload: HandshakePayload::HelloRequest,
        }),
    })
}
/// ClientHello => 0x01,
pub fn fn_client_hello(
    client_version: &ProtocolVersion,
    random: &Random,
    session_id: &SessionID,
    cipher_suites: &Vec<CipherSuite>,
    compression_methods: &Vec<Compression>,
    extensions: &Vec<ClientExtension>,
) -> Result<Message, FnError> {
    Ok(Message {
        version: ProtocolVersion::TLSv1_2,
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
/// ServerHello => 0x02,
pub fn fn_server_hello(
    legacy_version: &ProtocolVersion,
    random: &Random,
    session_id: &SessionID,
    cipher_suite: &CipherSuite,
    compression_method: &Compression,
    extensions: &Vec<ServerExtension>,
) -> Result<Message, FnError> {
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
/// hello_verify_request_RESERVED => 0x03,
nyi_fn!();
/// NewSessionTicket => 0x04,
pub fn fn_new_session_ticket(ticket: &Vec<u8>) -> Result<Message, FnError> {
    // todo unclear where the arguments come from here, needs manual trace implementation
    Ok(Message {
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::NewSessionTicket,
            payload: HandshakePayload::NewSessionTicket(NewSessionTicketPayload {
                lifetime_hint: 10,
                ticket: PayloadU16::new(ticket.clone()),
            }),
        }),
    })
}
pub fn fn_new_session_ticket13(
    nonce: &Vec<u8>,
    ticket: &Vec<u8>,
    extensions: &Vec<NewSessionTicketExtension>,
) -> Result<Message, FnError> {
    // todo unclear where the arguments come from here, needs manual trace implementation
    Ok(Message {
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::NewSessionTicket,
            payload: HandshakePayload::NewSessionTicketTLS13(NewSessionTicketPayloadTLS13 {
                lifetime: 10,
                age_add: 12,
                nonce: PayloadU8::new(nonce.clone()),
                ticket: PayloadU16::new(ticket.clone()),
                exts: extensions.clone(),
            }),
        }),
    })
}
/// EndOfEarlyData => 0x05,
nyi_fn!();
/// HelloRetryRequest => 0x06,
pub fn fn_hello_retry_request(
    legacy_version: &ProtocolVersion,
    session_id: &SessionID,
    cipher_suite: &CipherSuite,
    extensions: &Vec<HelloRetryExtension>,
) -> Result<Message, FnError> {
    Ok(Message {
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::HelloRetryRequest,
            payload: HandshakePayload::HelloRetryRequest(HelloRetryRequest {
                legacy_version: legacy_version.clone(),
                session_id: session_id.clone(),
                cipher_suite: cipher_suite.clone(),
                extensions: extensions.clone(),
            }),
        }),
    })
}
/// EncryptedExtensions => 0x08,
pub fn fn_encrypted_extensions(
    server_extensions: &Vec<ServerExtension>,
) -> Result<Message, FnError> {
    Ok(Message {
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::EncryptedExtensions,
            payload: EncryptedExtensions(server_extensions.clone()),
        }),
    })
}
/// RequestConnectionId => 0x09,
nyi_fn!();
/// NewConnectionId => 0x0a,
nyi_fn!();
/// Certificate => 0x0b,
pub fn fn_certificate(certs: &CertificatePayload) -> Result<Message, FnError> {
    Ok(Message {
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::Certificate,
            payload: HandshakePayload::Certificate(certs.clone()),
        }),
    })
}
pub fn fn_certificate13(
    context: &Vec<u8>,
    entries: &Vec<CertificateEntry>,
) -> Result<Message, FnError> {
    // todo unclear where the arguments come from here, needs manual trace implementation
    //      Vec<CertificateEntry> is not possible to create
    Ok(Message {
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::Certificate,
            payload: HandshakePayload::CertificateTLS13(CertificatePayloadTLS13 {
                context: PayloadU8::new(context.clone()),
                entries: entries.clone(),
            }),
        }),
    })
}
/// ServerKeyExchange => 0x0c,
pub fn fn_server_key_exchange(data: &Vec<u8>) -> Result<Message, FnError> {
    Ok(Message {
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::ServerKeyExchange,
            payload: HandshakePayload::ServerKeyExchange(ServerKeyExchangePayload::Unknown(
                Payload::new(data.clone()),
            )),
        }),
    })
}
/// CertificateRequest => 0x0d,
pub fn fn_certificate_request() -> Result<Message, FnError> {
    // todo unclear where the arguments come from here, needs manual trace implementation
    Ok(Message {
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::CertificateRequest,
            payload: HandshakePayload::CertificateRequest(CertificateRequestPayload {
                certtypes: vec![ClientCertificateType::RSASign],
                sigschemes: vec![SignatureScheme::ED25519],
                canames: vec![PayloadU16::new("some ca name?".as_bytes().to_vec())],
            }),
        }),
    })
}
pub fn fn_certificate_request13(
    context: &Vec<u8>,
    extensions: &Vec<CertReqExtension>,
) -> Result<Message, FnError> {
    // todo unclear where the arguments come from here, needs manual trace implementation
    //      Vec<CertReqExtension> is not possible to create
    Ok(Message {
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::CertificateRequest,
            payload: HandshakePayload::CertificateRequestTLS13(CertificateRequestPayloadTLS13 {
                context: PayloadU8::new(context.clone()),
                extensions: extensions.clone(),
            }),
        }),
    })
}
/// ServerHelloDone => 0x0e,
pub fn fn_server_hello_done() -> Result<Message, FnError> {
    Ok(Message {
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::ServerHelloDone,
            payload: HandshakePayload::ServerHelloDone,
        }),
    })
}
/// CertificateVerify => 0x0f,
pub fn fn_certificate_verify(signature: &Vec<u8>) -> Result<Message, FnError> {
    // todo unclear where the arguments come from here, needs manual trace implementation
    Ok(Message {
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::CertificateVerify,
            payload: HandshakePayload::CertificateVerify(DigitallySignedStruct {
                scheme: SignatureScheme::ED25519,
                sig: PayloadU16::new(signature.clone()),
            }),
        }),
    })
}
/// ClientKeyExchange => 0x10,
pub fn fn_client_key_exchange(data: &Vec<u8>) -> Result<Message, FnError> {
    Ok(Message {
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::ClientKeyExchange,
            payload: HandshakePayload::ClientKeyExchange(Payload::new(data.clone())),
        }),
    })
}
/// Finished => 0x14,
pub fn fn_finished(verify_data: &Vec<u8>) -> Result<Message, FnError> {
    Ok(Message {
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::Finished,
            payload: HandshakePayload::Finished(Payload::new(verify_data.clone())),
        }),
    })
}
/// CertificateURL => 0x15,
nyi_fn!();
/// CertificateStatus => 0x16,
pub fn fn_certificate_status(ocsp_response: &Vec<u8>) -> Result<Message, FnError> {
    Ok(Message {
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::CertificateStatus,
            payload: HandshakePayload::CertificateStatus(CertificateStatus {
                ocsp_response: PayloadU24::new(ocsp_response.clone()),
            }),
        }),
    })
}
/// KeyUpdate => 0x18,
pub fn fn_key_update() -> Result<Message, FnError> {
    Ok(Message {
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::KeyUpdate,
            payload: HandshakePayload::KeyUpdate(KeyUpdateRequest::UpdateRequested),
        }),
    })
}
pub fn fn_key_update_not_requested() -> Result<Message, FnError> {
    Ok(Message {
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::KeyUpdate,
            payload: HandshakePayload::KeyUpdate(KeyUpdateRequest::UpdateNotRequested),
        }),
    })
}
/// compressed_certificate => 0x019,
nyi_fn!();
/// ekt_key => 0x01A,
nyi_fn!();
/// MessageHash => 0xfe
pub fn fn_message_hash(hash: &Vec<u8>) -> Result<Message, FnError> {
    // todo unclear where the arguments come from here, needs manual trace implementation
    Ok(Message {
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::MessageHash,
            payload: HandshakePayload::MessageHash(Payload::new(hash.clone())),
        }),
    })
}
