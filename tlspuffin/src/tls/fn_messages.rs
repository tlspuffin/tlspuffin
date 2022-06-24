#![allow(clippy::ptr_arg)]
#![allow(dead_code)]

//! Extensions according to IANA:
//! https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-7
//!
//! In the source code all IDs are available, but implementations are missing.
//! Return type is `Message`
//!

use rustls::{
    internal::msgs::{
        base::Payload,
        ccs::ChangeCipherSpecPayload,
        handshake::*,
        heartbeat::HeartbeatPayload,
        message::{Message, MessagePayload},
    },
    msgs::{
        alert::AlertMessagePayload,
        base::{PayloadU16, PayloadU24, PayloadU8},
        enums::*,
        handshake::{CertificateEntry, CertificateStatus, HelloRetryExtension},
        message::OpaqueMessage,
    },
    CipherSuite, ProtocolVersion, SignatureScheme,
};
use HandshakePayload::EncryptedExtensions;

use crate::{nyi_fn, tls::error::FnError};

pub fn fn_opaque_message(message: &OpaqueMessage) -> Result<OpaqueMessage, FnError> {
    Ok(message.clone())
}

pub fn fn_empty_handshake_message() -> Result<OpaqueMessage, FnError> {
    Ok(OpaqueMessage {
        typ: ContentType::Handshake,
        version: ProtocolVersion::TLSv1_2,
        payload: Payload::empty(),
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

// Adapted from https://github.com/mpgn/heartbleed-PoC/blob/master/heartbleed-exploit.py
// unused right now
/*pub fn fn_heartbeat_ch() -> Result<Message, FnError> {
    let hello_client_hex = "
        16 03 03 00  dc 01 00 00 d8 03 03 53
        43 5b 90 9d 9b 72 0b bc  0c bc 2b 92 a8 48 97 cf
        bd 39 04 cc 16 0a 85 03  90 9f 77 04 33 d4 de 00
        00 66 c0 14 c0 0a c0 22  c0 21 00 39 00 38 00 88
        00 87 c0 0f c0 05 00 35  00 84 c0 12 c0 08 c0 1c
        c0 1b 00 16 00 13 c0 0d  c0 03 00 0a c0 13 c0 09
        c0 1f c0 1e 00 33 00 32  00 9a 00 99 00 45 00 44
        c0 0e c0 04 00 2f 00 96  00 41 c0 11 c0 07 c0 0c
        c0 02 00 05 00 04 00 15  00 12 00 09 00 14 00 11
        00 08 00 06 00 03 00 ff  01 00 00 49 00 0b 00 04
        03 00 01 02 00 0a 00 34  00 32 00 0e 00 0d 00 19
        00 0b 00 0c 00 18 00 09  00 0a 00 16 00 17 00 08
        00 06 00 07 00 14 00 15  00 04 00 05 00 12 00 13
        00 01 00 02 00 03 00 0f  00 10 00 11 00 23 00 00
        00 0f 00 01 01";

    let hello_client = hex::decode(
        hello_client_hex
            .to_string()
            .replace(" ", "")
            .replace("\n", ""),
    ).map_err(|err| err.to_string())?;

    Ok(Message::try_from(OpaqueMessage::read(&mut Reader::init(
        hello_client.as_slice(),
    ))?)?)
}*/

pub fn fn_heartbeat_fake_length(payload: &Vec<u8>, fake_length: &u64) -> Result<Message, FnError> {
    Ok(Message {
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::Heartbeat(HeartbeatPayload {
            typ: HeartbeatMessageType::Request,
            payload: PayloadU16::new(payload.clone()),
            fake_length: Some(*fake_length as u16),
        }),
    })
}

pub fn fn_heartbeat(payload: &Vec<u8>) -> Result<Message, FnError> {
    fn_heartbeat_fake_length(payload, &(payload.len() as u64))
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
                client_version: *client_version,
                random: *random,
                session_id: *session_id,
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
                legacy_version: *legacy_version,
                random: *random,
                session_id: *session_id,
                cipher_suite: *cipher_suite,
                compression_method: *compression_method,
                extensions: extensions.clone(),
            }),
        }),
    })
}
/// hello_verify_request_RESERVED => 0x03,
nyi_fn!();
/// NewSessionTicket => 0x04,
pub fn fn_new_session_ticket(lifetime_hint: &u64, ticket: &Vec<u8>) -> Result<Message, FnError> {
    // todo unclear where the arguments come from here, needs manual trace implementation
    //      https://github.com/tlspuffin/tlspuffin/issues/155
    Ok(Message {
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::NewSessionTicket,
            payload: HandshakePayload::NewSessionTicket(NewSessionTicketPayload {
                lifetime_hint: *lifetime_hint as u32,
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
    //      https://github.com/tlspuffin/tlspuffin/issues/155
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
                legacy_version: *legacy_version,
                session_id: *session_id,
                cipher_suite: *cipher_suite,
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
    //      https://github.com/tlspuffin/tlspuffin/issues/155
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
    //      https://github.com/tlspuffin/tlspuffin/issues/155
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
    //      https://github.com/tlspuffin/tlspuffin/issues/155
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
    //      https://github.com/tlspuffin/tlspuffin/issues/155
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
    //      https://github.com/tlspuffin/tlspuffin/issues/155
    Ok(Message {
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::MessageHash,
            payload: HandshakePayload::MessageHash(Payload::new(hash.clone())),
        }),
    })
}
