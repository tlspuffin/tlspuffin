#![allow(clippy::ptr_arg)]
#![allow(dead_code)]

//! Extensions according to IANA:
//! <https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-7>
//!
//! In the source code all IDs are available, but implementations are missing.
//! Return type is `Message`

use puffin::algebra::error::FnError;

use crate::nyi_fn;
use crate::tls::rustls::msgs::base::{PayloadU16, PayloadU8};
use crate::tls::rustls::msgs::enums::*;
use crate::tls::rustls::msgs::handshake::*;
use crate::tls::rustls::msgs::heartbeat::HeartbeatPayload;
use crate::tls::rustls::msgs::message::{Message, MessagePayload};

// ----
// Alert Message constructors
// https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-6
// ----

// ----
// CCS Message constructors
// ----

// ----
// ApplicationData Message constructors
// ----

// ----
// Heartbeats Message constructors
// https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#heartbeat-message-types
// ----

// ----
// Handshake Message constructors
// ----

nyi_fn! {
    /// hello_verify_request_RESERVED => 0x03,
}

nyi_fn! {
    /// EndOfEarlyData => 0x05,
}

/// Specific ClientHello Random recognized by the client as the one previously used for a
/// HelloRetryRequest
pub fn fn_hello_retry_request_random() -> Result<Random, FnError> {
    Ok(Random([
        0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8,
        0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8,
        0x33, 0x9c,
    ]))
}

/// HelloRetryRequest => 0x06,
pub fn fn_hello_retry_request(
    legacy_version: &ProtocolVersion,
    random: &Random,
    session_id: &SessionID,
    cipher_suite: &CipherSuite,
    compression_methods: &Compressions,
    extensions: &HelloRetryExtensions,
) -> Result<Message, FnError> {
    Ok(Message {
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::HelloRetryRequest,
            payload: HandshakePayload::HelloRetryRequest(HelloRetryRequest {
                legacy_version: *legacy_version,
                random: *random,
                session_id: *session_id,
                cipher_suite: *cipher_suite,
                compression_methods: compression_methods.clone(),
                extensions: extensions.clone(),
            }),
        }),
    })
}
nyi_fn! {
    /// RequestConnectionId => 0x09,
}
nyi_fn! {
    /// NewConnectionId => 0x0a,
}
pub fn fn_certificate_request13(
    context: &PayloadU8,
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
                context: context.clone(),
                extensions: CertReqExtensions(extensions.clone()),
            }),
        }),
    })
}

nyi_fn! {
    /// CertificateURL => 0x15,
}
nyi_fn! {
    /// compressed_certificate => 0x019,
}
nyi_fn! {
    /// ekt_key => 0x01A,
}
