#![allow(clippy::ptr_arg)]
#![allow(dead_code)]

//! Extensions according to IANA:
//! <https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml>
//!
//! In the source code all IDs are available, but implementations are missing.

use puffin::algebra::error::FnError;

use crate::nyi_fn;
use crate::tls::fn_impl::fn_get_ticket_age_add;
use crate::tls::fn_utils::fn_get_ticket;
use crate::tls::key_exchange::deterministic_key_share;
use crate::tls::rustls::msgs::base::{Payload, PayloadU16};
use crate::tls::rustls::msgs::enums::*;
use crate::tls::rustls::msgs::handshake::*;
use crate::tls::rustls::msgs::message::Message;
use crate::tls::rustls::x509;

// todo ServerExtensions
//      https://gitlab.inria.fr/mammann/tlspuffin/-/issues/57

// todo CertReqExtension
//      https://gitlab.inria.fr/mammann/tlspuffin/-/issues/57

// todo NewSessionTicketExtension
//      https://gitlab.inria.fr/mammann/tlspuffin/-/issues/57

// todo Unknown Extensions for
//      ClientExtension, ServerExtension, HelloRetryExtension, NewSessionTicketExtension
//      https://gitlab.inria.fr/mammann/tlspuffin/-/issues/57

//
// Actual extensions
//

nyi_fn! {
    /// MaxFragmentLength => 0x0001,
}
nyi_fn! {
    /// ClientCertificateUrl => 0x0002,
}
nyi_fn! {
    /// TrustedCAKeys => 0x0003,
}
nyi_fn! {
    /// TruncatedHMAC => 0x0004,
}

nyi_fn! {
    /// UserMapping => 0x0006,
}
nyi_fn! {
    /// ClientAuthz => 0x0007,
}
nyi_fn! {
    /// ServerAuthz => 0x0008,
}
nyi_fn! {
    /// CertificateType => 0x0009,
}

nyi_fn! {
    /// SRP => 0x000c,
}

nyi_fn! {
    /// UseSRTP => 0x000e,
}
nyi_fn! {
    /// Heartbeat => 0x000f,
}
/// ALProtocolNegotiation => 0x0010,
pub fn fn_empty_vec_of_vec() -> Result<Vec<Vec<u8>>, FnError> {
    Ok(vec![])
}
pub fn fn_append_vec(vec_of_vec: &Vec<Vec<u8>>, data: &Vec<u8>) -> Result<Vec<Vec<u8>>, FnError> {
    // todo unclear where the arguments come from here, needs manual trace implementation
    //      https://github.com/tlspuffin/tlspuffin/issues/155
    let mut new = vec_of_vec.clone();
    new.push(data.clone());
    Ok(new)
}
nyi_fn! {
    /// status_request_v2 => 0x0011
}
nyi_fn! {
    /// client_certificate_type => 0x0013,
}
nyi_fn! {
    /// server_certificate_type => 0x0014,
}
nyi_fn! {
    /// Padding => 0x0015,
}
nyi_fn! {
    /// encrypt_then_mac => 0x0016,
}
nyi_fn! {
    /// token_binding => 0x0018,
}
nyi_fn! {
    /// cached_info => 0x0019,
}
nyi_fn! {
    /// tls_lts => 0x001A,
}
nyi_fn! {
    /// compress_certificate => 0x001B,
}
nyi_fn! {
    /// record_size_limit => 0x001C,
}
nyi_fn! {
    /// pwd_protect => 0x001D,
}
nyi_fn! {
    /// pwd_clear => 0x001E,
}
nyi_fn! {
    /// password_salt => 0x001F,
}
nyi_fn! {
    /// ticket_pinning => 0x0020,
}
nyi_fn! {
    /// tls_cert_with_extern_psk => 0x0021,
}
nyi_fn! {
    /// delegated_credentials => 0x0022,
}
/// SessionTicket => 0x0023,
pub fn fn_session_ticket_request_extension() -> Result<ClientExtension, FnError> {
    Ok(ClientExtension::SessionTicket(ClientSessionTicket::Request))
}
pub fn fn_session_ticket_offer_extension(ticket: &Vec<u8>) -> Result<ClientExtension, FnError> {
    // todo unclear where the arguments come from here, needs manual trace implementation
    //      https://github.com/tlspuffin/tlspuffin/issues/155
    Ok(ClientExtension::SessionTicket(ClientSessionTicket::Offer(
        Payload::new(ticket.clone()),
    )))
}
nyi_fn! {
    /// TLMSP => 0x0024,
}
nyi_fn! {
    /// TLMSP_proxying => 0x0025,
}
nyi_fn! {
    /// TLMSP_delegate => 0x0026,
}
nyi_fn! {
    /// supported_ekt_ciphers => 0x0027,
}

pub fn fn_preshared_keys_extension_empty_binder(
    new_ticket: &Message,
) -> Result<ClientExtension, FnError> {
    let ticket: Vec<u8> = fn_get_ticket(new_ticket)?;
    let age_add: u64 = fn_get_ticket_age_add(new_ticket)?;

    let ticket_age_millis: u32 = 100; // 100ms since receiving NewSessionTicket
    let obfuscated_ticket_age = ticket_age_millis.wrapping_add(age_add as u32);

    let resuming_suite = &crate::tls::rustls::tls13::TLS13_AES_128_GCM_SHA256; // todo allow other cipher suites
    let binder_len = resuming_suite.hash_algorithm().output_len;
    let binder = vec![0u8; binder_len];

    let psk_identity = PresharedKeyIdentity::new(ticket, obfuscated_ticket_age);

    Ok(ClientExtension::PresharedKey(PresharedKeyOffer::new(
        psk_identity,
        binder,
    )))
}

nyi_fn! {
    /// TicketEarlyDataInfo => 0x002e,
}
/// CertificateAuthorities => 0x002f,
pub fn fn_signature_algorithm_cert_extension() -> Result<ClientExtension, FnError> {
    Ok(ClientExtension::SignatureAlgorithmsCert(
        SupportedSignatureSchemes(vec![
            SignatureScheme::RSA_PKCS1_SHA1,
            SignatureScheme::ECDSA_SHA1_Legacy,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PSS_SHA256,
        ]),
    ))
}

pub fn fn_certificate_authorities_extension() -> Result<CertReqExtension, FnError> {
    let mut r = VecU16OfPayloadU16(Vec::new());

    let subject = "inria.fr";
    let mut name = Vec::new();
    name.extend_from_slice(subject.as_bytes());
    x509::wrap_in_sequence(&mut name);
    r.0.push(DistinguishedName::new(name));

    Ok(CertReqExtension::AuthorityNames(r))
}
nyi_fn! {
    /// OIDFilters => 0x0030,
}
nyi_fn! {
    /// PostHandshakeAuth => 0x0031,
}
/// KeyShare => 0x0033,

pub fn fn_key_share_deterministic(group: &NamedGroup) -> Result<KeyShareEntry, FnError> {
    Ok(KeyShareEntry {
        group: *group,
        payload: PayloadU16::new(deterministic_key_share(group)?),
    })
}

nyi_fn! {
    /// transparency_info => 0x0034,
}
nyi_fn! {
    /// connection_id => 0x0035,
}
nyi_fn! {
    /// external_id_hash => 0x0037,
}
nyi_fn! {
    /// external_session_id => 0x0038,
}
nyi_fn! {
    /// NextProtocolNegotiation => 0x3374,
}
nyi_fn! {
    /// ChannelId => 0x754f,
}

// Unknown extensions

pub fn fn_unknown_client_extension() -> Result<ClientExtension, FnError> {
    Ok(ClientExtension::Unknown(UnknownExtension {
        typ: ExtensionType::Unknown(0xFFFF),
        payload: Payload::new([42; 10]),
    }))
}

pub fn fn_unknown_server_extension() -> Result<ServerExtension, FnError> {
    Ok(ServerExtension::Unknown(UnknownExtension {
        typ: ExtensionType::Unknown(0xFFFF),
        payload: Payload::new([42; 10]),
    }))
}

pub fn fn_unknown_hello_retry_extension() -> Result<HelloRetryExtension, FnError> {
    Ok(HelloRetryExtension::Unknown(UnknownExtension {
        typ: ExtensionType::Unknown(0xFFFF),
        payload: Payload::new([42; 10]),
    }))
}

pub fn fn_unknown_cert_request_extension() -> Result<CertReqExtension, FnError> {
    Ok(CertReqExtension::Unknown(UnknownExtension {
        typ: ExtensionType::Unknown(0xFFFF),
        payload: Payload::new([42; 10]),
    }))
}

pub fn fn_unknown_new_session_ticket_extension() -> Result<NewSessionTicketExtension, FnError> {
    Ok(NewSessionTicketExtension::Unknown(UnknownExtension {
        typ: ExtensionType::Unknown(0xFFFF),
        payload: Payload::new([42; 10]),
    }))
}

pub fn fn_unknown_certificate_extension() -> Result<CertificateExtension, FnError> {
    Ok(CertificateExtension::Unknown(UnknownExtension {
        typ: ExtensionType::Unknown(0xFFFF),
        payload: Payload::new([42; 10]),
    }))
}
