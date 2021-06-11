//! Extensions according to IANA:
//! https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml
//!
//! In the source code all IDs are available, but implementations are missing.
//!
use rustls::internal::msgs::base::{PayloadU16, PayloadU8};
use rustls::internal::msgs::enums::*;
use rustls::internal::msgs::handshake::*;
use rustls::kx::KeyExchange;
use rustls::kx_group::X25519;
use rustls::msgs::base::Payload;
use rustls::{ProtocolVersion, SignatureScheme};

use crate::nyi_fn;
use crate::tls::key_exchange::deterministic_key_exchange;

use super::error::FnError;

pub fn fn_client_extensions_new() -> Result<Vec<ClientExtension>, FnError> {
    Ok(vec![])
}

pub fn fn_client_extensions_append(
    extensions: &Vec<ClientExtension>,
    extension: &ClientExtension,
) -> Result<Vec<ClientExtension>, FnError> {
    let mut new_extensions = extensions.clone();
    new_extensions.push(extension.clone());

    Ok(new_extensions)
}

pub fn fn_server_extensions_new() -> Result<Vec<ServerExtension>, FnError> {
    Ok(vec![])
}

pub fn fn_server_extensions_append(
    extensions: &Vec<ServerExtension>,
    extension: &ServerExtension,
) -> Result<Vec<ServerExtension>, FnError> {
    let mut new_extensions = extensions.clone();
    new_extensions.push(extension.clone());

    Ok(new_extensions)
}

pub fn fn_hello_retry_extensions_new() -> Result<Vec<HelloRetryExtension>, FnError> {
    Ok(vec![])
}

pub fn fn_hello_retry_extensions_append(
    extensions: &Vec<HelloRetryExtension>,
    extension: &HelloRetryExtension,
) -> Result<Vec<HelloRetryExtension>, FnError> {
    let mut new_extensions = extensions.clone();
    new_extensions.push(extension.clone());

    Ok(new_extensions)
}

pub fn fn_cert_req_extensions_new() -> Result<Vec<CertReqExtension>, FnError> {
    Ok(vec![])
}

pub fn fn_cert_req_extensions_append(
    extensions: &Vec<CertReqExtension>,
    extension: &CertReqExtension,
) -> Result<Vec<CertReqExtension>, FnError> {
    let mut new_extensions = extensions.clone();
    new_extensions.push(extension.clone());

    Ok(new_extensions)
}

// todo ServerExtensions

// todo CertReqExtension

// todo NewSessionTicketExtension

// todo Unknown Extensions for ClientExtension, ServerExtension, HelloRetryExtension

//
// Actual extensions
//

/// ServerName => 0x0000,
pub fn fn_server_name_extension() -> Result<ClientExtension, FnError> {
    let dns_name = "inria.fr";
    Ok(ClientExtension::ServerName(vec![ServerName {
        typ: ServerNameType::HostName,
        payload: ServerNamePayload::HostName((
            PayloadU16(dns_name.to_string().into_bytes()),
            webpki::DnsNameRef::try_from_ascii_str(dns_name)?.to_owned(),
        )),
    }]))
}
/// MaxFragmentLength => 0x0001,
nyi_fn!();
/// ClientCertificateUrl => 0x0002,
nyi_fn!();
/// TrustedCAKeys => 0x0003,
nyi_fn!();
/// TruncatedHMAC => 0x0004,
nyi_fn!();
/// StatusRequest => 0x0005,
pub fn fn_status_request_extension(
    responder_ids: &Vec<Vec<u8>>,
    extensions: &Vec<u8>,
) -> Result<ClientExtension, FnError> {
    // todo unclear where the arguments come from here, needs manual trace implementation
    Ok(ClientExtension::CertificateStatusRequest(
        CertificateStatusRequest::OCSP(OCSPCertificateStatusRequest {
            responder_ids: responder_ids
                .iter()
                .map(|data| PayloadU16::new(data.clone()))
                .collect(),
            extensions: PayloadU16::new(extensions.clone())
        }),
    ))
}
/// UserMapping => 0x0006,
nyi_fn!();
/// ClientAuthz => 0x0007,
nyi_fn!();
/// ServerAuthz => 0x0008,
nyi_fn!();
/// CertificateType => 0x0009,
nyi_fn!();
/// EllipticCurves => 0x000a,
pub fn fn_x25519_support_group_extension() -> Result<ClientExtension, FnError> {
    Ok(ClientExtension::NamedGroups(vec![NamedGroup::X25519]))
}
/// ECPointFormats => 0x000b,
pub fn fn_ec_point_formats_extension() -> Result<ClientExtension, FnError> {
    Ok(ClientExtension::ECPointFormats(vec![
        ECPointFormat::Uncompressed,
    ]))
}
pub fn fn_ec_point_formats_server_extension() -> Result<ServerExtension, FnError> {
    Ok(ServerExtension::ECPointFormats(vec![
        ECPointFormat::Uncompressed,
    ]))
}
/// SRP => 0x000c,
nyi_fn!();
/// SignatureAlgorithms => 0x000d,
pub fn fn_signature_algorithm_extension() -> Result<ClientExtension, FnError> {
    Ok(ClientExtension::SignatureAlgorithms(vec![
        SignatureScheme::RSA_PKCS1_SHA256,
        SignatureScheme::RSA_PSS_SHA256,
    ]))
}
/// UseSRTP => 0x000e,
nyi_fn!();
/// Heartbeat => 0x000f,
nyi_fn!();
/// ALProtocolNegotiation => 0x0010,
pub fn empty_vec_of_vec() -> Result<Vec<Vec<u8>>, FnError> {
    Ok(vec![])
}
pub fn append_vec(vec_of_vec: &Vec<Vec<u8>>, data: &Vec<u8>) -> Result<Vec<Vec<u8>>, FnError> {
    let mut new = vec_of_vec.clone();
    new.push(data.clone());
    Ok(new)
}
pub fn fn_al_protocol_negotiation(
    protocol_name_list: &Vec<Vec<u8>>,
) -> Result<ClientExtension, FnError> {
    // todo unclear where the arguments come from here, needs manual trace implementation
    Ok(ClientExtension::Protocols(
        protocol_name_list
            .iter()
            .map(|data| PayloadU8::new(data.clone()))
            .collect(),
    ))
}
/// status_request_v2 => 0x0011
nyi_fn!();
/// SCT => 0x0012,
pub fn fn_signed_certificate_timestamp() -> Result<ClientExtension, FnError> {
    Ok(ClientExtension::SignedCertificateTimestampRequest)
}
/// client_certificate_type => 0x0013,
nyi_fn!();
/// server_certificate_type => 0x0014,
nyi_fn!();
/// Padding => 0x0015,
nyi_fn!();
/// encrypt_then_mac => 0x0016,
nyi_fn!();
/// ExtendedMasterSecret => 0x0017,
pub fn fn_extended_master_secret_extension() -> Result<ClientExtension, FnError> {
    Ok(ClientExtension::ExtendedMasterSecretRequest)
}
/// token_binding => 0x0018,
nyi_fn!();
/// cached_info => 0x0019,
nyi_fn!();
/// tls_lts => 0x001A,
nyi_fn!();
/// compress_certificate => 0x001B,
nyi_fn!();
/// record_size_limit => 0x001C,
nyi_fn!();
/// pwd_protect => 0x001D,
nyi_fn!();
/// pwd_clear => 0x001E,
nyi_fn!();
/// password_salt => 0x001F,
nyi_fn!();
/// ticket_pinning => 0x0020,
nyi_fn!();
/// tls_cert_with_extern_psk => 0x0021,
nyi_fn!();
/// delegated_credentials => 0x0022,
nyi_fn!();
/// SessionTicket => 0x0023,
pub fn fn_session_ticket_request_extension() -> Result<ClientExtension, FnError> {
    Ok(ClientExtension::SessionTicketRequest)
}
pub fn fn_session_ticket_offer_extension(ticket: Vec<u8>) -> Result<ClientExtension, FnError> {
    // todo unclear where the arguments come from here, needs manual trace implementation
    Ok(ClientExtension::SessionTicketOffer(Payload::new(ticket)))
}
/// TLMSP => 0x0024,
nyi_fn!();
/// TLMSP_proxying => 0x0025,
nyi_fn!();
/// TLMSP_delegate => 0x0026,
nyi_fn!();
/// supported_ekt_ciphers => 0x0027,
nyi_fn!();
/// PreSharedKey => 0x0029,
pub fn fn_new_preshared_key_identity(identity: &Vec<u8>) -> Result<PresharedKeyIdentity, FnError> {
    Ok(PresharedKeyIdentity {
        identity: PayloadU16::new(identity.clone()),
        obfuscated_ticket_age: 10
    })
}
pub fn fn_empty_preshared_keys_identity_vec() -> Result<Vec<PresharedKeyIdentity>, FnError> {
    Ok(vec![])
}
pub fn fn_append_preshared_keys_identity(
    identities: &Vec<PresharedKeyIdentity>,
    identify: &PresharedKeyIdentity,
) -> Result<Vec<PresharedKeyIdentity>, FnError> {
    let mut new = identities.clone();
    new.push(identify.clone());
    Ok(new)
}
pub fn fn_preshared_keys(
    identities: &Vec<PresharedKeyIdentity>,
    binders: &Vec<Vec<u8>>,
) -> Result<ClientExtension, FnError> {
    // todo unclear where the arguments come from here, needs manual trace implementation
    Ok(ClientExtension::PresharedKey(PresharedKeyOffer {
        identities: identities.clone(),
        binders: binders
            .iter()
            .map(|data| PayloadU8::new(data.clone()))
            .collect(),
    }))
}
/// EarlyData => 0x002a,
pub fn fn_early_data_extension() -> Result<ClientExtension, FnError> {
    Ok(ClientExtension::EarlyData)
}
/// SupportedVersions => 0x002b,
pub fn fn_supported_versions12_extension() -> Result<ClientExtension, FnError> {
    Ok(ClientExtension::SupportedVersions(vec![
        ProtocolVersion::TLSv1_2,
    ]))
}
pub fn fn_supported_versions13_extension() -> Result<ClientExtension, FnError> {
    Ok(ClientExtension::SupportedVersions(vec![
        ProtocolVersion::TLSv1_3,
    ]))
}
pub fn fn_supported_versions12_hello_retry_extension() -> Result<HelloRetryExtension, FnError> {
    Ok(HelloRetryExtension::SupportedVersions(ProtocolVersion::TLSv1_2))
}
pub fn fn_supported_versions13_hello_retry_extension() -> Result<HelloRetryExtension, FnError> {
    Ok(HelloRetryExtension::SupportedVersions(ProtocolVersion::TLSv1_3))
}
/// Cookie => 0x002c,
pub fn fn_cookie_extension(cookie: Vec<u8>) -> Result<ClientExtension, FnError> {
    Ok(ClientExtension::Cookie(PayloadU16::new(cookie)))
}
pub fn fn_cookie_hello_retry_extension(cookie: Vec<u8>) -> Result<HelloRetryExtension, FnError> {
    Ok(HelloRetryExtension::Cookie(PayloadU16::new(cookie)))
}
/// PSKKeyExchangeModes => 0x002d,
pub fn fn_psk_exchange_modes_extension() -> Result<ClientExtension, FnError> {
    Ok(ClientExtension::PresharedKeyModes(vec![
        PSKKeyExchangeMode::PSK_DHE_KE,
        PSKKeyExchangeMode::PSK_KE,
    ]))
}
/// TicketEarlyDataInfo => 0x002e,
nyi_fn!();
/// CertificateAuthorities => 0x002f,
nyi_fn!();
/// OIDFilters => 0x0030,
nyi_fn!();
/// PostHandshakeAuth => 0x0031,
nyi_fn!();
/// SignatureAlgorithmsCert => 0x0032,
pub fn fn_signature_algorithm_cert_extension() -> Result<ClientExtension, FnError> {
    Ok(ClientExtension::SignatureAlgorithmsCert(vec![
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
    ]))
}
/// KeyShare => 0x0033,
pub fn fn_key_share_extension() -> Result<ClientExtension, FnError> {
    let our_key_share: KeyExchange = deterministic_key_exchange(&X25519)?;
    Ok(ClientExtension::KeyShare(vec![KeyShareEntry {
        group: NamedGroup::X25519,
        payload: PayloadU16::new(Vec::from(our_key_share.pubkey.as_ref())),
    }]))
}
pub fn fn_hello_retry_key_share_extension() -> Result<HelloRetryExtension, FnError> {
    Ok(HelloRetryExtension::KeyShare(NamedGroup::X25519))
}
/// transparency_info => 0x0034,
nyi_fn!();
/// connection_id => 0x0035,
nyi_fn!();
/// external_id_hash => 0x0037,
nyi_fn!();
/// external_session_id => 0x0038,
nyi_fn!();
/// TransportParameters/quic_transport_parameters => 0x0039,
pub fn fn_transport_parameters_extension(parameters: &Vec<u8>) -> Result<ClientExtension, FnError> {
    // todo unclear where the arguments come from here, needs manual trace implementation
    Ok(ClientExtension::TransportParameters(parameters.clone()))
}
/// NextProtocolNegotiation => 0x3374,
nyi_fn!();
/// ChannelId => 0x754f,
nyi_fn!();
/// RenegotiationInfo => 0xff01,
pub fn fn_renegotiation_info_initial_extension() -> Result<ClientExtension, FnError> {
    Ok(ClientExtension::RenegotiationInfo(PayloadU8::empty()))
}
pub fn fn_renegotiation_info_extension(data: &Vec<u8>) -> Result<ClientExtension, FnError> {
    Ok(ClientExtension::RenegotiationInfo(PayloadU8::new(
        data.clone(),
    )))
}
/// TransportParametersDraft => 0xffa5
pub fn fn_transport_parameters_draft_extension(parameters: &Vec<u8>) -> Result<ClientExtension, FnError> {
    // todo unclear where the arguments come from here, needs manual trace implementation
    Ok(ClientExtension::TransportParametersDraft(parameters.clone()))
}