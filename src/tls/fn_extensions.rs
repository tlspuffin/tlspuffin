use rustls::internal::msgs::base::{PayloadU16, PayloadU8};
use rustls::internal::msgs::enums::{NamedGroup, ServerNameType};
use rustls::internal::msgs::handshake::{
    ClientExtension, KeyShareEntry, ServerName, ServerNamePayload,
};
use rustls::kx::KeyExchange;
use rustls::kx_group::X25519;
use rustls::{ProtocolVersion, SignatureScheme};
use super::NoneError;

use crate::tls::key_exchange::deterministic_key_exchange;

pub fn fn_extensions_new() -> Result<Vec<ClientExtension>, NoneError> {
    Ok(vec![])
}

pub fn fn_extensions_append(
    extensions: &Vec<ClientExtension>,
    extension: &ClientExtension,
) -> Result<Vec<ClientExtension>, NoneError> {
    let mut new_extensions = extensions.clone();
    new_extensions.push(extension.clone());
    Ok(new_extensions)
}

// ----
// seed_client_attacker()
// ----

pub fn fn_server_name_extension() -> Result<ClientExtension, NoneError> {
    let dns_name = "maxammann.org";
    Ok(ClientExtension::ServerName(vec![ServerName {
        typ: ServerNameType::HostName,
        payload: ServerNamePayload::HostName((
            PayloadU16(dns_name.to_string().into_bytes()),
            webpki::DnsNameRef::try_from_ascii_str(dns_name)
                .unwrap()
                .to_owned(),
        )),
    }]))
}

pub fn fn_x25519_support_group_extension() -> Result<ClientExtension, NoneError> {
    Ok(ClientExtension::NamedGroups(vec![NamedGroup::X25519]))
}

pub fn fn_signature_algorithm_extension() -> Result<ClientExtension, NoneError> {
    Ok(ClientExtension::SignatureAlgorithms(vec![
        SignatureScheme::RSA_PKCS1_SHA256,
        SignatureScheme::RSA_PSS_SHA256,
    ]))
}

pub fn fn_signature_algorithm_cert_extension() -> Result<ClientExtension, NoneError> {
    Ok(ClientExtension::SignatureAlgorithmsCert(vec![
        SignatureScheme::RSA_PKCS1_SHA1,
        SignatureScheme::ECDSA_SHA1_Legacy,
        SignatureScheme::RSA_PKCS1_SHA256,
        SignatureScheme::ECDSA_NISTP256_SHA256,
        SignatureScheme::RSA_PKCS1_SHA384,
        SignatureScheme::ECDSA_NISTP384_SHA384,
        SignatureScheme::RSA_PKCS1_SHA512,
        SignatureScheme::ECDSA_NISTP521_SHA512,
        SignatureScheme::RSA_PSS_SHA256,
        SignatureScheme::RSA_PSS_SHA384,
        SignatureScheme::RSA_PSS_SHA512,
        SignatureScheme::ED25519,
        SignatureScheme::ED448,
    ]))
}

pub fn fn_key_share_extension() -> Result<ClientExtension, NoneError> {
    //let key = Vec::from(rand::random::<[u8; 32]>()); // 32 byte public key
    //let key = Vec::from([42; 32]); // 32 byte public key
    let our_key_share: KeyExchange = deterministic_key_exchange(&X25519);
    Ok(ClientExtension::KeyShare(vec![KeyShareEntry {
        group: NamedGroup::X25519,
        payload: PayloadU16::new(Vec::from(our_key_share.pubkey.as_ref())),
    }]))
}

pub fn fn_renegotiation_info(data: &Vec<u8>) -> Result<ClientExtension, NoneError> {
    Ok(ClientExtension::RenegotiationInfo(PayloadU8::new(data.clone())))
}

pub fn fn_supported_versions_extension() -> Result<ClientExtension, NoneError> {
    Ok(ClientExtension::SupportedVersions(vec![ProtocolVersion::TLSv1_3]))
}

// ----
// seed_client_attacker12()
// ----

pub fn fn_signed_certificate_timestamp() -> Result<ClientExtension, NoneError> {
    Ok(ClientExtension::SignedCertificateTimestampRequest)
}

pub fn fn_ec_point_formats() -> Result<ClientExtension, NoneError> {
    Ok(ClientExtension::ECPointFormats(vec![
        rustls::internal::msgs::enums::ECPointFormat::Uncompressed,
    ]))
}