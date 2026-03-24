#![allow(clippy::ptr_arg)]

use puffin::algebra::error::FnError;

use crate::static_certs::{
    ALICE_CERT, ALICE_PRIVATE_KEY, BOB_CERT, BOB_PRIVATE_KEY, EVE_CERT, RANDOM_EC_CERT,
    RANDOM_EC_PRIVATE_KEY_PKCS8,
};
use crate::tls::rustls::hash_hs::HandshakeHash;
use crate::tls::rustls::key::Certificate;
use crate::tls::rustls::msgs::enums::SignatureScheme;
use crate::tls::rustls::msgs::handshake::{
    CertificateEntry, CertificateExtensions, HandshakePayload,
};
use crate::tls::rustls::msgs::message::{Message, MessagePayload};
use crate::tls::rustls::verify::{
    construct_tls13_client_verify_message_raw, construct_tls13_server_verify_message_raw,
};
use crate::tls::sign;

pub fn fn_bob_cert() -> Result<Vec<u8>, FnError> {
    Ok(BOB_CERT.1.into())
}

pub fn fn_bob_key() -> Result<Vec<u8>, FnError> {
    Ok(BOB_PRIVATE_KEY.1.into())
}

pub fn fn_alice_cert() -> Result<Vec<u8>, FnError> {
    Ok(ALICE_CERT.1.into())
}

pub fn fn_alice_key() -> Result<Vec<u8>, FnError> {
    Ok(ALICE_PRIVATE_KEY.1.into())
}

pub fn fn_eve_cert() -> Result<Vec<u8>, FnError> {
    Ok(EVE_CERT.1.into())
}

pub fn fn_random_ec_cert() -> Result<Vec<u8>, FnError> {
    Ok(RANDOM_EC_CERT.1.into())
}

pub fn fn_random_ec_key() -> Result<Vec<u8>, FnError> {
    Ok(RANDOM_EC_PRIVATE_KEY_PKCS8.1.into())
}

pub fn fn_certificate_entry_extensions(
    cert: &Vec<u8>,
    extensions: &CertificateExtensions,
) -> Result<CertificateEntry, FnError> {
    Ok(CertificateEntry {
        cert: Certificate(cert.clone()),
        exts: extensions.clone(),
    })
}

pub fn fn_certificate_from_vec_u8(cert: &Vec<u8>) -> Result<Certificate, FnError> {
    Ok(Certificate(cert.clone()))
}

pub fn fn_empty_certificate_chain() -> Result<Vec<CertificateEntry>, FnError> {
    Ok(Vec::new())
}

pub fn fn_chain_append_certificate_entry(
    chain: &Vec<CertificateEntry>,
    cert: &CertificateEntry,
) -> Result<Vec<CertificateEntry>, FnError> {
    let mut res = chain.clone();
    res.push(cert.clone());
    Ok(res)
}

pub fn fn_get_context(certificate_request: &Message) -> Result<Vec<u8>, FnError> {
    match certificate_request.payload.clone() {
        MessagePayload::Handshake(payload) => match payload.payload {
            HandshakePayload::CertificateRequestTLS13(payload) => Some(payload.context.0),
            _ => None,
        },
        _ => None,
    }
    .ok_or_else(|| FnError::Malformed("Could not find context in message".to_owned()))
}

pub fn fn_eve_pkcs1_signature() -> Result<Vec<u8>, FnError> {
    Ok(include_bytes!("../../assets/eve-signature").to_vec())
}
pub fn fn_rsa_sign_client(
    transcript: &HandshakeHash,
    private_key: &Vec<u8>,
    scheme: &SignatureScheme,
) -> Result<Vec<u8>, FnError> {
    sign::rsa_sign(
        &construct_tls13_client_verify_message_raw(&transcript.get_current_hash_raw()),
        private_key,
        scheme,
    )
}

pub fn fn_rsa_sign_server(
    transcript: &HandshakeHash,
    private_key: &Vec<u8>,
    scheme: &SignatureScheme,
) -> Result<Vec<u8>, FnError> {
    sign::rsa_sign(
        &construct_tls13_server_verify_message_raw(&transcript.get_current_hash_raw()),
        private_key,
        scheme,
    )
}

pub fn fn_ecdsa_sign_client(
    transcript: &HandshakeHash,
    private_key: &Vec<u8>,
) -> Result<Vec<u8>, FnError> {
    let message = construct_tls13_client_verify_message_raw(&transcript.get_current_hash_raw());
    sign::ecdsa_sign(&message, private_key)
}

pub fn fn_ecdsa_sign_server(
    transcript: &HandshakeHash,
    private_key: &Vec<u8>,
) -> Result<Vec<u8>, FnError> {
    let message = construct_tls13_server_verify_message_raw(&transcript.get_current_hash_raw());
    sign::ecdsa_sign(&message, private_key)
}

pub fn fn_rsa_pss_signature_algorithm() -> Result<SignatureScheme, FnError> {
    Ok(SignatureScheme::RSA_PSS_SHA256)
}

pub fn fn_rsa_pkcs1_signature_algorithm() -> Result<SignatureScheme, FnError> {
    Ok(SignatureScheme::RSA_PKCS1_SHA256)
}

pub fn fn_invalid_signature_algorithm() -> Result<SignatureScheme, FnError> {
    Ok(SignatureScheme::Unknown(0x0100))
}

pub fn fn_ecdsa_signature_algorithm() -> Result<SignatureScheme, FnError> {
    Ok(SignatureScheme::ECDSA_NISTP256_SHA256)
}
