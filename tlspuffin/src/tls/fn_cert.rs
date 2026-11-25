#![allow(clippy::ptr_arg)]

use puffin::algebra::error::FnError;

use crate::static_certs::{
    ALICE_CERT, ALICE_EC_CERT, ALICE_EC_PRIVATE_KEY, ALICE_PRIVATE_KEY, BOB_CERT, BOB_EC_CERT,
    BOB_EC_PRIVATE_KEY, BOB_PRIVATE_KEY, EVE_CERT, EVE_EC_CERT, RANDOM_EC_CERT,
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

/// EC counterpart of [`fn_alice_cert`] - same identity, usable with ECDSA signing (see
/// [`fn_alice_ec_key`]).
pub fn fn_alice_ec_cert() -> Result<Vec<u8>, FnError> {
    Ok(ALICE_EC_CERT.1.into())
}

/// EC counterpart of [`fn_alice_key`].
pub fn fn_alice_ec_key() -> Result<Vec<u8>, FnError> {
    Ok(ALICE_EC_PRIVATE_KEY.1.into())
}

/// EC counterpart of [`fn_bob_cert`] - same identity, usable with ECDSA signing (see
/// [`fn_bob_ec_key`]).
pub fn fn_bob_ec_cert() -> Result<Vec<u8>, FnError> {
    Ok(BOB_EC_CERT.1.into())
}

/// EC counterpart of [`fn_bob_key`].
pub fn fn_bob_ec_key() -> Result<Vec<u8>, FnError> {
    Ok(BOB_EC_PRIVATE_KEY.1.into())
}

/// EC counterpart of [`fn_eve_cert`]. Deliberately has no `fn_eve_ec_key` counterpart, same as
/// `fn_eve_cert` itself has no `fn_eve_key` - Eve's private key(s) must not be directly usable by
/// the symbolic attacker, or security-violation oracles that rely on the attacker not actually
/// holding Eve's key would false-positive.
pub fn fn_eve_ec_cert() -> Result<Vec<u8>, FnError> {
    Ok(EVE_EC_CERT.1.into())
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
/// Signs a TLS 1.3 client `CertificateVerify` with whatever algorithm `scheme` selects (RSA
/// PKCS1/PSS or ECDSA-P256 - see [`sign::sign`]). Replaces the former `fn_rsa_sign_client`/
/// `fn_ecdsa_sign_client` pair: those had different arities (ECDSA had no `scheme` argument,
/// since the only backend available at the time was hardcoded to one algorithm), so a mutator
/// could never move between them without also reshaping the call itself. This one function
/// covers both: changing `scheme` is enough.
pub fn fn_sign_client(
    transcript: &HandshakeHash,
    private_key: &Vec<u8>,
    scheme: &SignatureScheme,
) -> Result<Vec<u8>, FnError> {
    sign::sign(
        &construct_tls13_client_verify_message_raw(&transcript.get_current_hash_raw()),
        private_key,
        scheme,
    )
}

/// Server-side counterpart of [`fn_sign_client`].
pub fn fn_sign_server(
    transcript: &HandshakeHash,
    private_key: &Vec<u8>,
    scheme: &SignatureScheme,
) -> Result<Vec<u8>, FnError> {
    sign::sign(
        &construct_tls13_server_verify_message_raw(&transcript.get_current_hash_raw()),
        private_key,
        scheme,
    )
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
