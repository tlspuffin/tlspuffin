use std::sync::Arc;

use puffin::algebra::error::FnError;
use ring::signature::{RsaKeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};

use crate::{
    static_certs::{
        ALICE_CERT, ALICE_PRIVATE_KEY, BOB_CERT, BOB_PRIVATE_KEY, EVE_CERT, RANDOM_EC_CERT,
    },
    tls::rustls::{
        hash_hs::HandshakeHash,
        key::{Certificate, PrivateKey},
        msgs::{
            enums::SignatureScheme,
            handshake::{CertificateEntry, CertificateExtensions, HandshakePayload},
            message::{Message, MessagePayload},
        },
        sign::{EcdsaSigningKey, RsaSigner, Signer, SigningKey},
        verify::{
            construct_tls13_client_verify_message_raw, construct_tls13_server_verify_message_raw,
        },
    },
};

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

pub fn fn_certificate_entry(cert: &Vec<u8>) -> Result<CertificateEntry, FnError> {
    Ok(CertificateEntry {
        cert: Certificate(cert.clone()),
        exts: CertificateExtensions(vec![]),
    })
}

pub fn fn_empty_certificate_chain() -> Result<Vec<CertificateEntry>, FnError> {
    Ok(Vec::new())
}

pub fn fn_append_certificate_entry(
    cert: &CertificateEntry,
    chain: &Vec<CertificateEntry>,
) -> Result<Vec<CertificateEntry>, FnError> {
    let mut chain = chain.clone();
    chain.push(cert.clone());
    Ok(chain)
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
    _fn_rsa_sign(
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
    _fn_rsa_sign(
        &construct_tls13_server_verify_message_raw(&transcript.get_current_hash_raw()),
        private_key,
        scheme,
    )
}

fn _fn_rsa_sign(
    message: &[u8],
    private_key: &Vec<u8>,
    scheme: &SignatureScheme,
) -> Result<Vec<u8>, FnError> {
    let invalid_scheme = match scheme {
        SignatureScheme::RSA_PKCS1_SHA256
        | SignatureScheme::RSA_PKCS1_SHA384
        | SignatureScheme::RSA_PKCS1_SHA512
        | SignatureScheme::RSA_PSS_SHA256
        | SignatureScheme::RSA_PSS_SHA384
        | SignatureScheme::RSA_PSS_SHA512 => false,
        _ => true,
    };
    if invalid_scheme {
        return Err(FnError::Crypto("Unknown signature scheme".to_string()));
    }

    let key = RsaKeyPair::from_der(private_key)
        .map_err(|_| FnError::Crypto("Failed to parse rsa key.".to_string()))?;

    let signer = RsaSigner::new(
        Arc::new(key),
        *scheme,
        Box::new(ring::test::rand::FixedByteRandom { byte: 43 }),
    );
    signer
        .sign(message)
        .map_err(|_err| FnError::Crypto("Failed to sign using RSA key".to_string()))
}

pub fn fn_ecdsa_sign_client(
    transcript: &HandshakeHash,
    private_key: &Vec<u8>,
) -> Result<Vec<u8>, FnError> {
    let message = construct_tls13_client_verify_message_raw(&transcript.get_current_hash_raw());
    _fn_ecdsa_sign(&message, private_key)
}

pub fn fn_ecdsa_sign_server(
    transcript: &HandshakeHash,
    private_key: &Vec<u8>,
) -> Result<Vec<u8>, FnError> {
    let message = construct_tls13_server_verify_message_raw(&transcript.get_current_hash_raw());
    _fn_ecdsa_sign(&message, private_key)
}

fn _fn_ecdsa_sign(message: &[u8], private_key: &Vec<u8>) -> Result<Vec<u8>, FnError> {
    let key = EcdsaSigningKey::new(
        &PrivateKey(private_key.to_vec()),
        SignatureScheme::ECDSA_NISTP256_SHA256,
        &ECDSA_P256_SHA256_ASN1_SIGNING,
    )
    .map_err(|_| FnError::Crypto("Failed to parse ecdsa key.".to_string()))?;

    let signer = key
        .choose_scheme(
            &[SignatureScheme::ECDSA_NISTP256_SHA256],
            Box::new(ring::test::rand::FixedByteRandom { byte: 43 }),
        )
        .ok_or_else(|| FnError::Crypto("Failed to find signature scheme.".to_string()))?;

    signer
        .sign(message)
        .map_err(|_err| FnError::Crypto("Failed to sign using ECDHE key".to_string()))
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
