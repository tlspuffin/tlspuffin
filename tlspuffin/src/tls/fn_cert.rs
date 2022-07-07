use std::sync::Arc;

use ring::signature::RsaKeyPair;
use rustls::{
    hash_hs::HandshakeHash,
    msgs::{
        handshake::{CertReqExtension, CertificateEntry, HandshakePayload},
        message::{Message, MessagePayload},
    },
    sign::RsaSigner,
    verify::{
        construct_tls13_client_verify_message, construct_tls13_client_verify_message_raw,
        construct_tls13_server_verify_message,
    },
    Certificate, SignatureScheme,
    SignatureScheme::{RSA_PKCS1_SHA256, RSA_PSS_SHA256},
};

use crate::{
    static_certs::{
        ALICE_CERT_DER, BOB_CERT_DER, BOB_PRIVATE_KEY_DER, EVE_CERT_DER, EVE_PRIVATE_KEY_DER,
    },
    tls::error::FnError,
};

pub fn fn_bob_cert() -> Result<Vec<u8>, FnError> {
    Ok(BOB_CERT_DER.into())
}

pub fn fn_alice_cert() -> Result<Vec<u8>, FnError> {
    Ok(ALICE_CERT_DER.into())
}

pub fn fn_eve_cert() -> Result<Vec<u8>, FnError> {
    Ok(EVE_CERT_DER.into())
}

pub fn fn_certificate_entry(cert: &Vec<u8>) -> Result<CertificateEntry, FnError> {
    Ok(CertificateEntry {
        cert: Certificate(cert.clone()),
        exts: vec![],
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
    .ok_or_else(|| FnError::Unknown("Could not find context in message".to_owned()))
}

pub fn fn_rsa_sign_client(
    transcript: &HandshakeHash,
    private_key: &&'static [u8],
) -> Result<Vec<u8>, FnError> {
    let key = RsaKeyPair::from_der(private_key).unwrap();
    let signer = RsaSigner::new(Arc::new(key), SignatureScheme::RSA_PSS_SHA256);
    let message = construct_tls13_client_verify_message_raw(&transcript.get_current_hash_raw());
    Ok(signer.sign(&message)?)
}

pub fn fn_rsa_sign_server(
    transcript: &HandshakeHash,
    private_key: &&'static [u8],
) -> Result<Vec<u8>, FnError> {
    let key = RsaKeyPair::from_der(private_key).unwrap();
    let signer = RsaSigner::new(Arc::new(key), SignatureScheme::RSA_PSS_SHA256);
    let message = construct_tls13_server_verify_message(&transcript.get_current_hash());
    Ok(signer.sign(&message)?)
}

pub fn fn_get_signature_algorithm(
    certificate_request: &Message,
) -> Result<SignatureScheme, FnError> {
    Ok(SignatureScheme::RSA_PSS_SHA256) // FIXME
}
/*
pub fn fn_get_signature_algorithm(
    certificate_request: &Message,
) -> Result<SignatureScheme, FnError> {
    match &certificate_request.payload {
        MessagePayload::Handshake(payload) => match &payload.payload {
            HandshakePayload::CertificateRequestTLS13(payload) => payload
                .extensions
                .iter()
                .find_map(|extension: &CertReqExtension| match &extension {
                    CertReqExtension::SignatureAlgorithms(algs) => algs.first().cloned(),
                    CertReqExtension::AuthorityNames(_) => None,
                    CertReqExtension::Unknown(_) => None,
                }),
            _ => None,
        },
        _ => None,
    }
    .ok_or_else(|| FnError::Unknown("Could not find signature algorithm in message".to_owned()))
}*/
