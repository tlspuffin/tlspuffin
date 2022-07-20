use std::sync::Arc;

use puffin::algebra::error::FnError;
use ring::signature::{EcdsaKeyPair, RsaKeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
use rustls::{
    hash_hs::HandshakeHash,
    msgs::{
        handshake::{CertReqExtension, CertificateEntry, HandshakePayload},
        message::{Message, MessagePayload},
    },
    sign::{EcdsaSigner, EcdsaSigningKey, RsaSigner, Signer, SigningKey},
    verify::{
        construct_tls13_client_verify_message, construct_tls13_client_verify_message_raw,
        construct_tls13_server_verify_message, construct_tls13_server_verify_message_raw,
    },
    Certificate, PrivateKey, SignatureScheme,
};

use crate::static_certs::{
    ALICE_CERT, ALICE_PRIVATE_KEY, BOB_CERT, BOB_PRIVATE_KEY, EVE_CERT, RANDOM_EC_CERT,
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

pub fn fn_eve_pkcs1_signature() -> Result<Vec<u8>, FnError> {
    Ok(vec![
        78, 243, 129, 112, 207, 119, 126, 103, 15, 194, 242, 254, 105, 174, 85, 77, 148, 45, 90,
        108, 6, 195, 126, 192, 98, 155, 15, 226, 33, 91, 215, 141, 70, 134, 14, 101, 65, 155, 182,
        229, 25, 55, 148, 22, 177, 23, 250, 46, 158, 168, 74, 236, 111, 42, 211, 136, 167, 240, 65,
        136, 119, 221, 194, 51, 221, 77, 204, 115, 193, 111, 82, 171, 177, 79, 173, 135, 229, 63,
        103, 222, 181, 84, 123, 233, 212, 77, 47, 241, 199, 157, 46, 114, 141, 33, 186, 136, 250,
        78, 29, 93, 120, 240, 204, 153, 46, 117, 56, 186, 69, 70, 178, 124, 141, 239, 140, 40, 57,
        51, 87, 75, 214, 6, 13, 234, 36, 79, 44, 143, 171, 236, 11, 140, 131, 212, 26, 112, 127,
        31, 22, 26, 197, 105, 91, 159, 100, 160, 133, 120, 131, 84, 180, 191, 226, 66, 178, 9, 141,
        41, 61, 62, 36, 190, 101, 191, 174, 144, 142, 150, 112, 204, 84, 117, 72, 42, 181, 131,
        216, 51, 81, 177, 197, 233, 252, 77, 60, 111, 250, 8, 62, 106, 76, 205, 230, 169, 233, 128,
        45, 230, 140, 195, 70, 240, 229, 129, 175, 236, 28, 169, 34, 49, 148, 42, 230, 236, 89,
        176, 199, 197, 229, 235, 251, 151, 190, 208, 73, 165, 179, 229, 131, 201, 3, 147, 51, 1,
        46, 110, 30, 62, 94, 80, 87, 192, 117, 84, 223, 77, 11, 236, 38, 52, 108, 233, 118, 168,
        124, 196,
    ])
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
        return Err(FnError::Rustls("Unknown signature scheme".to_string()));
    }

    let key = RsaKeyPair::from_der(private_key)
        .map_err(|_| FnError::Rustls("Failed to parse rsa key.".to_string()))?;

    let signer = RsaSigner::new(
        Arc::new(key),
        *scheme,
        Box::new(ring::test::rand::FixedByteRandom { byte: 43 }),
    );
    signer
        .sign(&message)
        .map_err(|err| FnError::Rustls("Failed to sign using RSA key".to_string()))
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
    .map_err(|_| FnError::Rustls("Failed to parse ecdsa key.".to_string()))?;

    let signer = key
        .choose_scheme(
            &[SignatureScheme::ECDSA_NISTP256_SHA256],
            Box::new(ring::test::rand::FixedByteRandom { byte: 43 }),
        )
        .ok_or_else(|| FnError::Rustls("Failed to find signature scheme.".to_string()))?;

    signer
        .sign(&message)
        .map_err(|err| FnError::Rustls("Failed to sign using ECDHE key".to_string()))
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
