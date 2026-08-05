#![allow(clippy::ptr_arg)]

use puffin::algebra::error::FnError;

use crate::static_certs::{
    ALICE_CERT, ALICE_PRIVATE_KEY, BOB_CERT, BOB_PRIVATE_KEY, EVE_CERT, RANDOM_EC_CERT,
    RANDOM_EC_PRIVATE_KEY_PKCS8,
};
use crate::tls::rustls::hash_hs::HandshakeHash;
use crate::tls::rustls::msgs::enums::SignatureScheme;
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

pub fn fn_invalid_signature_algorithm() -> Result<SignatureScheme, FnError> {
    Ok(SignatureScheme::Unknown(0x0100))
}
