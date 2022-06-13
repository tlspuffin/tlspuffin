#![allow(clippy::ptr_arg)]
#![allow(dead_code)]

use rustls::{
    hash_hs::HandshakeHash,
    msgs::{
        codec::{Codec, Reader},
        enums::{Compression, ExtensionType, NamedGroup},
        handshake::{HasServerExtensions, Random, ServerECDHParams, ServerExtension, SessionID},
    },
    CipherSuite, NoKeyLog, ProtocolVersion,
};

use crate::tls::{error::FnError, key_exchange::tls12_new_secrets, key_schedule::dhe_key_schedule};

pub fn fn_protocol_version13() -> Result<ProtocolVersion, FnError> {
    Ok(ProtocolVersion::TLSv1_3)
}

pub fn fn_protocol_version12() -> Result<ProtocolVersion, FnError> {
    Ok(ProtocolVersion::TLSv1_2)
}

pub fn fn_new_session_id() -> Result<SessionID, FnError> {
    let mut id: Vec<u8> = Vec::from([3u8; 32]);
    id.insert(0, 32);
    let id = SessionID::read(&mut Reader::init(id.as_slice()));
    Ok(id.unwrap())
}

pub fn fn_new_random() -> Result<Random, FnError> {
    let random_data: [u8; 32] = [1; 32];
    Ok(Random::from(random_data))
}

pub fn fn_compressions() -> Result<Vec<Compression>, FnError> {
    Ok(vec![Compression::Null])
}

pub fn fn_compression() -> Result<Compression, FnError> {
    Ok(Compression::Null)
}

pub fn fn_no_key_share() -> Result<Option<Vec<u8>>, FnError> {
    Ok(None)
}

pub fn fn_get_server_key_share(
    server_extensions: &Vec<ServerExtension>,
) -> Result<Option<Vec<u8>>, FnError> {
    let server_extension = server_extensions
        .find_extension(ExtensionType::KeyShare)
        .ok_or(FnError::Unknown("KeyShare extension not found".to_string()))?;

    if let ServerExtension::KeyShare(keyshare) = server_extension {
        Ok(Some(keyshare.payload.0.clone()))
    } else {
        Err(FnError::Unknown("KeyShare extension not found".to_string()))
    }
}

pub fn fn_verify_data(
    server_finished: &HandshakeHash,
    server_hello: &HandshakeHash,
    server_key_share: &Option<Vec<u8>>,
    psk: &Option<Vec<u8>>,
) -> Result<Vec<u8>, FnError> {
    let client_random = &[1u8; 32]; // todo see op_random() https://gitlab.inria.fr/mammann/tlspuffin/-/issues/45
    let suite = &rustls::tls13::TLS13_AES_128_GCM_SHA256; // todo see op_cipher_suites()

    let group = NamedGroup::secp384r1; // todo https://gitlab.inria.fr/mammann/tlspuffin/-/issues/45

    let key_schedule = dhe_key_schedule(suite, group, server_key_share, psk)?;

    let (hs, _client_secret, _server_secret) = key_schedule.derive_handshake_secrets(
        &server_hello.get_current_hash_raw(),
        &NoKeyLog,
        client_random,
    );

    let (pending, _client_secret, _server_secret) = hs
        .into_traffic_with_client_finished_pending_raw(
            &server_hello.get_current_hash_raw(),
            &NoKeyLog,
            client_random,
        );

    let (_traffic, tag, _client_secret) =
        pending.sign_client_finish_raw(&server_finished.get_current_hash_raw());
    Ok(Vec::from(tag.as_ref()))
}

// ----
// seed_client_attacker12()
// ----

pub fn fn_sign_transcript(
    server_random: &Random,
    server_ecdh_params: &ServerECDHParams,
    transcript: &HandshakeHash,
) -> Result<Vec<u8>, FnError> {
    let secrets = tls12_new_secrets(server_random, server_ecdh_params)?;

    let vh = transcript.get_current_hash();
    Ok(secrets.client_verify_data(&vh))
}

// ----
// Cipher Suites
// ----

pub fn fn_new_cipher_suites() -> Result<Vec<CipherSuite>, FnError> {
    Ok(vec![])
}

// todo implement functions for all supported cipher suites as constants
//      https://gitlab.inria.fr/mammann/tlspuffin/-/issues/65
pub fn fn_append_cipher_suite(
    suites: &Vec<CipherSuite>,
    suite: &CipherSuite,
) -> Result<Vec<CipherSuite>, FnError> {
    let mut new: Vec<CipherSuite> = suites.clone();
    new.push(*suite);
    Ok(new)
}

pub fn fn_cipher_suite12() -> Result<CipherSuite, FnError> {
    Ok(
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        /*CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
        CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
        CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256*/
    )
}

pub fn fn_cipher_suite13_aes_128_gcm_sha256() -> Result<CipherSuite, FnError> {
    Ok(CipherSuite::TLS13_AES_128_GCM_SHA256)
}

pub fn fn_cipher_suite13_aes_256_gcm_sha384() -> Result<CipherSuite, FnError> {
    Ok(CipherSuite::TLS13_AES_256_GCM_SHA384)
}

pub fn fn_cipher_suite13_aes_128_ccm_sha256() -> Result<CipherSuite, FnError> {
    Ok(CipherSuite::TLS13_AES_128_CCM_SHA256)
}

pub fn fn_weak_export_cipher_suite() -> Result<CipherSuite, FnError> {
    Ok(CipherSuite::TLS_RSA_EXPORT_WITH_DES40_CBC_SHA)
}

// todo should be removed because it returns the ready vec instead of a single one
pub fn fn_weak_export_cipher_suites_remove_me() -> Result<Vec<CipherSuite>, FnError> {
    Ok(vec![CipherSuite::TLS_RSA_EXPORT_WITH_DES40_CBC_SHA])
}

pub fn fn_secure_rsa_cipher_suite12() -> Result<CipherSuite, FnError> {
    Ok(CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA256)
}
