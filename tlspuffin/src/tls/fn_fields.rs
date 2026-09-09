#![allow(clippy::ptr_arg)]
#![allow(dead_code)]

use puffin::algebra::error::FnError;
use puffin::codec::{Codec, Reader};

use super::suite_as_supported_suite;
use crate::tls::key_exchange::tls12_new_secrets;
use crate::tls::key_schedule::dhe_key_schedule;
use crate::tls::rustls::hash_hs::HandshakeHash;
use crate::tls::rustls::key_log::NoKeyLog;
use crate::tls::rustls::msgs::enums::{CipherSuite, ExtensionType, NamedGroup};
use crate::tls::rustls::msgs::handshake::{ClientExtension, Random, SessionID};

pub fn fn_empty_session_id() -> Result<SessionID, FnError> {
    let mut id: Vec<u8> = Vec::from([]);
    id.insert(0, 0);
    let id = SessionID::read(&mut Reader::init(id.as_slice()));
    Ok(id.unwrap())
}

pub fn fn_no_key_share() -> Result<Option<Vec<u8>>, FnError> {
    Ok(None)
}

pub fn fn_get_client_key_share(
    client_extensions: &Vec<ClientExtension>,
    group: &NamedGroup,
) -> Result<Option<Vec<u8>>, FnError> {
    let client_extension = client_extensions
        .iter()
        .find(|x| x.get_type() == ExtensionType::KeyShare)
        .ok_or(FnError::Malformed(
            "KeyShare extension not found".to_string(),
        ))?;

    if let ClientExtension::KeyShare(keyshares) = client_extension {
        let keyshare = keyshares
            .0
            .iter()
            .find(|keyshare| keyshare.group == *group)
            .ok_or(FnError::Malformed("Keyshare not found".to_string()))?;
        Ok(Some(keyshare.payload.0.clone()))
    } else {
        Err(FnError::Malformed(
            "KeyShare extension not found".to_string(),
        ))
    }
}

pub fn fn_verify_data(
    server_finished: &HandshakeHash,
    server_hello: &HandshakeHash,
    server_key_share: &Option<Vec<u8>>,
    psk: &Option<Vec<u8>>,
    group: &NamedGroup,
    client_random: &Random,
    suite: &CipherSuite,
) -> Result<Vec<u8>, FnError> {
    let supported_suite = suite_as_supported_suite(suite)?;

    let key_schedule = dhe_key_schedule(&supported_suite, group, server_key_share, psk)?;

    let (hs, _client_secret, _server_secret) = key_schedule.derive_handshake_secrets(
        &server_hello.get_current_hash_raw(),
        &NoKeyLog,
        &client_random.0,
    );

    let (pending, _client_secret, _server_secret) = hs
        .into_traffic_with_client_finished_pending_raw(
            &server_hello.get_current_hash_raw(),
            &NoKeyLog,
            &client_random.0,
        );

    let (_traffic, tag, _client_secret) =
        pending.sign_client_finish_raw(&server_finished.get_current_hash_raw());
    Ok(Vec::from(tag.as_ref()))
}

pub fn fn_verify_data_server(
    server_finished: &HandshakeHash,
    server_hello: &HandshakeHash,
    server_key_share: &Option<Vec<u8>>,
    group: &NamedGroup,
    psk: &Option<Vec<u8>>,
    client_random: &Random,
    suite: &CipherSuite,
) -> Result<Vec<u8>, FnError> {
    let supported_suite = suite_as_supported_suite(suite)?;

    let key_schedule = dhe_key_schedule(&supported_suite, group, server_key_share, psk)?;

    let (hs, _client_secret, _server_secret) = key_schedule.derive_handshake_secrets(
        &server_hello.get_current_hash_raw(),
        &NoKeyLog,
        &client_random.0,
    );

    let tag = hs.sign_server_finish_raw(&server_finished.get_current_hash_raw());
    let vec = Vec::from(tag.as_ref());
    Ok(vec)
}

// ----
// seed_client_attacker12()
// ----

pub fn fn_client_sign_transcript(
    server_random: &Random,
    server_ecdh_pubkey: &Vec<u8>,
    transcript: &HandshakeHash,
    group: &NamedGroup,
    client_random: &Random,
    suite: &CipherSuite,
) -> Result<Vec<u8>, FnError> {
    let supported_suite = suite_as_supported_suite(suite)?;

    let secrets = tls12_new_secrets(
        server_random,
        server_ecdh_pubkey,
        group,
        client_random,
        supported_suite,
    )?;

    let vh = transcript.get_current_hash();
    Ok(secrets.client_verify_data(&vh))
}

pub fn fn_server_sign_transcript(
    server_random: &Random,
    client_ecdh_pubkey: &Vec<u8>,
    transcript: &HandshakeHash,
    group: &NamedGroup,
    client_random: &Random,
    suite: &CipherSuite,
) -> Result<Vec<u8>, FnError> {
    let supported_suite = suite_as_supported_suite(suite)?;

    let secrets = tls12_new_secrets(
        server_random,
        client_ecdh_pubkey,
        group,
        client_random,
        supported_suite,
    )?;

    let vh = transcript.get_current_hash();
    Ok(secrets.server_verify_data(&vh))
}

// ----
// Cipher Suites
// ----
