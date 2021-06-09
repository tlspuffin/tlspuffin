use std::convert::{TryFrom, TryInto};
use ring::hkdf::Prk;
use rustls::conn::{ConnectionRandoms, ConnectionSecrets};
use rustls::hash_hs::HandshakeHash;
use rustls::internal::msgs::enums::{ExtensionType, NamedGroup};
use rustls::internal::msgs::handshake::{
    HasServerExtensions, KeyShareEntry, Random, ServerECDHParams, ServerExtension,
};
use rustls::key_schedule::{KeyScheduleHandshake, KeyScheduleNonSecret};
use rustls::kx::{KeyExchange, KeyExchangeResult};
use rustls::suites::Tls12CipherSuite;
use rustls::NoKeyLog;
use rustls::{tls12, SupportedCipherSuite, ALL_KX_GROUPS};
use fn_impl::*;
use crate::define_signature;
use crate::tls::key_exchange::deterministic_key_exchange;
use crate::tls::error::FnError;

mod fn_constants;
mod fn_extensions;
mod fn_fields;
mod fn_messages;
mod fn_utils;
mod key_exchange;
mod tests;

/// This modules contains all the concrete implementations of function symbols.
pub mod fn_impl {
    pub use crate::{
        tls::fn_constants::*, tls::fn_extensions::*, tls::fn_fields::*, tls::fn_messages::*,
        tls::fn_utils::*,
    };
}
pub mod error;

fn tls13_client_handshake_traffic_secret(
    server_public_key: &[u8],
    transcript: &HandshakeHash,
    write: bool,
) -> Result<(&'static SupportedCipherSuite, Prk), FnError> {
    let client_random = &[1u8; 32]; // todo see op_random()
    let suite = &rustls::suites::TLS13_AES_128_GCM_SHA256; // todo see op_cipher_suites()
    let group = NamedGroup::X25519; // todo
    let mut key_schedule = tls12_key_schedule(server_public_key, suite, group)?;

    let key = if write {
        key_schedule.client_handshake_traffic_secret(
            &transcript.get_current_hash(),
            &NoKeyLog {},
            client_random,
        )
    } else {
        key_schedule.server_handshake_traffic_secret(
            &transcript.get_current_hash(),
            &NoKeyLog {},
            client_random,
        )
    };

    Ok((suite, key))
}

fn tls12_key_schedule(
    server_public_key: &[u8],
    suite: &SupportedCipherSuite,
    group: NamedGroup,
) -> Result<KeyScheduleHandshake, FnError> {
    let skxg = KeyExchange::choose(group, &ALL_KX_GROUPS).ok_or(FnError::Message(
        "Failed to choose group in key exchange".to_string(),
    ))?;
    // Shared Secret
    let our_key_share: KeyExchange = deterministic_key_exchange(skxg)?;
    let shared = our_key_share
        .complete(server_public_key)
        .ok_or(FnError::Message(
            "Failed to complete key exchange".to_string(),
        ))?;

    // Key Schedule without PSK
    let key_schedule =
        KeyScheduleNonSecret::new(suite.hkdf_algorithm).into_handshake(&shared.shared_secret);

    Ok(key_schedule)
}

pub fn tls13_get_server_key_share(
    server_extensions: &Vec<ServerExtension>,
) -> Result<&KeyShareEntry, FnError> {
    let server_extension = server_extensions
        .find_extension(ExtensionType::KeyShare)
        .ok_or(FnError::Message("KeyShare extension not found".to_string()))?;

    if let ServerExtension::KeyShare(keyshare) = server_extension {
        Ok(keyshare)
    } else {
        Err(FnError::Message("KeyShare extension not found".to_string()))
    }
}

// ----
// seed_client_attacker12()
// ----

fn tls12_key_exchange(
    server_ecdh_params: &ServerECDHParams,
) -> Result<KeyExchangeResult, FnError> {
    let group = NamedGroup::X25519; // todo
    let skxg = KeyExchange::choose(group, &ALL_KX_GROUPS)
        .ok_or("Failed to find key exchange group".to_string())?;
    let kx: KeyExchange = deterministic_key_exchange(skxg)?;
    let kxd = tls12::complete_ecdh(kx, &server_ecdh_params.public.0)?;
    Ok(kxd)
}

fn tls12_new_secrets(
    server_random: &Random,
    server_ecdh_params: &ServerECDHParams,
) -> Result<ConnectionSecrets, FnError> {
    let suite = &rustls::suites::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256; // todo

    let mut server_random_bytes = vec![0; 32];

    server_random.write_slice(&mut server_random_bytes);

    let server_random = server_random_bytes
        .try_into()
        .map_err(|_| FnError::Message("Server random did not have length of 32".to_string()))?;
    let randoms = ConnectionRandoms {
        we_are_client: true,
        client: [1; 32], // todo
        server: server_random,
    };
    let kxd = tls12_key_exchange(server_ecdh_params)?;
    let suite12 = Tls12CipherSuite::try_from(suite)
        .map_err(|_err| FnError::Message("VersionNotCompatibleError".to_string()))?;
    let secrets = ConnectionSecrets::new(&randoms, suite12, &kxd.shared_secret);
    Ok(secrets)
}


// ----
// Signature
// ----

define_signature!(
    SIGNATURE,
    // constants
    fn_empty_bytes_vec,
    fn_seq_0,
    fn_seq_1,
    fn_seq_2,
    fn_seq_3,
    fn_seq_4,
    fn_seq_5,
    // extensions
    fn_ec_point_formats,
    fn_extensions_append,
    fn_extensions_new,
    fn_key_share_extension,
    fn_renegotiation_info,
    fn_server_name_extension,
    fn_signature_algorithm_cert_extension,
    fn_signature_algorithm_extension,
    fn_signed_certificate_timestamp,
    fn_supported_versions_extension,
    fn_x25519_support_group_extension,
    // messages
    fn_alert_close_notify,
    fn_append_transcript,
    fn_application_data,
    fn_arbitrary_to_key,
    fn_certificate,
    fn_change_cipher_spec,
    fn_change_cipher_spec12,
    fn_cipher_suites,
    fn_cipher_suites12,
    fn_client_hello,
    fn_client_key_exchange,
    fn_compressions,
    fn_decode_ecdh_params,
    fn_decrypt,
    fn_encrypt,
    fn_encrypt12,
    fn_encrypted_certificate,
    fn_finished,
    fn_finished12,
    fn_hmac256,
    fn_hmac256_new_key,
    fn_new_pubkey12,
    fn_new_transcript,
    fn_new_transcript12,
    fn_opaque_handshake_message,
    fn_protocol_version12,
    fn_random,
    fn_server_certificate,
    fn_server_hello,
    fn_server_hello_done,
    fn_server_key_exchange,
    fn_session_id,
    fn_sign_transcript,
    fn_verify_data,
);
