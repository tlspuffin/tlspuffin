//! The *tls* module provides concrete implementations for the functions used in the term.
//! The module offers a variety of [`DynamicFunction`]s which can be used in the fuzzing.

use std::convert::{TryFrom, TryInto};

use ring::digest::Digest;
use ring::hkdf::Prk;
use rustls::conn::{ConnectionRandoms, ConnectionSecrets};
use rustls::hash_hs::HandshakeHash;
use rustls::key_schedule::{
    KeyScheduleEarly, KeyScheduleHandshake, KeyScheduleNonSecret,
    KeyScheduleTrafficWithClientFinishedPending,
};
use rustls::kx::{KeyExchange, KeyExchangeResult};
use rustls::msgs::enums::{ExtensionType, NamedGroup};
use rustls::msgs::handshake::{
    HasServerExtensions, KeyShareEntry, Random, ServerECDHParams, ServerExtension,
};
use rustls::suites::Tls12CipherSuite;
use rustls::NoKeyLog;
use rustls::{tls12, SupportedCipherSuite, ALL_KX_GROUPS};

use fn_impl::*;

use crate::define_signature;
use crate::tls::error::FnError;
use crate::tls::key_exchange::deterministic_key_exchange;

pub mod fn_constants;
pub mod fn_extensions;
pub mod fn_fields;
pub mod fn_messages;
pub mod fn_utils;
mod key_exchange;
#[cfg(test)]
mod tests;

/// This modules contains all the concrete implementations of function symbols.
pub mod fn_impl {
    pub use crate::{
        tls::fn_constants::*, tls::fn_extensions::*, tls::fn_fields::*, tls::fn_messages::*,
        tls::fn_utils::*,
    };
}

pub mod error;

fn tls13_handshake_traffic_secret(
    server_public_key: &[u8],
    server_hello: &HandshakeHash,
    psk: &Option<Vec<u8>>,
    server: bool,
) -> Result<(&'static SupportedCipherSuite, Prk, KeyScheduleHandshake), FnError> {
    let client_random = &[1u8; 32]; // todo see op_random() https://gitlab.inria.fr/mammann/tlspuffin/-/issues/45
    let suite = &rustls::suites::TLS13_AES_128_GCM_SHA256; // todo see op_cipher_suites() https://gitlab.inria.fr/mammann/tlspuffin/-/issues/45
    let group = NamedGroup::secp384r1; // todo https://gitlab.inria.fr/mammann/tlspuffin/-/issues/45
    let mut key_schedule = tls12_dhe_key_schedule(server_public_key, suite, group, psk)?;

    let server_secret = key_schedule.server_handshake_traffic_secret(
        &server_hello.get_current_hash(),
        &NoKeyLog {},
        client_random,
    );

    let client_secret = key_schedule.client_handshake_traffic_secret(
        &server_hello.get_current_hash(),
        &NoKeyLog {},
        client_random,
    );

    Ok((
        suite,
        if server { client_secret } else { server_secret },
        key_schedule,
    ))
}

fn tls13_application_traffic_secret(
    server_public_key: &[u8],
    server_hello: &HandshakeHash,
    server_finished: &HandshakeHash,
    psk: &Option<Vec<u8>>,
    server: bool,
) -> Result<
    (
        &'static SupportedCipherSuite,
        Prk,
        KeyScheduleTrafficWithClientFinishedPending,
    ),
    FnError,
> {
    let client_random = &[1u8; 32]; // todo see op_random() https://gitlab.inria.fr/mammann/tlspuffin/-/issues/45
    let (suite, _key, key_schedule) =
        tls13_handshake_traffic_secret(server_public_key, server_hello, psk, server)?;

    let mut application_key_schedule = key_schedule.into_traffic_with_client_finished_pending();

    let server_secret = application_key_schedule.server_application_traffic_secret(
        &server_finished.get_current_hash(),
        &NoKeyLog {},
        client_random,
    );

    let client_secret = application_key_schedule.client_application_traffic_secret(
        &server_finished.get_current_hash(),
        &NoKeyLog {},
        client_random,
    );

    Ok((
        suite,
        if server { client_secret } else { server_secret },
        application_key_schedule,
    ))
}

fn tls13_derive_psk(
    server_public_key: &[u8],
    server_hello: &HandshakeHash,
    server_finished: &HandshakeHash,
    client_finished: &HandshakeHash,
    new_ticket_nonce: &Vec<u8>,
) -> Result<(Vec<u8>), FnError> {
    let client_random = &[1u8; 32]; // todo see op_random() https://gitlab.inria.fr/mammann/tlspuffin/-/issues/45

    let (_, _, mut application_key_schedule) =
        tls13_application_traffic_secret(server_public_key, server_hello, server_finished, &None, true)?;

    application_key_schedule.exporter_master_secret(
        &server_finished.get_current_hash(), // todo
        &NoKeyLog {},
        client_random,
    );

    let psk = application_key_schedule
        .into_traffic()
        .resumption_master_secret_and_derive_ticket_psk(
            &client_finished.get_current_hash(), // todo
            new_ticket_nonce,
        );

    Ok(psk)
}

fn tls12_dhe_key_schedule(
    server_public_key: &[u8],
    suite: &SupportedCipherSuite,
    group: NamedGroup,
    psk: &Option<Vec<u8>>,
) -> Result<KeyScheduleHandshake, FnError> {
    let skxg = KeyExchange::choose(group, &ALL_KX_GROUPS).ok_or(FnError::Unknown(
        "Failed to choose group in key exchange".to_string(),
    ))?;
    // Shared Secret
    let kx: KeyExchange = deterministic_key_exchange(skxg)?;
    let shared = kx.complete(server_public_key).ok_or(FnError::Unknown(
        "Failed to complete key exchange".to_string(),
    ))?;

    // Key Schedule with or without PSK
    let shared_secret = &shared.shared_secret;
    let key_schedule = match psk {
        None => KeyScheduleNonSecret::new(suite.hkdf_algorithm).into_handshake(shared_secret),
        Some(psk) => KeyScheduleEarly::new(suite.hkdf_algorithm, psk.as_slice()).into_handshake(shared_secret),
    };

    Ok(key_schedule)
}

fn tls13_get_server_key_share(
    server_extensions: &Vec<ServerExtension>,
) -> Result<&KeyShareEntry, FnError> {
    let server_extension = server_extensions
        .find_extension(ExtensionType::KeyShare)
        .ok_or(FnError::Unknown("KeyShare extension not found".to_string()))?;

    if let ServerExtension::KeyShare(keyshare) = server_extension {
        Ok(keyshare)
    } else {
        Err(FnError::Unknown("KeyShare extension not found".to_string()))
    }
}

// ----
// seed_client_attacker12()
// ----

fn tls12_key_exchange(server_ecdh_params: &ServerECDHParams) -> Result<KeyExchangeResult, FnError> {
    let group = NamedGroup::secp384r1; // todo https://gitlab.inria.fr/mammann/tlspuffin/-/issues/45
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
    let suite = &rustls::suites::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256; // todo https://gitlab.inria.fr/mammann/tlspuffin/-/issues/45

    let mut server_random_bytes = vec![0; 32];

    server_random.write_slice(&mut server_random_bytes);

    let server_random = server_random_bytes
        .try_into()
        .map_err(|_| FnError::Unknown("Server random did not have length of 32".to_string()))?;
    let randoms = ConnectionRandoms {
        we_are_client: true,
        client: [1; 32], // todo https://gitlab.inria.fr/mammann/tlspuffin/-/issues/45
        server: server_random,
    };
    let kxd = tls12_key_exchange(server_ecdh_params)?;
    let suite12 = Tls12CipherSuite::try_from(suite)
        .map_err(|_err| FnError::Unknown("VersionNotCompatibleError".to_string()))?;
    let secrets = ConnectionSecrets::new(&randoms, suite12, &kxd.shared_secret);
    // master_secret is: 01 40 26 dd 53 3c 0a...
    Ok(secrets)
}

#[macro_export]
macro_rules! nyi_fn {
    () => {};
}

define_signature!(
    SIGNATURE,
    // constants
    fn_empty_bytes_vec
    fn_large_length
    fn_seq_0
    fn_seq_1
    fn_seq_10
    fn_seq_11
    fn_seq_12
    fn_seq_13
    fn_seq_14
    fn_seq_15
    fn_seq_16
    fn_seq_2
    fn_seq_3
    fn_seq_4
    fn_seq_5
    fn_seq_6
    fn_seq_7
    fn_seq_8
    fn_seq_9
    // messages
    fn_alert_close_notify
    fn_application_data
    fn_certificate
    fn_certificate13
    fn_certificate_request
    fn_certificate_request13
    fn_certificate_status
    fn_certificate_verify
    fn_change_cipher_spec
    fn_client_hello
    fn_client_key_exchange
    fn_empty_handshake_message
    fn_encrypted_extensions
    fn_finished
    fn_heartbeat
    fn_heartbeat_fake_length
    fn_hello_request
    fn_hello_retry_request
    fn_key_update
    fn_key_update_not_requested
    fn_message_hash
    fn_new_session_ticket
    fn_new_session_ticket13
    fn_opaque_message
    fn_server_hello
    fn_server_hello_done
    fn_server_key_exchange
    // extensions
    fn_al_protocol_negotiation
    fn_al_protocol_server_negotiation
    fn_append_preshared_keys_identity
    fn_append_vec
    fn_cert_extensions_append
    fn_cert_extensions_new
    fn_cert_req_extensions_append
    fn_cert_req_extensions_new
    fn_certificate_authorities_extension
    fn_client_extensions_append
    fn_client_extensions_new
    fn_cookie_extension
    fn_cookie_hello_retry_extension
    fn_derive_binder
    fn_derive_psk
    fn_early_data_extension
    fn_early_data_new_session_ticket_extension
    fn_early_data_server_extension
    fn_ec_point_formats_extension
    fn_ec_point_formats_server_extension
    fn_empty_preshared_keys_identity_vec
    fn_empty_vec_of_vec
    fn_extended_master_secret_extension
    fn_extended_master_secret_server_extension
    fn_fill_binder
    fn_get_ticket
    fn_get_ticket_age_add
    fn_get_ticket_nonce
    fn_hello_retry_extensions_append
    fn_hello_retry_extensions_new
    fn_key_share_deterministic_extension
    fn_key_share_deterministic_server_extension
    fn_key_share_extension
    fn_key_share_hello_retry_extension
    fn_key_share_server_extension
    fn_new_preshared_key_identity
    fn_new_session_ticket_extensions_append
    fn_new_session_ticket_extensions_new
    fn_preshared_keys_extension_empty_binder
    fn_preshared_keys_server_extension
    fn_psk_exchange_modes_extension
    fn_renegotiation_info_extension
    fn_renegotiation_info_server_extension
    fn_secp384r1_support_group_extension
    fn_server_extensions_append
    fn_server_extensions_new
    fn_server_name_extension
    fn_server_name_server_extension
    fn_session_ticket_offer_extension
    fn_session_ticket_request_extension
    fn_session_ticket_server_extension
    fn_signature_algorithm_cert_extension
    fn_signature_algorithm_cert_req_extension
    fn_signature_algorithm_extension
    fn_signed_certificate_timestamp_certificate_extension
    fn_signed_certificate_timestamp_extension
    fn_signed_certificate_timestamp_server_extension
    fn_status_request_certificate_extension
    fn_status_request_extension
    fn_status_request_server_extension
    fn_supported_versions12_extension
    fn_supported_versions12_hello_retry_extension
    fn_supported_versions12_server_extension
    fn_supported_versions13_extension
    fn_supported_versions13_hello_retry_extension
    fn_supported_versions13_server_extension
    fn_transport_parameters_draft_extension
    fn_transport_parameters_draft_server_extension
    fn_transport_parameters_extension
    fn_transport_parameters_server_extension
    fn_unknown_cert_request_extension
    fn_unknown_certificate_extension
    fn_unknown_client_extension
    fn_unknown_hello_retry_extension
    fn_unknown_new_session_ticket_extension
    fn_unknown_server_extension
    // fields
    fn_append_cipher_suite
    fn_cipher_suite12
    fn_cipher_suite13
    fn_compression
    fn_compressions
    fn_new_cipher_suites
    fn_new_random
    fn_new_session_id
    fn_protocol_version12
    fn_protocol_version13
    fn_secure_rsa_cipher_suite12
    fn_sign_transcript
    fn_verify_data
    fn_weak_export_cipher_suite
    fn_weak_export_cipher_suites_remove_me
    // utils
    fn_append_certificate
    fn_append_certificate_entry
    fn_append_transcript
    fn_decode_ecdh_params
    fn_decrypt_application
    fn_decrypt_handshake
    fn_encrypt12
    fn_encrypt_application
    fn_encrypt_handshake
    fn_new_certificate
    fn_new_certificate_entries
    fn_new_certificates
    fn_new_pubkey12
    fn_new_transcript
    fn_new_transcript12
    fn_no_psk
);
