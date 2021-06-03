use std::convert::{TryInto, TryFrom};

use ring::hkdf::Prk;
use rustls::conn::{ConnectionRandoms, ConnectionSecrets};
use rustls::hash_hs::HandshakeHash;
use rustls::internal::msgs::enums::{ExtensionType, NamedGroup};
use rustls::internal::msgs::handshake::{
    HasServerExtensions, KeyShareEntry, Random, ServerECDHParams, ServerExtension,
};
use rustls::internal::msgs::message::Message;
use rustls::key_schedule::{KeyScheduleHandshake, KeyScheduleNonSecret};
use rustls::kx::{KeyExchange, KeyExchangeResult};
use rustls::{kx, tls12, SupportedCipherSuite, ALL_KX_GROUPS};
use rustls::{NoKeyLog};
use rustls::suites::Tls12CipherSuite;

use fn_impl::*;

use crate::register_fn;
use crate::tls::key_exchange::deterministic_key_exchange;
use std::{error, fmt};

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

// ----
// Types
// ----

/// Special type which is used in [`crate::trace::InputAction`]. This is used if an recipe outputs
/// more or less than exactly one message.
#[derive(Clone)]
pub struct MultiMessage {
    pub messages: Vec<Message>,
}

// todo it would be possible generate dynamic functions like in criterion_group! macro
// or via a procedural macro.
// https://gitlab.inria.fr/mammann/tlspuffin/-/issues/28

fn prepare_key(
    server_public_key: &[u8],
    transcript: &HandshakeHash,
    write: bool,
) -> (&'static SupportedCipherSuite, Prk) {
    let client_random = &[1u8; 32]; // todo see op_random()
    let suite = &rustls::suites::TLS13_AES_128_GCM_SHA256; // todo see op_cipher_suites()
    let group = NamedGroup::X25519; // todo
    let mut key_schedule = create_handshake_key_schedule(server_public_key, suite, group);

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

    (suite, key)
}

fn create_handshake_key_schedule(
    server_public_key: &[u8],
    suite: &SupportedCipherSuite,
    group: NamedGroup,
) -> KeyScheduleHandshake {
    let skxg = KeyExchange::choose(group, &ALL_KX_GROUPS).unwrap();
    // Shared Secret
    let our_key_share: KeyExchange = deterministic_key_exchange(skxg);
    let shared = our_key_share.complete(server_public_key).unwrap();

    // Key Schedule without PSK
    let key_schedule =
        KeyScheduleNonSecret::new(suite.hkdf_algorithm).into_handshake(&shared.shared_secret);

    key_schedule
}

pub fn get_server_public_key(server_extensions: &Vec<ServerExtension>) -> Option<&KeyShareEntry> {
    let server_extension = server_extensions
        .find_extension(ExtensionType::KeyShare)
        .unwrap();

    if let ServerExtension::KeyShare(keyshare) = server_extension {
        Some(keyshare)
    } else {
        None
    }
}

// ----
// seed_client_attacker12()
// ----

fn new_key_exchange_result(server_ecdh_params: &ServerECDHParams) -> KeyExchangeResult {
    let group = NamedGroup::X25519; // todo
    let skxg = kx::KeyExchange::choose(group, &ALL_KX_GROUPS).unwrap();
    let kx: kx::KeyExchange = deterministic_key_exchange(skxg);
    let kxd = tls12::complete_ecdh(kx, &server_ecdh_params.public.0).unwrap();
    kxd
}

fn new_secrets(server_random: &Random, server_ecdh_params: &ServerECDHParams) -> ConnectionSecrets {
    let suite = &rustls::suites::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256; // todo

    let mut server_random_bytes = vec![0; 32];

    server_random.write_slice(&mut server_random_bytes);

    let randoms = ConnectionRandoms {
        we_are_client: true,
        client: [1; 32], // todo
        server: server_random_bytes.try_into().unwrap(),
    };
    let kxd = new_key_exchange_result(server_ecdh_params);
    let suite12 = Tls12CipherSuite::try_from(suite).unwrap();
    let secrets = ConnectionSecrets::new(&randoms, suite12, &kxd.shared_secret);
    secrets
}

/*pub trait IntoResult<T> {
    fn into_fn_result(self) -> T;
}

impl<T> IntoResult<Result<T, String>> for Result<T, ()> {
    fn into_fn_result(self) -> Result<T, String> {
        self.map_err(|()| format!("error"))
    }
}

impl<T> IntoResult<Result<T, String>> for Result<T, rustls::error::Error> {
    fn into_fn_result(self) -> Result<T, String> {
        self.map_err(|err| format!("error: {}", err))
    }
}

impl<T> IntoResult<Result<T, String>> for Option<T> {
    fn into_fn_result(self) -> Result<T, String> {
        match self {
            None => Err(format!("error")),
            Some(some) => Ok(some),
        }
    }
}*/

#[derive(Debug)]
pub struct NoneError;

impl std::error::Error for NoneError {}

impl fmt::Display for NoneError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NoneError")
    }
}

// ----
// Registry
// ----

register_fn!(
    REGISTERED_FN,
    REGISTERED_TYPES,
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
    // utils
    fn_concat_messages_2,
    fn_concat_messages_3,
);
