use rustls::internal::msgs::message::Message;

use fn_constants::*;
use fn_extensions::*;
use fn_messages::*;
use fn_utils::*;

use crate::register_fn;

mod fn_constants;
mod fn_extensions;
mod fn_messages;
mod fn_utils;
mod key_exchange;
mod tests;

/// This modules contains all the concrete implementations of function symbols.
pub mod fn_impl {
    pub use crate::{
        tls::fn_constants::*, tls::fn_extensions::*, tls::fn_messages::*, tls::fn_utils::*,
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
    fn_attack_cve_2021_3449,
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
