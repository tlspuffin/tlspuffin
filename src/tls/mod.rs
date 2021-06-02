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
    op_empty_bytes_vec,
    op_seq_0,
    op_seq_1,
    op_seq_2,
    op_seq_3,
    op_seq_4,
    op_seq_5,
    // extensions
    op_attack_cve_2021_3449,
    op_ec_point_formats,
    op_extensions_append,
    op_extensions_new,
    op_key_share_extension,
    op_renegotiation_info,
    op_server_name_extension,
    op_signature_algorithm_cert_extension,
    op_signature_algorithm_extension,
    op_signed_certificate_timestamp,
    op_supported_versions_extension,
    op_x25519_support_group_extension,
    // messages
    op_alert_close_notify,
    op_append_transcript,
    op_application_data,
    op_arbitrary_to_key,
    op_certificate,
    op_change_cipher_spec,
    op_change_cipher_spec12,
    op_cipher_suites,
    op_cipher_suites12,
    op_client_hello,
    op_client_key_exchange,
    op_compressions,
    op_decode_ecdh_params,
    op_decrypt,
    op_encrypt,
    op_encrypt12,
    op_encrypted_certificate,
    op_finished,
    op_finished12,
    op_hmac256,
    op_hmac256_new_key,
    op_new_pubkey12,
    op_new_transcript,
    op_new_transcript12,
    op_opaque_handshake_message,
    op_protocol_version12,
    op_random,
    op_server_certificate,
    op_server_hello,
    op_server_hello_done,
    op_server_key_exchange,
    op_session_id,
    op_sign_transcript,
    op_verify_data,
    // utils
    op_concat_messages_2,
    op_concat_messages_3,
);
