//! The *tls* module provides concrete implementations for the functions used in the term.
//! The module offers a variety of [`DynamicFunction`]s which can be used in the fuzzing.

use fn_impl::*;
use puffin::{algebra::error::FnError, define_signature};

mod key_exchange;
mod key_schedule;

pub mod seeds;
pub mod violation;

/// This modules contains all the concrete implementations of function symbols.
#[path = "."]
pub mod fn_impl {
    pub mod fn_cert;
    pub mod fn_constants;
    pub mod fn_extensions;
    pub mod fn_fields;
    pub mod fn_messages;
    pub mod fn_transcript;
    pub mod fn_utils;

    pub use fn_cert::*;
    pub use fn_constants::*;
    pub use fn_extensions::*;
    pub use fn_fields::*;
    pub use fn_messages::*;
    pub use fn_transcript::*;
    pub use fn_utils::*;
}

/// Function symbol which can be used for debugging
///
#[allow(dead_code)]
fn fn_debug(
    message: &rustls::msgs::message::Message,
) -> Result<rustls::msgs::message::Message, FnError> {
    dbg!(message);
    Ok(message.clone())
}

#[macro_export]
macro_rules! nyi_fn {
    () => {};
}

define_signature!(
    TLS_SIGNATURE,
    // constants
    fn_true
    fn_false
    fn_seq_0
    fn_seq_1
    fn_seq_2
    fn_seq_3
    fn_seq_4
    fn_seq_5
    fn_seq_6
    fn_seq_7
    fn_seq_8
    fn_seq_9
    fn_seq_10
    fn_seq_11
    fn_seq_12
    fn_seq_13
    fn_seq_14
    fn_seq_15
    fn_seq_16
    fn_large_length
    fn_empty_bytes_vec
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
    fn_client_extensions_new
    fn_client_extensions_append
    fn_server_extensions_new
    fn_server_extensions_append
    fn_hello_retry_extensions_new
    fn_hello_retry_extensions_append
    fn_cert_req_extensions_new
    fn_cert_req_extensions_append
    fn_cert_extensions_new
    fn_cert_extensions_append
    fn_new_session_ticket_extensions_new
    fn_new_session_ticket_extensions_append
    fn_server_name_extension
    fn_server_name_server_extension
    fn_status_request_extension
    fn_status_request_server_extension
    fn_status_request_certificate_extension
    fn_support_group_extension
    fn_ec_point_formats_extension
    fn_ec_point_formats_server_extension
    fn_signature_algorithm_extension
    fn_signature_algorithm_cert_req_extension
    fn_empty_vec_of_vec
    fn_append_vec
    fn_al_protocol_negotiation
    fn_al_protocol_server_negotiation
    fn_signed_certificate_timestamp_extension
    fn_signed_certificate_timestamp_server_extension
    fn_signed_certificate_timestamp_certificate_extension
    fn_extended_master_secret_extension
    fn_extended_master_secret_server_extension
    fn_session_ticket_request_extension
    fn_session_ticket_offer_extension
    fn_session_ticket_server_extension
    fn_new_preshared_key_identity
    fn_empty_preshared_keys_identity_vec
    fn_append_preshared_keys_identity
    fn_preshared_keys_extension_empty_binder
    fn_preshared_keys_server_extension
    fn_early_data_extension
    fn_early_data_new_session_ticket_extension
    fn_early_data_server_extension
    fn_supported_versions12_extension
    fn_supported_versions13_extension
    fn_supported_versions12_hello_retry_extension
    fn_supported_versions13_hello_retry_extension
    fn_supported_versions12_server_extension
    fn_supported_versions13_server_extension
    fn_cookie_extension
    fn_cookie_hello_retry_extension
    fn_psk_exchange_mode_dhe_ke_extension
    fn_psk_exchange_mode_ke_extension
    fn_certificate_authorities_extension
    fn_signature_algorithm_cert_extension
    fn_key_share_deterministic_extension
    fn_key_share_extension
    fn_key_share_deterministic_server_extension
    fn_key_share_server_extension
    fn_key_share_hello_retry_extension
    fn_transport_parameters_extension
    fn_transport_parameters_server_extension
    fn_renegotiation_info_extension
    fn_renegotiation_info_server_extension
    fn_transport_parameters_draft_extension
    fn_transport_parameters_draft_server_extension
    fn_unknown_client_extension
    fn_unknown_server_extension
    fn_unknown_hello_retry_extension
    fn_unknown_cert_request_extension
    fn_unknown_new_session_ticket_extension
    fn_unknown_certificate_extension
    // fields
    fn_protocol_version13
    fn_protocol_version12
    fn_new_session_id
    fn_empty_session_id
    fn_new_random
    fn_compressions
    fn_compression
    fn_no_key_share
    fn_get_server_key_share
    fn_get_client_key_share
    fn_get_any_client_curve
    fn_verify_data
    fn_verify_data_server
    fn_sign_transcript
    fn_new_cipher_suites
    fn_append_cipher_suite
    fn_cipher_suite12
    fn_cipher_suite13_aes_128_gcm_sha256
    fn_cipher_suite13_aes_256_gcm_sha384
    fn_cipher_suite13_aes_128_ccm_sha256
    fn_weak_export_cipher_suite
    fn_secure_rsa_cipher_suite12
    // utils
    fn_new_transcript
    fn_append_transcript
    fn_decrypt_handshake
    fn_no_psk
    fn_psk
    fn_decrypt_application
    fn_encrypt_handshake
    fn_encrypt_application
    fn_derive_psk
    fn_derive_binder
    fn_fill_binder
    fn_get_ticket
    fn_get_ticket_age_add
    fn_get_ticket_nonce
    fn_new_transcript12
    fn_decode_ecdh_pubkey
    fn_encode_ec_pubkey12
    fn_new_pubkey12
    fn_encrypt12
    fn_new_certificate
    fn_new_certificates
    fn_append_certificate
    fn_new_certificate_entries
    fn_append_certificate_entry
    fn_named_group_secp384r1
    fn_named_group_x25519
    // transcript functions
    fn_server_hello_transcript
    fn_client_finished_transcript
    fn_server_finished_transcript
    fn_certificate_transcript
    // certificate functions
    fn_bob_cert
    fn_bob_key
    fn_alice_cert
    fn_alice_key
    fn_eve_cert
    fn_random_ec_cert
    fn_certificate_entry
    fn_empty_certificate_chain
    fn_append_certificate_entry
    fn_get_context
    fn_eve_pkcs1_signature
    fn_rsa_sign_client
    fn_rsa_sign_server
    fn_ecdsa_sign_client
    fn_ecdsa_sign_server
    fn_rsa_pss_signature_algorithm
    fn_rsa_pkcs1_signature_algorithm
    fn_invalid_signature_algorithm
    fn_ecdsa_signature_algorithm
);
