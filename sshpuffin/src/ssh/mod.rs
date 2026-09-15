// FIXME stabilize sshpuffin and reactivate the dead_code lint
//
//     Currently sshpuffin contains many functions that are unused but will be
//     necessary for the full implementation. To avoid the many unhelpful
//     warning messages, we deactivate the dead_code lint globally in this
//     module.
//
//     Once the necessary features and API of sshpuffin are more stable, we
//     should reactivate the dead_code lint, as it provides valuable insights.
#![allow(dead_code)]

use puffin::algebra::dynamic_function::FunctionAttributes;
pub mod deframe;
pub mod message;
pub(crate) mod seeds;
pub mod transcript;
#[path = "."]
pub mod fn_impl {
    pub mod fn_constants;
    pub mod fn_crypto;
    pub mod fn_message;

    pub use fn_constants::*;
    pub use fn_crypto::*;
    pub use fn_message::*;
}

use fn_impl::*;
use puffin::define_signature;

use crate::protocol::SshProtocolTypes;

define_signature!(
    SSH_SIGNATURE<SshProtocolTypes>,
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
    fn_empty_bytes_vec
    fn_u32_0
    fn_u32_1
    fn_u32_2
    fn_u32_3
    fn_u32_4
    fn_u32_5
    fn_u32_6
    fn_ssh_userauth
    fn_ssh_connection
    fn_method_password
    fn_method_publickey
    fn_method_none
    fn_username
    fn_password
    fn_channel_session
    fn_algo_ssh_ed25519
    fn_algo_ecdsa_sha2_nistp256
    fn_algo_rsa_sha2_256
    fn_algo_curve25519_sha256
    fn_algo_aes128_gcm
    fn_algo_aes128_ctr
    fn_algo_aes256_ctr
    fn_algo_3des_cbc
    fn_algo_chacha20_poly1305
    fn_algo_hmac_sha2_256
    fn_algo_hmac_sha2_512
    fn_algo_hmac_sha1
    fn_algo_none
    fn_algo_dh_group14_sha256
    fn_algo_ssh_rsa
    fn_algo_rsa_sha2_512
    fn_algo_kex_strict_c
    fn_algo_kex_strict_s
    fn_algo_unknown
    fn_algo_ext_info_c
    fn_ext_name_server_sig_algs
    fn_ext_val_rsa_sha2
    fn_cookie_zeros
    fn_cookie_ff
    fn_username_empty
    fn_username_root
    fn_username_long
    fn_password_empty
    fn_password_long
    fn_username_b
    fn_username_c
    fn_password_b
    fn_password_c
    fn_u32_7
    fn_u32_max
    fn_u32_0x10000
    fn_puffin_banner
    fn_puffin_id
    fn_placeholder_16bytes
    fn_placeholder_32bytes
    fn_channel_exec
    fn_channel_shell
    fn_channel_pty_req
    fn_disconnect_reason_protocol_error
    fn_disconnect_reason_service_not_available
    fn_password_auth_data
    fn_none_auth_data
    fn_exec_payload
    fn_channel_payload
    fn_ssh_bytes
    fn_ssh_bytes_empty
    fn_ssh_public_key
    fn_ssh_signature
    fn_raw_message
    fn_packet
    fn_onwire_message
    // Registers the whole-flight knowledge type `RawSshMessageFlight` in the
    // signature's type table so `(agent, n)/RawSshMessageFlight` query terms
    // round-trip through (de)serialization. `no_gen`: not for term generation.
    fn_raw_message_flight [no_gen]
    fn_onwire_data
    fn_namelist_empty
    fn_namelist_1
    fn_namelist_2
    fn_namelist_3
    fn_namelist_from_bytes
    fn_kex_algos
    fn_enc_algos
    fn_mac_algos
    fn_sig_schemes
    fn_comp_algos
    fn_banner
    fn_disconnect
    fn_ignore
    fn_ext_info
    fn_unimplemented
    fn_debug
    fn_service_request
    fn_service_accept
    fn_kex_init
    fn_kex_ecdh_init
    fn_kex_ecdh_reply
    fn_new_keys
    fn_client_kexinit_aesgcm
    fn_server_kexinit_aesgcm
    fn_user_auth_request
    fn_user_auth_failure
    fn_user_auth_success
    fn_user_auth_banner
    fn_global_request
    fn_request_success
    fn_request_failure
    fn_channel_open
    fn_channel_open_confirmation
    fn_channel_open_failure
    fn_channel_window_adjust
    fn_channel_data
    fn_channel_extended_data
    fn_channel_eof
    fn_channel_close
    fn_channel_request
    fn_channel_success
    fn_channel_failure
    fn_client_ecdh_privkey
    fn_client_ecdh_pubkey
    fn_ecdh_shared_secret
    fn_banner_id
    fn_kexinit_payload
    fn_server_ecdh_pubkey
    fn_server_hostkey
    fn_server_hostkey_raw
    fn_kex_exchange_hash
    // Explicit ExchangeHash -> SessionId conversion; makes session-id-vs-exchange-hash
    // confusion (rekey / Terrapin) a first-class, well-typed DY mutation.
    fn_session_id_from_hash
    // Sources the exchange hash H from the server's completion claim (session id)
    // instead of reconstructing it from a hard-coded client KEXINIT. `no_gen`: a
    // decryption-recipe helper (reads a claim), not for term generation.
    fn_claim_exchange_hash [no_gen]
    // Extracts the server's assigned channel number from its decrypted
    // CHANNEL_OPEN_CONFIRMATION, so a client can re-address channel traffic to the
    // channel THIS stack owns (libssh vs wolfSSH pick different numbers). `no_gen`:
    // decryption helper, not for term generation.
    fn_s2c_confirmation_sender_channel [no_gen]
    fn_derive_enc_key_c2s
    fn_derive_enc_key_s2c
    fn_encrypt_packet
    fn_decrypt_packet
    fn_derive_aes_key_c2s
    fn_derive_aes_key_s2c
    fn_derive_iv_c2s
    fn_derive_iv_s2c
    fn_encrypt_packet_aesgcm
    fn_decrypt_packet_aesgcm
    fn_decrypt_flight_aesgcm
    // Single comparison recipe of the AES-GCM decryption differential: folds a
    // server flight into one key-aligned `AlignedTranscript` (see
    // ssh/transcript.rs). `no_gen`: a comparison recipe, not for term generation.
    fn_fold_s2c_transcript [no_gen]
    fn_concat_raw_flights
    fn_derive_ctr_key_c2s
    fn_derive_ctr_key_s2c
    fn_derive_ctr_iv_c2s
    fn_derive_ctr_iv_s2c
    fn_derive_mac_key_c2s
    fn_derive_mac_key_s2c
    fn_encrypt_packet_ctr
    fn_decrypt_packet_ctr
    fn_algo_aes256_gcm
    fn_server_rsa_pubkey
    fn_server_rsa_pubkey_bytes
    fn_sign_exchange_hash [no_gen]
    fn_rsa_sha2_256_signature
    fn_client_a_pubkey_blob
    fn_client_b_pubkey_blob
    fn_client_c_pubkey_blob
    fn_sign_userauth [no_gen]
    fn_sign_userauth_b [no_gen]
    fn_sign_userauth_c [no_gen]
    fn_publickey_auth_data
);
