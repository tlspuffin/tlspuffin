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
pub(crate) mod differential;
pub mod message;
pub mod seeds;
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

// Flags (see `FunctionAttributes`): `[opaque]`, `[get]` and `[list]` steer where puffin can
// place payloads, `[no_gen]` what the term zoo generates. All four are checked by
// `sshpuffin/tests/term_zoo.rs`.
//   * no flag   — a builder whose encoding contains each argument's encoding
//     (`unflagged_symbols_contain_their_arguments`);
//   * [opaque]  — the encoding contains none of the arguments' (hash, KDF, DH, cipher, signature,
//     decryption, and the filler generator `fn_bytes_of_len`);
//   * [get]     — an accessor returning a field of its argument (TLS convention; also a truncating
//     conversion, like TLS's `fn_u32_to_u16`);
//   * [no_gen]  — not generated at the top level: probe/reproducer atoms, recipe helpers, and
//     symbols the zoo cannot build an evaluable term for (the KDFs need an exchange hash, the
//     decryptions a real ciphertext, `fn_encrypt_packet{,_ctr}` keys of an exact length); checked
//     by `tests/term_zoo.rs::test_term_eval`.
//   * [list]    — a list built one element at a time, like tlspuffin's (`fn_namelist_empty`,
//     `fn_namelist_append`); puffin finds the appended element at the end of the list.
define_signature!(
    SSH_SIGNATURE<SshProtocolTypes>,
    fn_true
    fn_false
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
    fn_u32_8
    fn_u32_9
    fn_u32_10
    fn_u32_11
    fn_u32_12
    fn_u32_13
    fn_u32_14
    fn_u32_15
    // Sentinel counter for AES-GCM sealing; the per-execution `preprocess_trace`
    // pass rewrites it to the packet's true wire position. `no_gen`: it is a
    // marker matched by symbol, never a value to synthesise during generation.
    fn_u32_auto [no_gen]
    fn_u32_max
    fn_u32_0x10000
    fn_puffin_banner
    fn_puffin_id
    // Out-of-spec banner / version identification-string probes (hypotheses H2/H3
    // of `banner_probe_seed`). Each PAIR = a wire banner (String, includes CR-LF) + its
    // RFC-4253-§8-canonical V_C (SshBytes, only trailing CR-LF stripped). `no_gen`:
    // deterministic reproducer atoms, not for blind term generation.
    fn_banner_wire_oversized [no_gen]
    fn_vc_oversized [no_gen]
    fn_banner_wire_ctrl [no_gen]
    fn_vc_ctrl [no_gen]
    fn_placeholder_16bytes
    fn_placeholder_32bytes
    fn_channel_exec
    fn_channel_shell
    fn_channel_pty_req
    fn_disconnect_reason_protocol_error
    fn_disconnect_reason_service_not_available
    fn_password_auth_data
    fn_password_change_auth_data
    fn_none_auth_data
    // TCP/IP forwarding (RFC 4254 §7; issue #1047 items 2-4): request/channel-type
    // name atoms + type-specific payload builders.
    fn_request_tcpip_forward
    fn_request_cancel_tcpip_forward
    fn_request_unknown
    // SSH message numbers selecting a message out of a decrypted flight.
    fn_msg_kexinit
    fn_msg_kex_ecdh_reply
    fn_msg_userauth_pk_ok
    fn_msg_channel_open
    fn_msg_channel_open_confirmation
    fn_msg_channel_window_adjust
    fn_msg_channel_request
    fn_ordinal_first
    fn_ordinal_second
    fn_window_size_default
    fn_max_packet_size_default
    fn_extended_data_stderr
    fn_channel_type_direct_tcpip
    fn_channel_type_forwarded_tcpip
    fn_tcpip_forward_data
    fn_direct_tcpip_data
    fn_forwarded_tcpip_data
    fn_addr_localhost
    fn_port_ssh
    fn_exec_payload
    fn_exec_command_userauth
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
    fn_namelist_empty [list] // the empty name-list, start of fn_namelist_append
    fn_namelist_1
    fn_namelist_append [list] // a name-list and one more name
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
    // Arbitrary / unknown-type SSH message injection (RFC 4253 §11.4 probing;
    // issue #1047 item 7). `fn_raw_ssh_message(number, body)` is generator-usable
    // (the type byte comes from an `fn_msg_*` atom or `fn_msg_number(fn_u32_*)`); the
    // fixed 250-type convenience is `no_gen` (a deterministic reproducer atom, not for
    // blind generation).
    fn_raw_ssh_message
    fn_msg_number [get] // the low byte of a u32
    fn_msg_unknown_highnumber [no_gen]
    fn_debug
    fn_service_request
    fn_service_accept
    fn_kex_init
    fn_kex_ecdh_init
    // Classic modular-DH KEXDH_INIT (msg 30) + out-of-range exponent atoms
    // (RFC 4253 §8 range validation; issue #1047 item 1).
    fn_kex_dh_init
    fn_dh_exponent_zero
    fn_dh_exponent_one
    fn_dh_exponent_huge
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
    // Channel-id producers (type-directed): a converter from any u32 and the fixed
    // channel 0 the honest seeds use. See `ChannelId` in ssh/message.rs.
    fn_channel_id
    fn_channel_id_0
    fn_client_ecdh_privkey
    fn_client_ecdh_pubkey
    fn_ecdh_shared_secret [opaque] // X25519
    fn_banner_id [get] // the banner line without its CR-LF
    fn_kexinit_payload
    fn_server_ecdh_pubkey [get] // Q_S field of a KEX_ECDH_REPLY
    fn_server_hostkey [get] // K_S field of a KEX_ECDH_REPLY
    fn_server_hostkey_raw [get] // K_S field, from the raw packet
    fn_kex_exchange_hash [opaque] // SHA-256
    // Explicit ExchangeHash -> SessionId conversion; makes session-id-vs-exchange-hash
    // confusion (rekey / Terrapin) a first-class, well-typed DY mutation.
    fn_session_id_from_hash
    // Sources the exchange hash H from the server's completion claim (session id)
    // instead of reconstructing it from a hard-coded client KEXINIT. `no_gen`: a
    // decryption-recipe helper (reads a claim), not for term generation.
    fn_claim_exchange_hash [get] [no_gen] // the session id carried by a claim
    // Extracts the server's assigned channel number from its decrypted
    // CHANNEL_OPEN_CONFIRMATION, so a client can re-address channel traffic to the
    // channel THIS stack owns (libssh vs wolfSSH pick different numbers). `no_gen`:
    // decryption helper, not for term generation.
    fn_s2c_confirmation_sender_channel [opaque] [no_gen] // decryption
    fn_decrypted_message [opaque] [no_gen] // decryption
    fn_sender_channel [get] // sender_channel field
    fn_initial_window_size [get] // initial_window_size field
    fn_pk_ok_blob [get] // key blob field of a PK_OK
    fn_channel_send_budget [get] // the smaller of two fields
    fn_bytes_of_len [opaque] // `len` filler bytes, not the length itself
    fn_derive_enc_key_c2s [opaque] [no_gen] // KDF
    fn_derive_enc_key_s2c [opaque] [no_gen] // KDF
    fn_encrypt_packet [opaque] [no_gen] // encryption
    fn_decrypt_packet [opaque] [no_gen] // decryption
    fn_derive_aes_key_c2s [opaque] [no_gen] // KDF
    fn_derive_aes_key_s2c [opaque] [no_gen] // KDF
    fn_derive_iv_c2s [opaque] [no_gen] // KDF
    fn_derive_iv_s2c [opaque] [no_gen] // KDF
    fn_encrypt_packet_aesgcm [opaque] // encryption
    fn_decrypt_packet_aesgcm [opaque] [no_gen] // decryption
    fn_decrypt_flight_aesgcm [opaque] [no_gen] // decryption
    // Single comparison recipe of the AES-GCM decryption differential: folds a
    // server flight into one key-aligned `AlignedTranscript` (see
    // ssh/transcript.rs). `no_gen`: a comparison recipe, not for term generation.
    fn_fold_s2c_transcript [opaque] [no_gen] // decryption
    // Joins two flights (not a list and one element, so not `[list]`).
    fn_concat_raw_flights
    fn_derive_ctr_key_c2s [opaque] [no_gen] // KDF
    fn_derive_ctr_key_s2c [opaque] [no_gen] // KDF
    fn_derive_ctr_iv_c2s [opaque] [no_gen] // KDF
    fn_derive_ctr_iv_s2c [opaque] [no_gen] // KDF
    fn_derive_mac_key_c2s [opaque] [no_gen] // KDF
    fn_derive_mac_key_s2c [opaque] [no_gen] // KDF
    fn_encrypt_packet_ctr [opaque] [no_gen] // encryption + MAC
    fn_decrypt_packet_ctr [opaque] [no_gen] // decryption
    fn_algo_aes256_gcm
    fn_server_rsa_pubkey
    fn_server_rsa_pubkey_bytes
    // Signs the exchange hash with the embedded host key (server-attacker
    // seeds). `no_gen`: a signing helper that needs a specific private key and a
    // well-formed transcript; generating it blindly only yields useless terms.
    fn_sign_exchange_hash [opaque] [no_gen] // RSA signature
    fn_rsa_sha2_256_signature
    fn_client_a_pubkey_blob
    fn_client_b_pubkey_blob
    fn_client_c_pubkey_blob
    // Sign a USERAUTH_REQUEST for client identity A / B / C with that identity's
    // private key. `no_gen`: each needs its matching key and the session's
    // exchange hash, so they are only meaningful when hand-wired in a seed, not
    // synthesised by the mutator.
    fn_sign_userauth [opaque] [no_gen] // RSA signature
    fn_sign_userauth_b [opaque] [no_gen] // RSA signature
    fn_sign_userauth_c [opaque] [no_gen] // RSA signature
    fn_publickey_auth_data
    fn_publickey_query_data
);
