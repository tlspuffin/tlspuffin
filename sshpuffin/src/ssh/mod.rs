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
    fn_ssh_public_key [opaque]
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
    fn_namelist_2 [opaque]
    fn_namelist_3 [opaque]
    fn_namelist_from_bytes [opaque]
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
    // (drives the type byte from fn_u32_* atoms); the fixed 250-type convenience is
    // `no_gen` (a deterministic reproducer atom, not for blind generation).
    fn_raw_ssh_message [opaque]
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
    fn_ecdh_shared_secret [opaque]
    fn_banner_id [get]
    fn_kexinit_payload
    fn_server_ecdh_pubkey [get]
    fn_server_hostkey [get]
    fn_server_hostkey_raw [get]
    fn_kex_exchange_hash [opaque]
    // Explicit ExchangeHash -> SessionId conversion; makes session-id-vs-exchange-hash
    // confusion (rekey / Terrapin) a first-class, well-typed DY mutation.
    fn_session_id_from_hash
    // Sources the exchange hash H from the server's completion claim (session id)
    // instead of reconstructing it from a hard-coded client KEXINIT. `no_gen`: a
    // decryption-recipe helper (reads a claim), not for term generation.
    fn_claim_exchange_hash [get] [no_gen]
    // Extracts the server's assigned channel number from its decrypted
    // CHANNEL_OPEN_CONFIRMATION, so a client can re-address channel traffic to the
    // channel THIS stack owns (libssh vs wolfSSH pick different numbers). `no_gen`:
    // decryption helper, not for term generation.
    fn_s2c_confirmation_sender_channel [opaque] [no_gen]
    fn_decrypted_message [opaque] [no_gen]
    fn_sender_channel [get]
    fn_initial_window_size [get]
    fn_pk_ok_blob [get]
    fn_channel_send_budget [opaque]
    fn_bytes_of_len [opaque]
    fn_derive_enc_key_c2s [opaque]
    fn_derive_enc_key_s2c [opaque]
    fn_encrypt_packet [opaque]
    fn_decrypt_packet [opaque]
    fn_derive_aes_key_c2s [opaque]
    fn_derive_aes_key_s2c [opaque]
    fn_derive_iv_c2s [opaque]
    fn_derive_iv_s2c [opaque]
    fn_encrypt_packet_aesgcm [opaque]
    fn_decrypt_packet_aesgcm [opaque]
    fn_decrypt_flight_aesgcm [opaque]
    // Single comparison recipe of the AES-GCM decryption differential: folds a
    // server flight into one key-aligned `AlignedTranscript` (see
    // ssh/transcript.rs). `no_gen`: a comparison recipe, not for term generation.
    fn_fold_s2c_transcript [opaque] [no_gen]
    fn_concat_raw_flights
    fn_derive_ctr_key_c2s [opaque]
    fn_derive_ctr_key_s2c [opaque]
    fn_derive_ctr_iv_c2s [opaque]
    fn_derive_ctr_iv_s2c [opaque]
    fn_derive_mac_key_c2s [opaque]
    fn_derive_mac_key_s2c [opaque]
    fn_encrypt_packet_ctr [opaque]
    fn_decrypt_packet_ctr [opaque]
    fn_algo_aes256_gcm
    fn_server_rsa_pubkey
    fn_server_rsa_pubkey_bytes
    // Signs the exchange hash with the embedded host key (server-attacker
    // seeds). `no_gen`: a signing helper that needs a specific private key and a
    // well-formed transcript; generating it blindly only yields useless terms.
    fn_sign_exchange_hash [opaque] [no_gen]
    fn_rsa_sha2_256_signature
    fn_client_a_pubkey_blob
    fn_client_b_pubkey_blob
    fn_client_c_pubkey_blob
    // Sign a USERAUTH_REQUEST for client identity A / B / C with that identity's
    // private key. `no_gen`: each needs its matching key and the session's
    // exchange hash, so they are only meaningful when hand-wired in a seed, not
    // synthesised by the mutator.
    fn_sign_userauth [opaque] [no_gen]
    fn_sign_userauth_b [opaque] [no_gen]
    fn_sign_userauth_c [opaque] [no_gen]
    fn_publickey_auth_data
    fn_publickey_query_data
);

#[cfg(test)]
mod signature_tests {
    use std::collections::HashSet;

    use puffin::algebra::dynamic_function::DescribableFunction;
    use puffin::test_utils::zoo_read_encode;

    use super::SSH_SIGNATURE;
    use crate::protocol::SshProtocolBehavior;

    /// Encode / `try_read` / re-encode round-trip over the whole SSH signature,
    /// via the protocol-parametric `puffin::test_utils::zoo_read_encode` harness
    /// (TLS's `tests/term_zoo.rs::test_term_read_encode` is the reference). Locks the
    /// codec-consistency invariant: whenever a generated value reads back as its
    /// declared type, re-encoding it is byte-identical — i.e. `encode` and
    /// `try_read_bytes` are mutually consistent. A `read_wrong > 0` regression is a
    /// genuine `encode ≠ encode ∘ try_read` codec bug (many `read_fail`s are
    /// expected and benign — e.g. a bare `u32` atom cannot be re-read as a specific
    /// message type — so only `read_wrong` is asserted). PUT-gated because building
    /// the (empty) evaluation context needs a linked registry.
    #[cfg(any(has_put = "libssh0114", has_put = "wolfssh150"))]
    #[test]
    fn ssh_term_read_encode_roundtrip() {
        use crate::put_registry::ssh_registry;
        use crate::ssh::fn_impl::fn_concat_raw_flights;

        // `fn_concat_raw_flights` is the one documented exception to byte-exact
        // round-tripping, and it is BY DESIGN, not a codec bug. It joins two flights
        // at the message level; `RawSshMessageFlight::encode` then just concatenates
        // each message's wire bytes, while `RawSshMessageFlight::read` re-deframes the
        // WHOLE joined stream from scratch (`SshMessageDeframer`). For arbitrary,
        // misaligned zoo-generated pairs the re-deframe legitimately re-canonicalises
        // framing — e.g. a partial `OnWire` packet at the A/B boundary completes with
        // B's bytes and parses as a typed message, or a NEWKEYS in A flips the
        // deframer into opaque mode for B — so `encode ∘ read` need not reproduce the
        // naive concatenation. This is exactly the chunk-boundary re-framing the
        // decryption recipes rely on; the aligned-input identity property is locked
        // separately by `message::tests::concatenated_flights_reread_as_one_stream`.
        let ignored: HashSet<String> = [fn_concat_raw_flights.name().to_string()]
            .into_iter()
            .collect();
        // 400 draws per symbol across two seeds. Because `zoo_read_encode` generates
        // syntactically and evaluates once (see its `filter_evaluated = false` note)
        // instead of burning the 140k-try zoo budget forcing evaluable draws, this is
        // ~104k round-tripped terms in ~8s — an order of magnitude MORE codec
        // coverage than the naive `filter_evaluated = true` version gave (~6k terms)
        // in ~18 min. Draws, not per-symbol retries, are the cheap axis to spend on.
        let stats = zoo_read_encode::<SshProtocolBehavior>(
            &SSH_SIGNATURE,
            ssh_registry(),
            &[0, 1],
            400,
            &ignored,
        );
        log::info!("[ssh_term_read_encode_roundtrip] {stats:?}");
        assert!(
            stats.read_success > 0,
            "round-trip test was vacuous: no generated term read back as its declared type"
        );
        assert_eq!(
            stats.read_wrong, 0,
            "a value read back as its declared type but re-encoded differently: {stats:?}"
        );
    }

    /// Payload-evaluation check over the whole SSH signature — the correctness check
    /// behind the signature's `[opaque]` / `[get]` attributes (see
    /// `puffin::test_utils::zoo_payloads_eval` and `FunctionAttributes`). A payload
    /// placed under a parent whose encoding does not contain its arguments'
    /// concretizations (a KDF, hash, cipher, DH, or a re-encoding builder such as
    /// `fn_namelist_{2,3}`) raises `Error::TermBug` unless that parent is flagged
    /// `[opaque]` (or `[get]` for extractors). Asserting zero `TermBug`s locks the flag
    /// audit: adding a new re-encoding symbol without its flag fails here, and the
    /// per-parent table printed on failure names the symbol to flag.
    #[cfg(any(has_put = "libssh0114", has_put = "wolfssh150"))]
    #[test]
    fn ssh_term_payloads_eval() {
        use puffin::test_utils::zoo_payloads_eval;

        use crate::put_registry::ssh_registry;

        let stats = zoo_payloads_eval::<SshProtocolBehavior>(
            &SSH_SIGNATURE,
            ssh_registry(),
            &[0, 1, 2, 3, 4, 5, 6, 7],
            60,
            &HashSet::new(),
        );
        eprintln!(
            "[ssh_term_payloads_eval] success={} add_payload_fail={} termbug_fail={} other_eval_fail={}",
            stats.success, stats.add_payload_fail, stats.eval_payload_fail, stats.other_eval_fail
        );
        let mut rows: Vec<_> = stats.by_parent.iter().filter(|(_, v)| v.1 > 0).collect();
        rows.sort_by(|a, b| b.1 .1.cmp(&a.1 .1));
        assert!(stats.success > 0, "payload check was vacuous: {stats:?}");
        assert_eq!(
            stats.eval_payload_fail, 0,
            "payload evaluation hit Error::TermBug — a parent symbol is missing its \
             [opaque]/[get] flag. Parents of failing payloads (ok, TermBug): {rows:?}"
        );
    }
}
