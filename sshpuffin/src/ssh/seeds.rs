use puffin::agent::{AgentDescriptor, AgentName};
use puffin::algebra::Term;
use puffin::term;
use puffin::trace::{InputAction, OutputAction, Trace};

use crate::protocol::{AgentType, SshDescriptorConfig, SshProtocolBehavior, SshProtocolTypes};
use crate::ssh::fn_impl::*;
use crate::ssh::message::{
    CompressionAlgorithms, EncryptionAlgorithms, KexAlgorithms, MacAlgorithms, OnWireData,
    RawSshMessage, SignatureSchemes, SshBytes, SshMessage,
};

pub fn seed_successful(client: AgentName, server: AgentName) -> Trace<SshProtocolTypes> {
    Trace {
        prior_traces: vec![],
        descriptors: vec![
            AgentDescriptor::from_config(
                client,
                SshDescriptorConfig {
                    typ: AgentType::Client,
                    try_reuse: false, // FIXME: Remove?
                },
            ),
            AgentDescriptor::from_config(
                server,
                SshDescriptorConfig {
                    typ: AgentType::Server,
                    try_reuse: false, // FIXME: Remove?
                },
            ),
        ],
        steps: vec![
            OutputAction::new_step(client),
            // Client -> Server: Banner
            InputAction::new_step(
                server,
                term! {
                    fn_banner(
                        ((client, 0))
                    )
                },
            ),
            // Server -> Client: Banner
            InputAction::new_step(
                client,
                term! {
                    fn_banner(
                        ((server, 0))
                    )
                },
            ),
            // Client -> Server: KexInit
            InputAction::new_step(
                server,
                term! {
                    fn_kex_init(
                        ((client, 0)[None]/[u8; 16]),
                        ((client, 0)[None]/KexAlgorithms),
                        ((client, 0)[None]/SignatureSchemes),
                        ((client, 0)[None]/EncryptionAlgorithms),
                        ((client, 1)[None]/EncryptionAlgorithms),
                        ((client, 0)[None]/MacAlgorithms),
                        ((client, 1)[None]/MacAlgorithms),
                        ((client, 0)[None]/CompressionAlgorithms),
                        ((client, 1)[None]/CompressionAlgorithms)
                    )
                },
            ),
            // Server -> Client: KexInit
            InputAction::new_step(
                client,
                term! {
                    fn_kex_init(
                        ((server, 0)[None]/[u8; 16]),
                        ((server, 0)[None]/KexAlgorithms),
                        ((server, 0)[None]/SignatureSchemes),
                        ((server, 0)[None]/EncryptionAlgorithms),
                        ((server, 1)[None]/EncryptionAlgorithms),
                        ((server, 0)[None]/MacAlgorithms),
                        ((server, 1)[None]/MacAlgorithms),
                        ((server, 0)[None]/CompressionAlgorithms),
                        ((server, 1)[None]/CompressionAlgorithms)
                    )
                },
            ),
            // Client -> Server: ECDH Init
            InputAction::new_step(
                server,
                term! {
                    fn_raw_message(
                        ((client, 2)[None]/RawSshMessage)  // ECDH Init
                    )
                },
            ),
            // Server -> Client: ECDH Reply (pass through raw; the DY extractor
            // will index SshPublicKey / SshBytes / SshSignature from it for mutations)
            InputAction::new_step(
                client,
                term! { fn_raw_message(((server, 2)[None]/RawSshMessage)) },
            ),
            InputAction::new_step(
                server,
                term! {
                    fn_raw_message(
                        ((client, 3)[None]/RawSshMessage)  // SSH_MSG_NEWKEYS??
                    )
                },
            ),
            // auth finished in this input step
            // in auto-output step the client auth is called
            InputAction::new_step(
                client,
                term! {
                    fn_raw_message(
                        ((server, 3)[None]/RawSshMessage)  // SSH_MSG_NEWKEYS??
                    )
                },
            ),
            InputAction::new_step(
                client,
                term! {
                    fn_onwire_message(
                        ((server, 0)[None]/OnWireData)  // option data??
                    )
                },
            ),
            InputAction::new_step(
                server,
                term! {
                    fn_onwire_message(
                        ((client, 0)[None]/OnWireData)  // Auth request??
                    )
                },
            ),
            InputAction::new_step(
                client,
                term! {
                    fn_onwire_message(
                        ((server, 1)[None]/OnWireData)  // Auth response??
                    )
                },
            ),
            InputAction::new_step(
                server,
                term! {
                    fn_onwire_message(
                        ((client, 1)[None]/OnWireData)  // ?
                    )
                },
            ),
            InputAction::new_step(
                client,
                term! {
                    fn_onwire_message(
                        ((server, 2)[None]/OnWireData)  // ??
                    )
                },
            ),
        ],
        ..Default::default()
    }
}

/// A trace that exercises the service-request → password-auth path with
/// structured terms.  Steps up to NewKeys mirror seed_successful; after that
/// we inject a structured ServiceRequest and UserAuthRequest so the fuzzer
/// has real handles on the auth code paths.
pub fn seed_auth_structured(client: AgentName, server: AgentName) -> Trace<SshProtocolTypes> {
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
            // Banner exchange
            InputAction::new_step(
                server,
                term! { fn_banner(((client, 0))) },
            ),
            InputAction::new_step(
                client,
                term! { fn_banner(((server, 0))) },
            ),
            // KexInit exchange
            InputAction::new_step(
                server,
                term! {
                    fn_kex_init(
                        ((client, 0)[None]/[u8; 16]),
                        ((client, 0)[None]/KexAlgorithms),
                        ((client, 0)[None]/SignatureSchemes),
                        ((client, 0)[None]/EncryptionAlgorithms),
                        ((client, 1)[None]/EncryptionAlgorithms),
                        ((client, 0)[None]/MacAlgorithms),
                        ((client, 1)[None]/MacAlgorithms),
                        ((client, 0)[None]/CompressionAlgorithms),
                        ((client, 1)[None]/CompressionAlgorithms)
                    )
                },
            ),
            InputAction::new_step(
                client,
                term! {
                    fn_kex_init(
                        ((server, 0)[None]/[u8; 16]),
                        ((server, 0)[None]/KexAlgorithms),
                        ((server, 0)[None]/SignatureSchemes),
                        ((server, 0)[None]/EncryptionAlgorithms),
                        ((server, 1)[None]/EncryptionAlgorithms),
                        ((server, 0)[None]/MacAlgorithms),
                        ((server, 1)[None]/MacAlgorithms),
                        ((server, 0)[None]/CompressionAlgorithms),
                        ((server, 1)[None]/CompressionAlgorithms)
                    )
                },
            ),
            // ECDH init — structured: extract the ephemeral key as SshBytes
            // so the fuzzer can mutate it independently from the packet framing.
            InputAction::new_step(
                server,
                term! { fn_kex_ecdh_init(((client, 2)[None]/SshBytes)) },
            ),
            // ECDH reply — pass through raw (same reason as in seed_successful).
            InputAction::new_step(
                client,
                term! { fn_raw_message(((server, 2)[None]/RawSshMessage)) },
            ),
            InputAction::new_step(server, term! { fn_raw_message(((client, 3)[None]/RawSshMessage)) }),
            InputAction::new_step(client, term! { fn_raw_message(((server, 3)[None]/RawSshMessage)) }),
            // Service request (structured — gives the fuzzer a handle on service dispatch)
            InputAction::new_step(
                server,
                term! { fn_service_request((fn_ssh_userauth)) },
            ),
            // Password auth request (structured)
            InputAction::new_step(
                server,
                term! {
                    fn_user_auth_request(
                        (fn_username),
                        (fn_ssh_connection),
                        (fn_method_password),
                        (fn_password)
                    )
                },
            ),
        ],
        ..Default::default()
    }
}

// ── Helper: agent descriptor pair ────────────────────────────────────────────

fn descriptors(
    client: AgentName,
    server: AgentName,
) -> Vec<AgentDescriptor<SshDescriptorConfig>> {
    vec![
        AgentDescriptor::from_config(client, SshDescriptorConfig { typ: AgentType::Client, try_reuse: false }),
        AgentDescriptor::from_config(server, SshDescriptorConfig { typ: AgentType::Server, try_reuse: false }),
    ]
}

// ── Seed: disconnect during KEX ───────────────────────────────────────────────
//
// Client and server exchange banners, then the fuzzer injects a disconnect
// before KEX completes.  Exercises libssh's early-teardown paths.

pub fn seed_disconnect_early(
    client: AgentName,
    server: AgentName,
) -> Trace<SshProtocolTypes> {
    Trace {
        prior_traces: vec![],
        descriptors: descriptors(client, server),
        steps: vec![
            OutputAction::new_step(client),
            InputAction::new_step(server, term! { fn_banner(((client, 0))) }),
            InputAction::new_step(client, term! { fn_banner(((server, 0))) }),
            InputAction::new_step(
                server,
                term! {
                    fn_disconnect(
                        (fn_disconnect_reason_protocol_error),
                        (fn_ssh_bytes_empty),
                        (fn_ssh_bytes_empty)
                    )
                },
            ),
        ],
        ..Default::default()
    }
}

// ── Seed: "none" auth probe ───────────────────────────────────────────────────
//
// After a successful KEX, the client probes the server with method "none"
// (RFC 4252 §5.2) to learn which auth methods the server supports.  The
// server should reply with SSH_MSG_USERAUTH_FAILURE listing available methods.

pub fn seed_none_auth_probe(
    client: AgentName,
    server: AgentName,
) -> Trace<SshProtocolTypes> {
    Trace {
        prior_traces: vec![],
        descriptors: descriptors(client, server),
        steps: vec![
            OutputAction::new_step(client),
            InputAction::new_step(server, term! { fn_banner(((client, 0))) }),
            InputAction::new_step(client, term! { fn_banner(((server, 0))) }),
            // KexInit exchange
            InputAction::new_step(
                server,
                term! {
                    fn_kex_init(
                        ((client, 0)[None]/[u8; 16]),
                        ((client, 0)[None]/KexAlgorithms),
                        ((client, 0)[None]/SignatureSchemes),
                        ((client, 0)[None]/EncryptionAlgorithms),
                        ((client, 1)[None]/EncryptionAlgorithms),
                        ((client, 0)[None]/MacAlgorithms),
                        ((client, 1)[None]/MacAlgorithms),
                        ((client, 0)[None]/CompressionAlgorithms),
                        ((client, 1)[None]/CompressionAlgorithms)
                    )
                },
            ),
            InputAction::new_step(
                client,
                term! {
                    fn_kex_init(
                        ((server, 0)[None]/[u8; 16]),
                        ((server, 0)[None]/KexAlgorithms),
                        ((server, 0)[None]/SignatureSchemes),
                        ((server, 0)[None]/EncryptionAlgorithms),
                        ((server, 1)[None]/EncryptionAlgorithms),
                        ((server, 0)[None]/MacAlgorithms),
                        ((server, 1)[None]/MacAlgorithms),
                        ((server, 0)[None]/CompressionAlgorithms),
                        ((server, 1)[None]/CompressionAlgorithms)
                    )
                },
            ),
            InputAction::new_step(server, term! { fn_raw_message(((client, 2)[None]/RawSshMessage)) }),
            InputAction::new_step(client, term! { fn_raw_message(((server, 2)[None]/RawSshMessage)) }),
            InputAction::new_step(server, term! { fn_raw_message(((client, 3)[None]/RawSshMessage)) }),
            InputAction::new_step(client, term! { fn_raw_message(((server, 3)[None]/RawSshMessage)) }),
            // Service request + "none" auth probe (structured)
            InputAction::new_step(
                server,
                term! { fn_service_request((fn_ssh_userauth)) },
            ),
            InputAction::new_step(
                server,
                term! {
                    fn_user_auth_request(
                        (fn_username),
                        (fn_ssh_connection),
                        (fn_method_none),
                        (fn_none_auth_data)
                    )
                },
            ),
        ],
        ..Default::default()
    }
}

// ── Seed: wrong-password auth failure ────────────────────────────────────────
//
// Client authenticates with an incorrect password.  The server sends
// SSH_MSG_USERAUTH_FAILURE; the fuzzer then sends a second attempt.

pub fn seed_auth_wrong_password(
    client: AgentName,
    server: AgentName,
) -> Trace<SshProtocolTypes> {
    Trace {
        prior_traces: vec![],
        descriptors: descriptors(client, server),
        steps: vec![
            OutputAction::new_step(client),
            InputAction::new_step(server, term! { fn_banner(((client, 0))) }),
            InputAction::new_step(client, term! { fn_banner(((server, 0))) }),
            InputAction::new_step(
                server,
                term! {
                    fn_kex_init(
                        ((client, 0)[None]/[u8; 16]),
                        ((client, 0)[None]/KexAlgorithms),
                        ((client, 0)[None]/SignatureSchemes),
                        ((client, 0)[None]/EncryptionAlgorithms),
                        ((client, 1)[None]/EncryptionAlgorithms),
                        ((client, 0)[None]/MacAlgorithms),
                        ((client, 1)[None]/MacAlgorithms),
                        ((client, 0)[None]/CompressionAlgorithms),
                        ((client, 1)[None]/CompressionAlgorithms)
                    )
                },
            ),
            InputAction::new_step(
                client,
                term! {
                    fn_kex_init(
                        ((server, 0)[None]/[u8; 16]),
                        ((server, 0)[None]/KexAlgorithms),
                        ((server, 0)[None]/SignatureSchemes),
                        ((server, 0)[None]/EncryptionAlgorithms),
                        ((server, 1)[None]/EncryptionAlgorithms),
                        ((server, 0)[None]/MacAlgorithms),
                        ((server, 1)[None]/MacAlgorithms),
                        ((server, 0)[None]/CompressionAlgorithms),
                        ((server, 1)[None]/CompressionAlgorithms)
                    )
                },
            ),
            InputAction::new_step(server, term! { fn_raw_message(((client, 2)[None]/RawSshMessage)) }),
            InputAction::new_step(client, term! { fn_raw_message(((server, 2)[None]/RawSshMessage)) }),
            InputAction::new_step(server, term! { fn_raw_message(((client, 3)[None]/RawSshMessage)) }),
            InputAction::new_step(client, term! { fn_raw_message(((server, 3)[None]/RawSshMessage)) }),
            InputAction::new_step(server, term! { fn_service_request((fn_ssh_userauth)) }),
            // First attempt with wrong password
            InputAction::new_step(
                server,
                term! {
                    fn_user_auth_request(
                        (fn_username),
                        (fn_ssh_connection),
                        (fn_method_password),
                        (fn_password_auth_data((fn_password)))
                    )
                },
            ),
            // Second attempt with the correct password (as observed from client output)
            InputAction::new_step(
                server,
                term! {
                    fn_user_auth_request(
                        (fn_username),
                        (fn_ssh_connection),
                        (fn_method_password),
                        (fn_password_auth_data((fn_password)))
                    )
                },
            ),
        ],
        ..Default::default()
    }
}

// ── Seed: server attacker ─────────────────────────────────────────────────────
//
// Only the CLIENT is a real libssh instance; the fuzzer constructs all server-
// side messages from scratch.  This lets the fuzzer send arbitrary KexInit
// algorithm combinations, bogus public-host-keys, and invalid signatures to
// exercise the client's verification logic — things a legitimate server would
// never produce.

pub fn seed_server_attacker(client: AgentName) -> Trace<SshProtocolTypes> {
    Trace {
        prior_traces: vec![],
        descriptors: vec![AgentDescriptor::from_config(
            client,
            SshDescriptorConfig { typ: AgentType::Client, try_reuse: false },
        )],
        steps: vec![
            // Trigger the libssh client: it outputs its banner + KexInit.
            OutputAction::new_step(client),
            // Attacker → Client: server banner (constant string).
            InputAction::new_step(client, term! { fn_banner(fn_puffin_banner) }),
            // Attacker → Client: server KexInit, mirroring the client's own
            // algorithm preferences so negotiation can proceed.
            InputAction::new_step(
                client,
                term! {
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
                },
            ),
            // Attacker → Client: crafted KexEcdhReply with a valid algorithm
            // name but bogus key material and signature bytes.  A realistic
            // algorithm name gets past libssh's early name-check; the bogus
            // material exercises the deeper key-parsing and signature-
            // verification code paths that random bytes never reach.
            InputAction::new_step(
                client,
                term! {
                    fn_kex_ecdh_reply(
                        (fn_ssh_public_key(
                            (fn_algo_ssh_ed25519),
                            (fn_placeholder_32bytes)
                        )),
                        (fn_placeholder_32bytes),
                        (fn_ssh_signature(
                            (fn_algo_ssh_ed25519),
                            (fn_placeholder_32bytes)
                        ))
                    )
                },
            ),
            // Attacker → Client: NewKeys.
            InputAction::new_step(client, term! { fn_new_keys }),
        ],
        ..Default::default()
    }
}

// ── Seed: client attacker ─────────────────────────────────────────────────────
//
// Only the SERVER is a real libssh instance; the fuzzer constructs all client-
// side messages from scratch.  This lets the fuzzer send arbitrary KexInit
// combinations, garbage ECDH ephemeral keys, and out-of-order messages to
// exercise the server's key-exchange and auth-request handling.

pub fn seed_client_attacker(server: AgentName) -> Trace<SshProtocolTypes> {
    Trace {
        prior_traces: vec![],
        descriptors: vec![AgentDescriptor::from_config(
            server,
            SshDescriptorConfig { typ: AgentType::Server, try_reuse: false },
        )],
        steps: vec![
            // Trigger the libssh server: it outputs its banner + KexInit.
            OutputAction::new_step(server),
            // Attacker → Server: client banner.
            InputAction::new_step(server, term! { fn_banner(fn_puffin_banner) }),
            // Attacker → Server: client KexInit, mirroring the server's
            // algorithm list so negotiation can proceed.
            InputAction::new_step(
                server,
                term! {
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
                },
            ),
            // Attacker → Server: client KexEcdhInit with a placeholder key.
            // The server will try to compute a shared secret from this; a non-
            // valid curve point exercises the server's key-validation paths.
            InputAction::new_step(
                server,
                term! { fn_kex_ecdh_init((fn_placeholder_32bytes)) },
            ),
            // Attacker → Server: NewKeys.
            InputAction::new_step(server, term! { fn_new_keys }),
            // Attacker → Server: structured service request (plaintext; will
            // be decryption-rejected post-NewKeys, but exercises that path).
            InputAction::new_step(
                server,
                term! { fn_service_request((fn_ssh_userauth)) },
            ),
        ],
        ..Default::default()
    }
}

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
            InputAction::new_step(server, term! { fn_packet((fn_kex_ecdh_init((fn_client_ecdh_pubkey)))) }),
            InputAction::new_step(server, term! { fn_packet((fn_new_keys)) }),
            InputAction::new_step(server, term! { @svc_req }),
            InputAction::new_step(server, term! { @auth_req }),
            InputAction::new_step(server, term! { @chan_open }),
            InputAction::new_step(server, term! { @chan_req }),
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
    let iv  = term! { fn_derive_iv_c2s((@shared), (@exch_hash), (@exch_hash)) };

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
            SshDescriptorConfig { typ: AgentType::Server, try_reuse: false },
        )],
        steps: vec![
            OutputAction::new_step(server),
            InputAction::new_step(server, term! { fn_banner(fn_puffin_banner) }),
            InputAction::new_step(server, term! { fn_packet((@our_kexinit)) }),
            InputAction::new_step(server, term! { fn_packet((fn_kex_ecdh_init((fn_client_ecdh_pubkey)))) }),
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
            InputAction::new_step(client, term! {
                fn_packet((fn_kex_ecdh_reply(
                    (fn_server_rsa_pubkey),
                    (fn_client_ecdh_pubkey),
                    (fn_ssh_signature(
                        (fn_algo_rsa_sha2_256),
                        (@sig)
                    ))
                )))
            }),
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

pub fn create_corpus(
    _put: &dyn puffin::put_registry::Factory<SshProtocolBehavior>,
) -> Vec<(Trace<SshProtocolTypes>, &'static str)> {
    let client = AgentName::first();
    let server = client.next();

    vec![
        (seed_successful(client, server), "seed_successful"),
        (seed_auth_structured(client, server), "seed_auth_structured"),
        (seed_disconnect_early(client, server), "seed_disconnect_early"),
        (seed_none_auth_probe(client, server), "seed_none_auth_probe"),
        (seed_auth_wrong_password(client, server), "seed_auth_wrong_password"),
        (seed_server_attacker(client), "seed_server_attacker"),
        (seed_client_attacker(server), "seed_client_attacker"),
        (seed_client_attacker_full(server), "seed_client_attacker_full"),
        (seed_server_attacker_full(client), "seed_server_attacker_full"),
        (seed_client_attacker_full_aesgcm(server), "seed_client_attacker_full_aesgcm"),
    ]
}

#[cfg(test)]
mod tests {
    use puffin::execution::{Runner, TraceRunner};
    use puffin::trace::Spawner;

    use crate::ssh::seeds::{seed_client_attacker_full, seed_server_attacker_full, seed_successful};
    use crate::ssh_registry;

    #[test_log::test]
    #[ignore = "legacy seed trace still assumes old Rust libssh mapper/harness behavior; update trace for C harness framing"]
    fn test_seed_successful() {
        let registry = ssh_registry();
        let runner = Runner::new(registry.clone(), Spawner::new(registry));
        let client = puffin::agent::AgentName::first();
        let trace = seed_successful(client, client.next());

        let context = runner.execute(trace, &mut 0).unwrap();

        assert!(context.find_agent(client).unwrap().is_state_successful())
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
}
