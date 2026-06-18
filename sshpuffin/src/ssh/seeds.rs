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
    let iv  = term! { fn_derive_iv_s2c((@shared), (@exch_hash), (@exch_hash)) };

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
            SshDescriptorConfig { typ: AgentType::Client, try_reuse: false },
        )],
        steps: vec![
            OutputAction::new_step(client),
            InputAction::new_step(client, term! { fn_banner(fn_puffin_banner) }),
            InputAction::new_step(client, term! { fn_packet((@our_kexinit)) }),
            InputAction::new_step(client, term! {
                fn_packet((fn_kex_ecdh_reply(
                    (fn_server_rsa_pubkey),
                    (fn_client_ecdh_pubkey),
                    (fn_ssh_signature((fn_algo_rsa_sha2_256), (@sig)))
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

    // Only seeds that complete a full handshake are kept (the legacy mutual /
    // pre-crypto stub seeds were pruned). The chacha20 *_full seeds complete on
    // libssh; the *_aesgcm seeds complete on BOTH libssh and wolfSSH.
    vec![
        (seed_client_attacker_full(server), "seed_client_attacker_full"),
        (seed_server_attacker_full(client), "seed_server_attacker_full"),
        (seed_client_attacker_full_aesgcm(server), "seed_client_attacker_full_aesgcm"),
        (seed_server_attacker_full_aesgcm(client), "seed_server_attacker_full_aesgcm"),
    ]
}

#[cfg(test)]
mod tests {
    use puffin::execution::{Runner, TraceRunner};
    use puffin::trace::Spawner;

    use crate::ssh::seeds::{seed_client_attacker_full, seed_server_attacker_full};
    use crate::ssh_registry;

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
        let spawner = Spawner::new(registry.clone())
            .with_mapping(&[(server, PutDescriptor::new(wolfssh_put, PutOptions::default()))]);
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
