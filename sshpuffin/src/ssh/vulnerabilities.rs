//! Witness traces for the SSH vulnerability catalogue
//! (`puffin-build/vendors/<vendor>/vulnerabilities.toml`).
//!
//! Each `#[puffin::witness("<ID>")]` function returns a `Trace` that triggers the
//! catalogue entry's oracle on an affected PUT and nothing on a fixed one; it
//! auto-registers at link time (linkme), so there is no per-CVE test to write. The
//! catalogue test (`sshpuffin/tests/catalogue.rs`) runs every witness on every PUT
//! and checks the outcome against the PUT's catalogue state.
//!
//! Style reference: the `seed_server_attacker_*` traces in `seeds.rs` (the attacker
//! plays the server against a real CLIENT PUT).

use puffin::agent::{AgentDescriptor, AgentName};
use puffin::term;
use puffin::trace::{InputAction, OutputAction, Trace};

use crate::protocol::{AgentType, SshDescriptorConfig, SshProtocolTypes};
use crate::ssh::fn_impl::*;
use crate::ssh::seeds::{seed_client_attacker_rekey_dh_group16, seed_client_attacker_rekey_guess};

/// CVE-2025-14942 — wolfSSH client KEX state machine accepts user-authentication
/// messages out of order, during key exchange (CWE-287, wolfSSH <= 1.4.21; fixed in
/// 1.4.22 by wolfSSL/wolfssh#855). The vulnerable `IsMessageAllowedClient` defaults
/// to ALLOW, so a USERAUTH_SUCCESS received while the client is still keying is
/// accepted; the fixed client rejects auth-range messages until key exchange has
/// completed and a user-auth request has been sent.
///
/// Reachability: wire-reachable. The attacker plays the server; the real wolfSSH
/// CLIENT PUT is driven through the `while (ssh->isKeying)` receive loop
/// (connectState == CONNECT_CLIENT_KEXDH_INIT_SENT) and fed a single cleartext
/// USERAUTH_SUCCESS before any KEXDH reply. The vulnerable client processes it and
/// reaches SERVER_USERAUTH_ACCEPT_DONE while still keying — the harness raises
/// `auth_while_keying` and the claim oracle reports "Authentication bypass"
/// (sshpuffin/src/violation.rs). The fixed client rejects the message (WS message
/// not allowed), never reaches that state, and the witness yields no objective.
///
/// Minimal: the smallest trace that reaches the vulnerable state — banner + KEXINIT
/// so the client sends KEX_ECDH_INIT and starts keying, then the one out-of-order
/// USERAUTH_SUCCESS. No KEXDH reply, NewKeys, channel or default-list narrowing is
/// needed (default `SshDescriptorConfig`).
#[puffin::witness("CVE-2025-14942")]
pub fn witness_cve_2025_14942(client: AgentName) -> Trace<SshProtocolTypes> {
    // Fixed server KEXINIT (aes256-gcm, rsa-sha2-256 host key) — the algorithms the
    // wolfSSH client accepts, so it answers with KEX_ECDH_INIT and begins keying.
    let server_kexinit = term! { fn_server_kexinit_aesgcm((fn_placeholder_16bytes)) };

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
            OutputAction::new_step(client), // client banner
            InputAction::new_step(client, term! { fn_banner(fn_puffin_banner) }),
            OutputAction::new_step(client), // client KEXINIT
            InputAction::new_step(client, term! { fn_packet((@server_kexinit)) }),
            OutputAction::new_step(client), // client KEX_ECDH_INIT -> now keying
            // Out-of-order, cleartext USERAUTH_SUCCESS during key exchange.
            InputAction::new_step(client, term! { fn_packet((fn_user_auth_success)) }),
            OutputAction::new_step(client), // vulnerable client accepts it -> violation
        ],
        ..Default::default()
    }
}

/// CVE-2023-1667 — libssh SERVER NULL-pointer dereference during rekeying with KEX
/// "algorithm guessing" (CWE-476; libssh 0.9.1–0.9.6 and 0.10.0–0.10.4; fixed in 0.10.5 /
/// 0.9.7, GHSL-2023-032). The state tracking a received KEXINIT was keyed only on the
/// presence of the methods fields, and `first_kex_packet_follows` was handled only
/// partially: a post-authentication, client-initiated rekey whose KEXINIT sets
/// `first_kex_packet_follows = 1` (RFC 4253 §7.1) drives the server to dereference a NULL
/// kex-methods pointer and crash (ASan SEGV). The fix adds a `methods[0] != NULL` guard in
/// `server_set_kex` and tracks KEXINIT state with an explicit flag.
///
/// Reachability: wire-reachable, post-authentication. The attacker plays the client
/// against a real libssh SERVER PUT: initial KEX + NEWKEYS, then publickey auth (key A) —
/// libssh's packet filter only admits a rekey KEXINIT once the connection is established —
/// then the rekey KEXINIT carrying the guessing flag. On an affected server ASan reports
/// the NULL dereference (crash oracle); a fixed server survives and the witness yields no
/// objective. The trace is `seed_client_attacker_rekey_guess` (seeds.rs).
#[puffin::witness("CVE-2023-1667")]
pub fn witness_cve_2023_1667(server: AgentName) -> Trace<SshProtocolTypes> {
    seed_client_attacker_rekey_guess(server)
}

/// CVE-2021-3634 — libssh heap buffer over-read/over-write when a rekey changes the KEX to
/// one with a different digest size (CWE-787; libssh 0.9.1–0.9.5, fixed in 0.9.6 by commit
/// d3060bc8; OSS-Fuzz 35485). `session_id` and the secret hash shared one `digest_len`, so
/// a re-exchange whose hash is larger than the first leaves the 32-byte `session_id` buffer
/// accessed with the new, larger length in `ssh_packet_set_newkeys` (malloc/memcpy) and
/// `crypto_free` (`explicit_bzero`). The fix splits out `session_id_len`.
///
/// Reachability: wire-reachable, post-authentication. The attacker plays the client against
/// a real libssh SERVER PUT: a curve25519-sha256 first handshake (32-byte session id) + NEWKEYS,
/// publickey auth (key A), then a rekey whose KEXINIT offers only `diffie-hellman-group16-sha512`
/// (64-byte digest) and whose KEXDH_INIT carries an in-range `e`. The server completes the
/// re-KEX (`digest_len = 64`) and, on the rekey NEWKEYS, reads/writes the carried-over 32-byte
/// `session_id` with the 64-byte length — ASan reports the heap overflow on an affected server;
/// a fixed server (>= 0.9.6) survives and the witness yields no objective. All rekey packets are
/// encrypted under the FIRST keys, so no post-rekey secret is needed. The trace is
/// `seed_client_attacker_rekey_dh_group16` (seeds.rs); its only new Mapper atom is the
/// `fn_algo_dh_group16_sha512` KEX name (no existing term yields a >32-byte-digest KEX).
#[puffin::witness("CVE-2021-3634")]
pub fn witness_cve_2021_3634(server: AgentName) -> Trace<SshProtocolTypes> {
    seed_client_attacker_rekey_dh_group16(server)
}
