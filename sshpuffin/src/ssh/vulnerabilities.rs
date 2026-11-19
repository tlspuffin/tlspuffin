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
