//! Witness traces for the SSH vulnerability catalogue
//! (`puffin-build/vendors/<vendor>/vulnerabilities.toml`).
//!
//! Each `#[puffin::witness("<ID>")]` function returns a `Trace` that triggers the catalogue
//! entry's oracle on an affected PUT and nothing on a fixed one; it auto-registers at link time
//! (linkme), so there is no per-CVE test to write. The catalogue test
//! (`sshpuffin/tests/catalogue.rs`) runs every witness on every PUT of the binary and checks the
//! outcome against the PUT's catalogue state.

use puffin::agent::{AgentDescriptor, AgentName};
use puffin::term;
use puffin::trace::{InputAction, OutputAction, Trace};

use crate::protocol::{AgentType, SshDescriptorConfig, SshProtocolTypes};
use crate::ssh::fn_impl::*;

/// CVE-2025-14942 — the wolfSSH client's key-exchange state machine accepts user-authentication
/// messages out of order, during key exchange (CWE-287; wolfSSH <= 1.4.21, fixed in 1.4.22 by
/// wolfSSL/wolfssh#855). The vulnerable `IsMessageAllowedClient` defaults to allow, so a
/// USERAUTH_SUCCESS received while the client is still keying is accepted; the fixed client rejects
/// auth-range messages until key exchange has completed and a user-auth request has been sent.
///
/// The attacker plays the server against a real wolfSSH CLIENT PUT: banner and KEXINIT, so the
/// client sends KEX_ECDH_INIT and starts keying, then one cleartext USERAUTH_SUCCESS before any
/// KEXDH reply. The vulnerable client reaches SERVER_USERAUTH_ACCEPT_DONE while still keying: the
/// harness raises `auth_while_keying` and the claim oracle reports "Authentication bypass". The
/// fixed client rejects the message.
#[puffin::witness("CVE-2025-14942")]
pub fn witness_cve_2025_14942(client: AgentName) -> Trace<SshProtocolTypes> {
    // The server KEXINIT of the AES-GCM seeds: algorithms the wolfSSH client accepts.
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
            OutputAction::new_step(client), // client KEX_ECDH_INIT: now keying
            // Out of order: a cleartext USERAUTH_SUCCESS during the key exchange.
            InputAction::new_step(client, term! { fn_packet((fn_user_auth_success)) }),
            OutputAction::new_step(client),
        ],
        ..Default::default()
    }
}

/// CVE-2025-11625 — wolfSSH client host-authentication bypass (CWE-287; wolfSSH <= 1.4.20, fixed in
/// 1.4.21 by wolfSSL/wolfssh#840). The client accepts a NEWKEYS before any KEX_ECDH_REPLY: the
/// vulnerable `DoNewKeys` clears the keying flag unconditionally, so the client leaves its
/// `while (ssh->isKeying)` loop and reaches CONNECT_KEYED without ever running `DoKexDhReply`,
/// where the server's host-key signature over H is verified. It then proceeds to user
/// authentication over an unencrypted transport. The fix splits the keying flag into SELF/PEER bits
/// and rejects a NEWKEYS received while the client is still self-keying.
///
/// The attacker plays the server against a real wolfSSH CLIENT PUT: banner and KEXINIT, so the
/// client sends KEX_ECDH_INIT and starts keying, then one cleartext NEWKEYS instead of a
/// KEX_ECDH_REPLY. The vulnerable client reaches CONNECT_KEYED with no host key checked: the
/// harness raises `host_auth_skipped` and the claim oracle reports "Host authentication bypass".
/// The fixed client rejects the NEWKEYS.
#[puffin::witness("CVE-2025-11625")]
pub fn witness_cve_2025_11625(client: AgentName) -> Trace<SshProtocolTypes> {
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
            OutputAction::new_step(client), // client KEX_ECDH_INIT: now keying
            // Out of order: a cleartext NEWKEYS before any KEX_ECDH_REPLY, so no host key is
            // shown.
            InputAction::new_step(client, term! { fn_packet((fn_new_keys)) }),
            OutputAction::new_step(client),
        ],
        ..Default::default()
    }
}
