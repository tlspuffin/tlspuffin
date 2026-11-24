//! Witness traces for the SSH vulnerability catalogue
//! (`puffin-build/vendors/<vendor>/vulnerabilities.toml`).
//!
//! Each `#[puffin::witness("<ID>")]` function returns a `Trace` that triggers the catalogue
//! entry's oracle on an affected PUT and nothing on a fixed one; it auto-registers at link time
//! (linkme), so there is no per-CVE test to write. The catalogue test
//! (`sshpuffin/tests/catalogue.rs`) runs every witness on every PUT of the binary and checks the
//! outcome against the PUT's catalogue state.

use puffin::agent::AgentName;
use puffin::trace::Trace;

use crate::protocol::SshProtocolTypes;
use crate::ssh::seeds::seed_client_attacker_rekey_guess;

/// CVE-2023-1667 — libssh SERVER NULL-pointer dereference during rekeying with KEX "algorithm
/// guessing" (CWE-476; libssh 0.9.1–0.9.6 and 0.10.0–0.10.4, fixed in 0.9.7 / 0.10.5). KEXINIT
/// state was keyed only on the presence of the methods fields and `first_kex_packet_follows` was
/// handled only partially: a post-authentication, client-initiated rekey whose KEXINIT sets the
/// flag (RFC 4253 §7.1) makes the server dereference a NULL kex-methods pointer and crash.
///
/// The attacker plays the client against a real libssh SERVER PUT: initial KEX + NEWKEYS, then
/// publickey auth (libssh's packet filter only admits a rekey KEXINIT once the connection is
/// established), then the rekey KEXINIT with the flag set. An affected server crashes (SEGV); a
/// fixed one survives.
#[puffin::witness("CVE-2023-1667")]
pub fn witness_cve_2023_1667(server: AgentName) -> Trace<SshProtocolTypes> {
    seed_client_attacker_rekey_guess(server)
}
