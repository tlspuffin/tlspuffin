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
use crate::ssh::seeds::{seed_client_attacker_rekey_dh_group16, seed_client_attacker_rekey_guess};

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

/// CVE-2021-3634 — libssh heap buffer over-read/over-write on a rekey that changes the KEX digest
/// size (CWE-787; libssh 0.9.1–0.9.5, fixed in 0.9.6). `session_id` and the secret hash shared one
/// length field, `digest_len`: a rekey to a KEX with a larger digest leaves the session id buffer
/// sized for the first KEX while `digest_len` grows, and `ssh_packet_set_newkeys` copies the
/// session id with the new length.
///
/// The attacker plays the client against a real libssh SERVER PUT: a curve25519-sha256 handshake
/// (32-byte session id), publickey auth, then a rekey offering only group16-sha512 (64-byte
/// digest). An affected server over-reads on the rekey NEWKEYS (ASan heap-buffer-overflow); a fixed
/// one keeps the session id at its own length.
#[puffin::witness("CVE-2021-3634")]
pub fn witness_cve_2021_3634(server: AgentName) -> Trace<SshProtocolTypes> {
    seed_client_attacker_rekey_dh_group16(server)
}
