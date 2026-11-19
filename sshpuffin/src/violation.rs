use puffin::claims::SecurityViolationPolicy;

use crate::claim::SshClaim;

pub struct SshSecurityViolationPolicy;

impl SecurityViolationPolicy for SshSecurityViolationPolicy {
    type C = SshClaim;

    fn check_violation(claims: &[SshClaim]) -> Option<&'static str> {
        // CVE-2025-14942 (wolfSSH <= 1.4.21, client KEX state machine, CWE-287):
        // a malicious server can manipulate the client's message-ordering state
        // machine so the client accepts user-authentication-protocol messages out
        // of order, during key exchange. The vulnerable `IsMessageAllowedClient`
        // defaults to ALLOW; the fix defaults to deny and rejects auth-range
        // messages while keying. Consequences: the client can be driven to skip
        // user authentication, send a password in the clear, or emit a premature
        // signature.
        //
        // Detection is one-sided (the agent's own state contradicts): the harness
        // raises `auth_while_keying` when the client reached the
        // server-userauth-accepted state (`serverState >= SERVER_USERAUTH_ACCEPT_DONE`)
        // while the transport was still keying (`isKeying != 0`) — see the
        // instrument accessor `puffin_wolfssh_authed_while_keying`
        // (puffin-build/vendors/wolfssh/instrument_claims.cmake) and its emit point
        // in the harness (sshpuffin/harness/wolfssh/src/put.c). An honest handshake
        // only reaches that state AFTER NEWKEYS (keying cleared), so the flag is
        // never set on a legitimate trace — including a legitimate "none"
        // authentication.
        for claim in claims {
            if claim.inner_ref().auth_while_keying {
                return Some("Authentication bypass");
            }
        }
        None
    }
}
