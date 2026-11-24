use puffin::claims::SecurityViolationPolicy;

use crate::claim::SshClaim;

/// Single-PUT security oracle of the SSH catalogue: one-sided flags the harness raises when a PUT's
/// own state contradicts the protocol, never on an honest run.
pub struct SshSecurityViolationPolicy;

impl SecurityViolationPolicy for SshSecurityViolationPolicy {
    type C = SshClaim;

    fn check_violation(claims: &[SshClaim]) -> Option<&'static str> {
        for claim in claims {
            // CVE-2025-14942: the client accepted user-authentication success during its initial
            // key exchange (`puffin_wolfssh_authed_while_keying`).
            if claim.inner_ref().auth_while_keying {
                return Some("Authentication bypass");
            }
            // CVE-2025-11625: the client finished its key exchange without checking the server's
            // host key (`puffin_wolfssh_client_keyed` and the harness's host-key-check record).
            if claim.inner_ref().host_auth_skipped {
                return Some("Host authentication bypass");
            }
        }
        None
    }
}
