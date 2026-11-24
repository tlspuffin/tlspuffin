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
        }
        None
    }
}
