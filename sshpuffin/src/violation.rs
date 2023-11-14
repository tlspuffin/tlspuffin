use puffin::claims::SecurityViolationPolicy;

use crate::claim::SshClaim;

pub struct SshSecurityViolationPolicy;

impl SecurityViolationPolicy<SshClaim> for SshSecurityViolationPolicy {
    fn check_violation(claims: &[SshClaim]) -> Option<&'static str> {
        None
    }
}
