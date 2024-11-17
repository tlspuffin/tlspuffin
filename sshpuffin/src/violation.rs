use puffin::claims::SecurityViolationPolicy;

use crate::claim::SshClaim;
pub struct SshSecurityViolationPolicy;

impl SecurityViolationPolicy for SshSecurityViolationPolicy {
    type C = SshClaim;

    fn check_violation(_claims: &[SshClaim]) -> Option<&'static str> {
        None
    }
}
