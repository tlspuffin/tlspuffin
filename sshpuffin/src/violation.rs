use puffin::claims::SecurityViolationPolicy;

use crate::claim::SshClaim;
use crate::protocol::SshProtocolTypes;
pub struct SshSecurityViolationPolicy;

impl SecurityViolationPolicy<SshProtocolTypes, SshClaim> for SshSecurityViolationPolicy {
    fn check_violation(_claims: &[SshClaim]) -> Option<&'static str> {
        None
    }
}
