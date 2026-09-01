use puffin::claims::SecurityViolationPolicy;

pub struct OpcuaSecurityViolationPolicy;

use crate::claims::OpcuaClaim;

impl SecurityViolationPolicy for OpcuaSecurityViolationPolicy {
    type C = OpcuaClaim;

    fn check_violation(_claims: &[OpcuaClaim]) -> Option<&'static str> {
        None
    }
}
