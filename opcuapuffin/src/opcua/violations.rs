use puffin::claims::SecurityViolationPolicy;

pub struct OpcuaSecurityViolationPolicy;

use crate::claims::OpcuaClaim;

impl SecurityViolationPolicy for OpcuaSecurityViolationPolicy {
    type C = OpcuaClaim;

    fn check_violation(claims: &[OpcuaClaim]) -> Option<&'static str> {
        Some("OPCUA check_violation is unimplemented.")
    }
}