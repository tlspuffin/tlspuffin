use puffin::claims::SecurityViolationPolicy;

use crate::claim::SshClaim;

/// SSH has **no active security oracle yet**: `check_violation` always returns `None`.
///
/// This is an intentional, documented stub — not a populated policy like tlspuffin's. Single-PUT
/// SSH fuzzing therefore surfaces only crashes, ASan reports and timeouts as objectives;
/// cross-implementation logic/auth divergences are caught by the DIFFERENTIAL oracle (two PUTs
/// compared), not here. A real claim-based oracle — e.g. flagging a success claim for the
/// unauthorized identity, or a session-id / user / key-fingerprint mismatch between honest peers —
/// is future work (see the CVE-catalogue effort). Until it exists, nothing in the tree should
/// advertise an active SSH oracle.
pub struct SshSecurityViolationPolicy;

impl SecurityViolationPolicy for SshSecurityViolationPolicy {
    type C = SshClaim;

    fn check_violation(_claims: &[SshClaim]) -> Option<&'static str> {
        None // no active oracle yet; see the type-level doc comment
    }
}
