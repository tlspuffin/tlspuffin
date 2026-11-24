use puffin::claims::SecurityViolationPolicy;

use crate::claim::SshClaim;

/// Single-PUT security oracle of sshpuffin: the entity-authentication invariants.
///
/// Each invariant pairs an authenticated state of the PUT's library (read by an instrument accessor)
/// with the check that must precede it (recorded by the harness where the library performs or
/// delegates that check). The harness raises a one-shot claim flag when the state is reached without
/// the check, which never happens on an honest run; this policy maps each flag to its violation.
/// See `hunt/ENTITY-AUTH-ORACLE.md`.
///
/// | id | role | invariant | violation |
/// |----|------|-----------|-----------|
/// | C2 | client | user-auth accepted ⟹ keyed | "Authentication bypass" |
/// | C1 | client | keyed ⟹ host key checked | "Host authentication bypass" |
/// | S1 | server | client authenticated ⟹ the harness approved a credential | "User authentication bypass" |
///
/// The first claim raising a flag decides; within a claim, C2, C1, then S1.
pub struct SshSecurityViolationPolicy;

impl SecurityViolationPolicy for SshSecurityViolationPolicy {
    type C = SshClaim;

    fn check_violation(claims: &[SshClaim]) -> Option<&'static str> {
        for claim in claims {
            let c = claim.inner_ref();
            // C2: the client accepted user-authentication success during its initial key exchange
            // (`puffin_wolfssh_authed_while_keying`) — CVE-2025-14942.
            if c.auth_while_keying {
                return Some("Authentication bypass");
            }
            // C1: the client finished its key exchange without checking the server's host key
            // (`puffin_wolfssh_client_keyed` and the harness's host-key-check record) — CVE-2025-11625.
            if c.host_auth_skipped {
                return Some("Host authentication bypass");
            }
            // S1: the server's library considers the client authenticated although the harness's
            // authentication decision never approved a credential (`puffin_wolfssh_server_user_authed`,
            // `puffin_ssh_server_authenticated`, and the harness's approval record).
            if c.user_auth_unapproved {
                return Some("User authentication bypass");
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use puffin::agent::AgentName;
    use puffin::claims::SecurityViolationPolicy;

    use super::SshSecurityViolationPolicy;
    use crate::claim::{SshClaim, SshClaimInner};

    fn check(inners: Vec<SshClaimInner>) -> Option<&'static str> {
        let claims: Vec<SshClaim> = inners
            .into_iter()
            .map(|inner| SshClaim::new(AgentName::first(), inner))
            .collect();
        SshSecurityViolationPolicy::check_violation(&claims)
    }

    #[test]
    fn each_flag_raises_its_violation() {
        let flag = |f: fn(&mut SshClaimInner)| {
            let mut c = SshClaimInner::default();
            f(&mut c);
            c
        };
        assert_eq!(
            check(vec![flag(|c| c.auth_while_keying = true)]),
            Some("Authentication bypass")
        );
        assert_eq!(
            check(vec![flag(|c| c.host_auth_skipped = true)]),
            Some("Host authentication bypass")
        );
        assert_eq!(
            check(vec![flag(|c| c.user_auth_unapproved = true)]),
            Some("User authentication bypass")
        );
    }

    #[test]
    fn honest_claims_raise_nothing() {
        // an authenticated server's completion claim, and a post-KEX claim: no flag, no violation
        let completion = SshClaimInner {
            auth_method: "publickey".into(),
            auth_user: "user".into(),
            auth_key_fp: vec![7; 32],
            session_id: vec![1; 32],
            ..Default::default()
        };
        let post_kex = SshClaimInner {
            session_id: vec![1; 32],
            ..Default::default()
        };
        assert_eq!(check(vec![post_kex, completion]), None);
        assert_eq!(check(vec![]), None);
    }

    #[test]
    fn the_first_flagged_claim_decides_then_c2_c1_s1() {
        let s1 = SshClaimInner {
            user_auth_unapproved: true,
            ..Default::default()
        };
        let c1 = SshClaimInner {
            host_auth_skipped: true,
            ..Default::default()
        };
        assert_eq!(
            check(vec![s1.clone(), c1.clone()]),
            Some("User authentication bypass")
        );
        assert_eq!(check(vec![c1, s1]), Some("Host authentication bypass"));
        let all = SshClaimInner {
            auth_while_keying: true,
            host_auth_skipped: true,
            user_auth_unapproved: true,
            ..Default::default()
        };
        assert_eq!(check(vec![all]), Some("Authentication bypass"));
    }
}
