use puffin::claims::SecurityViolationPolicy;

use crate::claim::SshClaim;

pub struct SshSecurityViolationPolicy;

const ROLE_CLIENT: u8 = 0;
const ROLE_SERVER: u8 = 1;
/// C `Claim.phase` == 3: handshake complete (the completion claim the entity-auth
/// checks target). The CVE-2025-14942 claim carries phase 0, so it is disjoint.
const PHASE_DONE: u8 = 3;

/// Authorized `(user, sha256(pubkey-blob))` publickey pairings — a mirror of
/// `sshpuffin/include/puffin/ssh_authorized_creds.h` (identities A and B; identity
/// C is deliberately unauthorized). Used by the P1 user-authentication oracle.
const AUTHORIZED_KEYS: &[(&str, [u8; 32])] = &[
    // identity A — user "user", key A (== embedded server host key)
    (
        "user",
        [
            0xa4, 0x9e, 0xba, 0xc7, 0x76, 0xcc, 0x3a, 0x80, 0x37, 0x2c, 0x44, 0x2a, 0xc5, 0x4c,
            0x2d, 0x7a, 0x9f, 0xd4, 0x5e, 0x7e, 0x93, 0xea, 0x64, 0x81, 0xd1, 0xa5, 0x5a, 0x2c,
            0x7e, 0x1b, 0x27, 0x29,
        ],
    ),
    // identity B — user "userb", key B (RSA-3072)
    (
        "userb",
        [
            0x23, 0x8c, 0x19, 0xea, 0x25, 0xb8, 0xb9, 0xc1, 0xec, 0x15, 0xbc, 0xd5, 0xf9, 0x10,
            0xc0, 0x49, 0xc1, 0x3c, 0x52, 0x6b, 0x4d, 0x4b, 0x64, 0x1c, 0xaf, 0xce, 0x63, 0x55,
            0xc6, 0xb2, 0x3b, 0x0a,
        ],
    ),
];

fn is_authorized_key(user: &str, fp: &[u8]) -> bool {
    fp.len() == 32
        && AUTHORIZED_KEYS
            .iter()
            .any(|(u, f)| *u == user && f.as_slice() == fp)
}

impl SecurityViolationPolicy for SshSecurityViolationPolicy {
    type C = SshClaim;

    fn check_violation(claims: &[SshClaim]) -> Option<&'static str> {
        // ── CVE-2025-14942 (ordering) ────────────────────────────────────────
        // Checked FIRST so the catalogue entry's oracle violation ("Authentication
        // bypass") is the one returned on its witness. See the field's doc in
        // claim.rs. The CVE claim carries phase 0, disjoint from the phase-3
        // completion claims the entity-auth checks below target.
        for claim in claims {
            if claim.inner_ref().auth_while_keying {
                return Some("Authentication bypass");
            }
        }

        // ── Entity-authentication oracles (completion claims only) ───────────
        // These are reusable, principled identity checks (see hunt/ENTITY-AUTH-ORACLE.md).
        // On a correct library they are silent — their triggers are other CVEs
        // (P1: a server auth-bypass; P2: a client host-auth bypass, e.g.
        // CVE-2025-11625) — so here they are validated as no-false-fire.
        for claim in claims {
            let c = claim.inner_ref();
            if !c.entity_auth_checked || c.phase != PHASE_DONE {
                continue;
            }
            match c.role {
                // P1 — user authentication (the server authenticated a client).
                ROLE_SERVER => {
                    if c.auth_method == "publickey" {
                        // A publickey login the library completed must have carried a
                        // verified signature for an authorized (user, key) pairing.
                        if !c.had_signature || !is_authorized_key(&c.auth_user, &c.auth_key_fp) {
                            return Some("User authentication bypass");
                        }
                    }
                }
                // P2 — host authentication (the server authenticated itself to the
                // client). A client that completed a handshake must have verified a
                // server host key during key exchange.
                ROLE_CLIENT => {
                    if !c.host_authenticated {
                        return Some("Host authentication bypass");
                    }
                }
                _ => {}
            }
        }

        // ── P3 — two-party matching conversation ─────────────────────────────
        // When a trace runs BOTH a real client and a real server (a relayed
        // handshake), RFC 4253 §7.2 requires them to share the exchange hash H iff
        // they had a matching conversation. A relay that desynchronises the
        // transcript (e.g. Terrapin prefix truncation) breaks that equality.
        // Inert on single-PUT traces (only one role present).
        let completion_h = |role: u8| {
            claims
                .iter()
                .map(SshClaim::inner_ref)
                .find(|c| {
                    c.entity_auth_checked
                        && c.role == role
                        && c.phase == PHASE_DONE
                        && !c.session_id.is_empty()
                })
                .map(|c| c.session_id.clone())
        };
        if let (Some(client_h), Some(server_h)) =
            (completion_h(ROLE_CLIENT), completion_h(ROLE_SERVER))
        {
            if client_h != server_h {
                return Some("Session hash mismatch");
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use puffin::agent::AgentName;
    use puffin::claims::SecurityViolationPolicy;

    use super::{SshSecurityViolationPolicy as P, ROLE_CLIENT, ROLE_SERVER};
    use crate::claim::{SshClaim, SshClaimInner};

    fn claim(inner: SshClaimInner) -> SshClaim {
        SshClaim::new(AgentName::first(), inner)
    }
    fn done(role: u8) -> SshClaimInner {
        SshClaimInner {
            role,
            phase: 3,
            entity_auth_checked: true,
            session_id: vec![1, 2, 3],
            ..Default::default()
        }
    }
    fn check(cs: &[SshClaim]) -> Option<&'static str> {
        P::check_violation(cs)
    }

    #[test]
    fn cve_auth_while_keying_wins_first() {
        let c = claim(SshClaimInner {
            auth_while_keying: true,
            ..Default::default()
        });
        assert_eq!(check(&[c]), Some("Authentication bypass"));
    }

    #[test]
    fn p1_publickey_without_signature_fires() {
        let c = claim(SshClaimInner {
            auth_method: "publickey".into(),
            auth_user: "user".into(),
            had_signature: false,
            ..done(ROLE_SERVER)
        });
        assert_eq!(check(&[c]), Some("User authentication bypass"));
    }

    #[test]
    fn p1_unauthorized_pairing_fires() {
        let c = claim(SshClaimInner {
            auth_method: "publickey".into(),
            auth_user: "userc".into(), // identity C: deliberately unauthorized
            auth_key_fp: vec![0xde; 32],
            had_signature: true,
            ..done(ROLE_SERVER)
        });
        assert_eq!(check(&[c]), Some("User authentication bypass"));
    }

    #[test]
    fn p1_authorized_pubkey_login_is_clean() {
        // identity A's authorized fingerprint — no violation.
        let fp = super::AUTHORIZED_KEYS[0].1.to_vec();
        let c = claim(SshClaimInner {
            auth_method: "publickey".into(),
            auth_user: "user".into(),
            auth_key_fp: fp,
            had_signature: true,
            ..done(ROLE_SERVER)
        });
        assert_eq!(check(&[c]), None);
    }

    #[test]
    fn p2_client_without_host_auth_fires() {
        let c = claim(SshClaimInner {
            host_authenticated: false,
            ..done(ROLE_CLIENT)
        });
        assert_eq!(check(&[c]), Some("Host authentication bypass"));
    }

    #[test]
    fn p2_client_with_host_auth_is_clean() {
        let c = claim(SshClaimInner {
            host_authenticated: true,
            ..done(ROLE_CLIENT)
        });
        assert_eq!(check(&[c]), None);
    }

    #[test]
    fn p3_two_party_hash_mismatch_fires() {
        let mut client = done(ROLE_CLIENT);
        client.host_authenticated = true;
        client.session_id = vec![1, 1, 1];
        let mut server = done(ROLE_SERVER);
        server.session_id = vec![2, 2, 2];
        assert_eq!(
            check(&[claim(client), claim(server)]),
            Some("Session hash mismatch")
        );
    }

    #[test]
    fn p3_two_party_matching_hash_is_clean() {
        let mut client = done(ROLE_CLIENT);
        client.host_authenticated = true;
        let server = done(ROLE_SERVER); // same session_id vec![1,2,3]
        assert_eq!(check(&[claim(client), claim(server)]), None);
    }

    #[test]
    fn un_instrumented_harness_never_false_fires() {
        // entity_auth_checked = false (default): a client DONE claim with everything
        // zero must NOT be read as a host-auth bypass.
        let c = claim(SshClaimInner {
            role: ROLE_CLIENT,
            phase: 3,
            session_id: vec![9],
            ..Default::default()
        });
        assert_eq!(check(&[c]), None);
    }
}
