use puffin::claims::SecurityViolationPolicy;

use crate::claim::SshClaim;

pub struct SshSecurityViolationPolicy;

impl SecurityViolationPolicy for SshSecurityViolationPolicy {
    type C = SshClaim;

    /// Dolev-Yao security oracle over the transport-layer claims.
    ///
    /// Two families of properties are checked:
    ///
    /// 1. **Per-endpoint soundness** — an agent that reports a completed
    ///    handshake must have negotiated a real key exchange and a real
    ///    (non-null) cipher in both directions. Reaching the authenticated
    ///    state over a `none` cipher means the transport is unprotected.
    ///
    /// 2. **Matching conversation (cross-endpoint agreement)** — if both a
    ///    client and a server completed, they must agree on the negotiated
    ///    parameters. Directional values are mirrored: one peer's inbound
    ///    channel is the other's outbound channel. A disagreement is the
    ///    signature of a downgrade / Terrapin-style attack where the two
    ///    endpoints end up with different views of the session.
    fn check_violation(claims: &[SshClaim]) -> Option<&'static str> {
        for claim in claims {
            let d = claim.data();
            if d.kex.is_empty() || d.kex == "none" {
                return Some("transport handshake completed without a key exchange");
            }
            if is_null_cipher(&d.cipher_in) || is_null_cipher(&d.cipher_out) {
                return Some("transport handshake completed with a null/none cipher");
            }
        }

        let server = claims.iter().map(SshClaim::data).find(|d| d.is_server);
        let client = claims.iter().map(SshClaim::data).find(|d| !d.is_server);
        if let (Some(s), Some(c)) = (server, client) {
            if s.kex != c.kex {
                return Some(
                    "client and server disagree on the negotiated key exchange (possible downgrade)",
                );
            }
            // The server's inbound channel is the client's outbound channel and
            // vice versa, so the negotiated ciphers must match crosswise.
            if s.cipher_in != c.cipher_out || s.cipher_out != c.cipher_in {
                return Some(
                    "client and server disagree on the negotiated cipher (possible downgrade)",
                );
            }
            if s.hmac_in != c.hmac_out || s.hmac_out != c.hmac_in {
                return Some(
                    "client and server disagree on the negotiated MAC (possible downgrade)",
                );
            }
        }

        None
    }
}

fn is_null_cipher(cipher: &str) -> bool {
    cipher.is_empty() || cipher == "none"
}

#[cfg(test)]
mod tests {
    use puffin::agent::AgentName;

    use super::*;
    use crate::claim::SshClaimInner;

    fn claim(is_server: bool, kex: &str, cipher_in: &str, cipher_out: &str) -> SshClaim {
        SshClaim::new(
            AgentName::first(),
            SshClaimInner {
                is_server,
                kex: kex.to_string(),
                cipher_in: cipher_in.to_string(),
                cipher_out: cipher_out.to_string(),
                hmac_in: String::new(),
                hmac_out: String::new(),
            },
        )
    }

    #[test]
    fn agreeing_endpoints_are_accepted() {
        // Crosswise-matching ciphers: server.in == client.out and vice versa.
        let claims = vec![
            claim(true, "curve25519-sha256", "cipher-c2s", "cipher-s2c"),
            claim(false, "curve25519-sha256", "cipher-s2c", "cipher-c2s"),
        ];
        assert_eq!(SshSecurityViolationPolicy::check_violation(&claims), None);
    }

    #[test]
    fn kex_disagreement_is_flagged() {
        let claims = vec![
            claim(true, "curve25519-sha256", "c", "c"),
            claim(false, "diffie-hellman-group1-sha1", "c", "c"),
        ];
        assert!(SshSecurityViolationPolicy::check_violation(&claims).is_some());
    }

    #[test]
    fn cipher_disagreement_is_flagged() {
        let claims = vec![
            claim(true, "curve25519-sha256", "aes256-gcm", "aes256-gcm"),
            claim(false, "curve25519-sha256", "chacha20-poly1305", "chacha20-poly1305"),
        ];
        assert!(SshSecurityViolationPolicy::check_violation(&claims).is_some());
    }

    #[test]
    fn null_cipher_is_flagged() {
        let claims = vec![claim(true, "curve25519-sha256", "none", "none")];
        assert!(SshSecurityViolationPolicy::check_violation(&claims).is_some());
    }
}
