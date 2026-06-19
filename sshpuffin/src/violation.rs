use puffin::claims::SecurityViolationPolicy;

use crate::claim::{SshClaim, SshClaimInner};

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
            // Matching conversation at the wire-transcript level — see
            // `handshake_transcripts_agree`. Only the cleanly-separable s2c
            // direction is sound today; the c2s direction needs a packet-aligned
            // relay (the client pipelines its first encrypted packet right after
            // NEWKEYS, so a byte-level digest captures it asymmetrically). Wired
            // in once that lands; the negotiation-level checks above are the
            // active matching-conversation oracle for now.
        }

        None
    }
}

/// Transcript-agreement check for the matching-conversation property: each
/// honest peer's sent handshake stream must equal the other's received stream.
/// A divergence means the two endpoints completed believing in different
/// transcripts — the generic, mechanism-blind signature of a transcript
/// integrity attack such as prefix truncation (Terrapin).
///
/// NOTE: built on the wire-byte handshake digests, which are currently sound
/// only for the s2c direction (see the harness note in `libssh_add_inbound`).
/// Returns the per-direction agreement so callers/tests can assert each.
#[must_use]
pub fn handshake_transcripts_agree(
    server: &SshClaimInner,
    client: &SshClaimInner,
) -> (bool, bool) {
    let c2s_agrees = client.tx_digest == server.rx_digest;
    let s2c_agrees = server.tx_digest == client.rx_digest;
    (c2s_agrees, s2c_agrees)
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
        claim_tx(is_server, kex, cipher_in, cipher_out, 0, 0)
    }

    fn claim_tx(
        is_server: bool,
        kex: &str,
        cipher_in: &str,
        cipher_out: &str,
        rx_digest: u64,
        tx_digest: u64,
    ) -> SshClaim {
        SshClaim::new(
            AgentName::first(),
            SshClaimInner {
                is_server,
                kex: kex.to_string(),
                cipher_in: cipher_in.to_string(),
                cipher_out: cipher_out.to_string(),
                hmac_in: String::new(),
                hmac_out: String::new(),
                rx_digest,
                tx_digest,
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
    fn matching_transcripts_agree() {
        // Crosswise digests agree: server.rx == client.tx and server.tx == client.rx.
        let s = claim_tx(true, "curve25519-sha256", "c2s", "s2c", 0xC2, 0x5C);
        let c = claim_tx(false, "curve25519-sha256", "s2c", "c2s", 0x5C, 0xC2);
        assert_eq!(
            handshake_transcripts_agree(s.data(), c.data()),
            (true, true)
        );
    }

    #[test]
    fn diverging_transcript_is_detected() {
        // Server received a different c2s stream than the client sent
        // (prefix-truncation signature): server.rx_digest != client.tx_digest.
        let s = claim_tx(true, "curve25519-sha256", "c2s", "s2c", 0xDEAD, 0x5C);
        let c = claim_tx(false, "curve25519-sha256", "s2c", "c2s", 0x5C, 0xC2);
        let (c2s_agrees, s2c_agrees) = handshake_transcripts_agree(s.data(), c.data());
        assert!(!c2s_agrees, "c2s divergence should be detected");
        assert!(s2c_agrees, "s2c should still agree");
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
