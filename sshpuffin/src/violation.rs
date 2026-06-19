use puffin::claims::SecurityViolationPolicy;

use crate::claim::{SshClaim, ATTACKER_PUBKEY_SHA256};

pub struct SshSecurityViolationPolicy;

impl SecurityViolationPolicy for SshSecurityViolationPolicy {
    type C = SshClaim;

    /// Dolev-Yao security oracle over the transport-layer claims.
    ///
    /// Two families of properties are checked:
    ///
    /// 1. **Per-endpoint soundness** — an agent that reports a completed handshake must have
    ///    negotiated a real key exchange and a real (non-null) cipher in both directions. Reaching
    ///    the authenticated state over a `none` cipher means the transport is unprotected.
    ///
    /// 2. **Matching conversation (cross-endpoint agreement)** — if both a client and a server
    ///    completed, they must agree on the negotiated parameters. Directional values are mirrored:
    ///    one peer's inbound channel is the other's outbound channel. A disagreement is the
    ///    signature of a downgrade / Terrapin-style attack where the two endpoints end up with
    ///    different views of the session.
    fn check_violation(claims: &[SshClaim]) -> Option<&'static str> {
        for claim in claims {
            let d = claim.data();
            if d.kex.is_empty() || d.kex == "none" {
                return Some("transport handshake completed without a key exchange");
            }
            if is_null_cipher(&d.cipher_in) || is_null_cipher(&d.cipher_out) {
                return Some("transport handshake completed with a null/none cipher");
            }
            // Entity authentication / no impersonation: a Dolev-Yao attacker can
            // only produce a valid publickey signature for a key whose private
            // half is in its knowledge (the term-algebra signature). The only
            // such client key is A (`ATTACKER_PUBKEY_SHA256`). So if a server
            // completed *publickey* authentication for any other key, the peer
            // authenticated as a principal whose private key it does not hold —
            // an impersonation / authentication bypass. Mechanism-blind: it never
            // inspects *how* the bypass happened, only that an unforgeable
            // credential was accepted.
            if d.is_server
                && d.auth_method == "publickey"
                && d.auth_key_fingerprint != ATTACKER_PUBKEY_SHA256
            {
                return Some(
                    "server authenticated a publickey identity the attacker cannot sign for \
                     (impersonation / authentication bypass)",
                );
            }
            // Entity authentication: a server that believes the handshake
            // completed must have run a real authentication method. Reaching the
            // authenticated state with no recorded method ("password" /
            // "publickey") means the peer was admitted without authenticating —
            // an authentication bypass (e.g. CVE-2018-10933). Mechanism-blind: it
            // asserts "completion implies authentication", not how a bypass works.
            if d.is_server && d.auth_method != "password" && d.auth_method != "publickey" {
                return Some(
                    "server reached the authenticated state without authenticating \
                     (authentication bypass)",
                );
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

/// Trace-analysis view of the matching-conversation property.
///
/// Re-evaluates the executed trace's input recipes against the final context to
/// recover the exact byte stream delivered to `agent` — i.e. *what this honest
/// party actually received on the wire* — using only the trace and the symbolic
/// term algebra, with no PUT introspection and no decryption.
///
/// This is the building block for matching conversation: in a faithful relay
/// each honest peer's received stream equals what its partner sent, so dropping,
/// injecting or reordering a relayed message (e.g. a Terrapin prefix truncation)
/// changes the delivered stream and is detectable here — mechanism-blind, by
/// comparing transcripts rather than recognising any specific attack.
pub fn delivered_to<PB>(
    trace: &puffin::trace::Trace<PB::ProtocolTypes>,
    ctx: &puffin::trace::TraceContext<PB>,
    agent: puffin::agent::AgentName,
) -> Vec<u8>
where
    PB: puffin::protocol::ProtocolBehavior,
{
    use puffin::algebra::TermType;
    use puffin::trace::Action;

    let mut delivered = Vec::new();
    for step in &trace.steps {
        if step.agent != agent {
            continue;
        }
        if let Action::Input(input) = &step.action {
            if let Ok(message) = input.recipe.evaluate(ctx) {
                delivered.extend_from_slice(&message);
            }
        }
    }
    delivered
}

/// `true` if one byte stream is a prefix of the other — i.e. the two honest
/// peers agree on the common part of the transcript (any difference is only an
/// undelivered, in-flight tail, not a disagreement).
fn transcripts_agree(a: &[u8], b: &[u8]) -> bool {
    a.starts_with(b) || b.starts_with(a)
}

/// Trace-aware **matching-conversation** oracle for two-honest-party traces.
///
/// For a client PUT and a server PUT relayed by the Dolev-Yao attacker, each
/// peer must have received exactly what its partner sent (up to an undelivered
/// tail). We recover *received* with [`delivered_to`] (re-evaluating the input
/// recipes) and *sent* with `TraceContext::agent_output_messages` (the agent's
/// emitted flights), and compare crosswise. A mid-stream divergence — a dropped,
/// injected or reordered relayed message, i.e. the Terrapin prefix-truncation
/// primitive — breaks the prefix relation and is flagged. Returns `None` for
/// single-party traces (no two honest views to compare).
pub fn matching_conversation_violation(
    trace: &puffin::trace::Trace<crate::protocol::SshProtocolTypes>,
    ctx: &puffin::trace::TraceContext<crate::protocol::SshProtocolBehavior>,
) -> Option<&'static str> {
    use std::any::TypeId;

    use crate::protocol::{AgentType, RawSshMessageFlight};

    let agent_of = |typ: AgentType| {
        trace
            .descriptors
            .iter()
            .find(|d| d.protocol_config.typ == typ)
            .map(|d| d.name)
    };
    let client = agent_of(AgentType::Client)?;
    let server = agent_of(AgentType::Server)?;

    let flight_ty = TypeId::of::<RawSshMessageFlight>();
    let server_received = delivered_to(trace, ctx, server); // c2s the server got
    let client_received = delivered_to(trace, ctx, client); // s2c the client got
    let client_sent = ctx.agent_output_messages(client, flight_ty).concat(); // c2s sent
    let server_sent = ctx.agent_output_messages(server, flight_ty).concat(); // s2c sent

    if !transcripts_agree(&server_received, &client_sent) {
        return Some(
            "client and server disagree on the client->server transcript \
             (matching-conversation violation)",
        );
    }
    if !transcripts_agree(&client_received, &server_sent) {
        return Some(
            "client and server disagree on the server->client transcript \
             (matching-conversation violation)",
        );
    }
    None
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
                // Server claims need a valid auth method or the bypass oracle
                // (rightly) flags them; these negotiation-level tests aren't
                // about authentication, so use a benign "password".
                auth_method: if is_server {
                    "password".to_string()
                } else {
                    String::new()
                },
                auth_user: String::new(),
                auth_key_fingerprint: Vec::new(),
            },
        )
    }

    fn pubkey_auth_claim(user: &str, key_fp: Vec<u8>) -> SshClaim {
        SshClaim::new(
            AgentName::first(),
            SshClaimInner {
                is_server: true,
                kex: "curve25519-sha256".to_string(),
                cipher_in: "c2s".to_string(),
                cipher_out: "s2c".to_string(),
                hmac_in: String::new(),
                hmac_out: String::new(),
                auth_method: "publickey".to_string(),
                auth_user: user.to_string(),
                auth_key_fingerprint: key_fp,
            },
        )
    }

    #[test]
    fn publickey_auth_as_attacker_key_is_accepted() {
        // Authenticating as key A (the key the attacker can sign for) is legit.
        let claims = vec![pubkey_auth_claim("alice", ATTACKER_PUBKEY_SHA256.to_vec())];
        assert_eq!(SshSecurityViolationPolicy::check_violation(&claims), None);
    }

    #[test]
    fn publickey_impersonation_is_flagged() {
        // Authenticating as a different key (B, whose private key is NOT in the
        // mapper) is an impersonation / authentication bypass.
        let victim_fp = vec![0xB0u8; 32];
        assert_ne!(victim_fp.as_slice(), ATTACKER_PUBKEY_SHA256.as_slice());
        let claims = vec![pubkey_auth_claim("victim", victim_fp)];
        assert!(SshSecurityViolationPolicy::check_violation(&claims).is_some());
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
            claim(
                false,
                "curve25519-sha256",
                "chacha20-poly1305",
                "chacha20-poly1305",
            ),
        ];
        assert!(SshSecurityViolationPolicy::check_violation(&claims).is_some());
    }

    #[test]
    fn null_cipher_is_flagged() {
        let claims = vec![claim(true, "curve25519-sha256", "none", "none")];
        assert!(SshSecurityViolationPolicy::check_violation(&claims).is_some());
    }
}
