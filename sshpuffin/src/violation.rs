use puffin::claims::SecurityViolationPolicy;

use crate::claim::{SshClaim, ATTACKER_PUBKEY_SHA256, PHASE_DONE};

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
        // Only completed-handshake claims (`PHASE_DONE`) carry final
        // security-relevant state. Intermediate phase claims are emitted by
        // partial/aborted runs purely to feed the claim-coverage feedback
        // (liveness depth) and must not be judged by the oracle (their
        // algorithm fields are empty/partial pre-negotiation).
        for claim in claims {
            let d = claim.data();
            if d.phase != PHASE_DONE {
                continue;
            }
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

        let server = claims
            .iter()
            .map(SshClaim::data)
            .filter(|d| d.phase == PHASE_DONE)
            .find(|d| d.is_server);
        let client = claims
            .iter()
            .map(SshClaim::data)
            .filter(|d| d.phase == PHASE_DONE)
            .find(|d| !d.is_server);
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

            // KEX-transcript agreement (RFC 4253 §7.2 / §8). The session
            // identifier is the exchange hash H, which binds the entire
            // key-exchange transcript (V_C,V_S,I_C,I_S,K_S,e,f,K). Two honest
            // peers that ran a matching conversation must share it; a mismatch
            // is a downgrade / transcript attack. Compared only when both
            // endpoints expose it — a cross-vendor peer that does not populate
            // it leaves the field empty and falls back to the algorithm-level
            // agreement checks above (no false positive).
            if !s.session_id.is_empty() && !c.session_id.is_empty() && s.session_id != c.session_id
            {
                return Some(
                    "client and server disagree on the SSH session id / exchange hash \
                     (KEX-transcript divergence)",
                );
            }

            // Channel-data integrity (RFC 4253 §6.4 / RFC 4251 §9.3.2). The
            // post-NEWKEYS secure-channel message stream is MAC-authenticated,
            // so each peer's outbound message-type digest must equal its
            // partner's inbound digest. A mismatch means a secure-channel
            // message was dropped / injected / reordered between the two honest
            // peers — the matching-conversation violation a Terrapin prefix
            // truncation produces by stripping the server's EXT_INFO. Compared
            // crosswise (s2c: server sent == client received; c2s: client sent
            // == server received), only when both digests are available
            // (non-zero). Unlike the byte-stream transcript oracle, this never
            // fires on padding / SSH_MSG_IGNORE corruption: those are explicitly
            // unprotected (RFC 4251 §9.3.6) and never enter the digest.
            if s.secure_tx_digest != 0
                && c.secure_rx_digest != 0
                && s.secure_tx_digest != c.secure_rx_digest
            {
                return Some(
                    "client and server disagree on the server->client secure-channel \
                     message stream (matching-conversation / channel-integrity violation)",
                );
            }
            if c.secure_tx_digest != 0
                && s.secure_rx_digest != 0
                && c.secure_tx_digest != s.secure_rx_digest
            {
                return Some(
                    "client and server disagree on the client->server secure-channel \
                     message stream (matching-conversation / channel-integrity violation)",
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

    // Precondition: BOTH parties must have completed the handshake. A transcript
    // difference only constitutes a *matching-conversation* violation between two
    // honest peers that both finished — otherwise it is merely a truncated or
    // perturbed run (a party aborted, the trace was cut short), which floods the
    // oracle with benign end-of-trace diffs. Crucially, because SSH binds the
    // per-direction sequence number into every MAC, a transcript divergence that
    // survives a *fully completed* handshake on both sides must be transport-valid
    // (sequence-number-compensated) — i.e. genuinely Terrapin-class — so this
    // precondition is exactly the filter that isolates real attacks.
    let completed = |a: puffin::agent::AgentName| {
        ctx.find_agent(a)
            .map(|agent| agent.is_state_successful())
            .unwrap_or(false)
    };
    if !completed(client) || !completed(server) {
        return None;
    }

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
    use crate::claim::{SshClaimInner, PHASE_DONE};

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
                session_id: Vec::new(),
                secure_tx_digest: 0,
                secure_rx_digest: 0,
                phase: PHASE_DONE,
                rx_count: 0,
                tx_count: 0,
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
                session_id: Vec::new(),
                secure_tx_digest: 0,
                secure_rx_digest: 0,
                phase: PHASE_DONE,
                rx_count: 0,
                tx_count: 0,
            },
        )
    }

    /// A completing endpoint carrying a session id and per-direction
    /// secure-channel digests, with crosswise-consistent ciphers so the
    /// cross-endpoint checks are reached.
    fn claim_ext(
        is_server: bool,
        session_id: Vec<u8>,
        secure_tx_digest: u64,
        secure_rx_digest: u64,
    ) -> SshClaim {
        SshClaim::new(
            AgentName::first(),
            SshClaimInner {
                is_server,
                kex: "curve25519-sha256".to_string(),
                cipher_in: "c".to_string(),
                cipher_out: "c".to_string(),
                hmac_in: String::new(),
                hmac_out: String::new(),
                auth_method: if is_server {
                    "password".to_string()
                } else {
                    String::new()
                },
                auth_user: String::new(),
                auth_key_fingerprint: Vec::new(),
                session_id,
                secure_tx_digest,
                secure_rx_digest,
                phase: PHASE_DONE,
                rx_count: 0,
                tx_count: 0,
            },
        )
    }

    #[test]
    fn session_id_disagreement_is_flagged() {
        // Different exchange hashes => the two peers did not share a KEX
        // transcript (downgrade / transcript attack).
        let claims = vec![
            claim_ext(true, vec![1, 2, 3], 0, 0),
            claim_ext(false, vec![9, 9, 9], 0, 0),
        ];
        assert!(SshSecurityViolationPolicy::check_violation(&claims).is_some());
    }

    #[test]
    fn matching_session_and_channel_are_accepted() {
        // Same session id; crosswise-consistent channel digests
        // (server tx == client rx, client tx == server rx).
        let claims = vec![
            claim_ext(true, vec![7; 32], 0xAAAA, 0xBBBB),
            claim_ext(false, vec![7; 32], 0xBBBB, 0xAAAA),
        ];
        assert_eq!(SshSecurityViolationPolicy::check_violation(&claims), None);
    }

    #[test]
    fn channel_data_s2c_divergence_is_flagged() {
        // Terrapin shape: the s2c stream the server sent (tx) is not the one
        // the client received (rx) — a dropped secure-channel message.
        let claims = vec![
            claim_ext(true, vec![7; 32], 0xAAAA, 0xBBBB),
            claim_ext(false, vec![7; 32], 0xBBBB, 0x1234),
        ];
        assert!(SshSecurityViolationPolicy::check_violation(&claims).is_some());
    }

    #[test]
    fn unavailable_session_and_channel_are_not_flagged() {
        // Cross-vendor peer that does not expose the session id / digests
        // (empty / zero): fall back to algorithm agreement, no false positive.
        let claims = vec![
            claim_ext(true, Vec::new(), 0, 0),
            claim_ext(false, Vec::new(), 0, 0),
        ];
        assert_eq!(SshSecurityViolationPolicy::check_violation(&claims), None);
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
