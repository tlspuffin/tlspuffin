use itertools::Itertools;
use puffin::claims::SecurityViolationPolicy;
use security_claims::ClaimTLSVersion;

use crate::claims::{ClaimData, ClaimDataMessage, Finished, TlsClaim};
use crate::protocol::AgentType;
use crate::static_certs::{ALICE_CERT, BOB_CERT};

pub struct TlsSecurityViolationPolicy;

impl SecurityViolationPolicy for TlsSecurityViolationPolicy {
    type C = TlsClaim;

    fn check_violation(claims: &[TlsClaim]) -> Option<&'static str> {
        if let Some((claim_a, claim_b)) = find_two_finished_messages(claims) {
            if let Some(((_, client), (_, server))) = get_client_server(claim_a, claim_b) {
                if client.tls_version != server.tls_version {
                    return Some("Mismatching versions");
                }

                if client.master_secret != server.master_secret {
                    return Some("Mismatching master secrets");
                }

                if client.server_random != server.server_random {
                    return Some("Mismatching server random");
                }
                if client.client_random != server.client_random {
                    return Some("Mismatching client random");
                }

                if client.chosen_cipher != server.chosen_cipher {
                    return Some("Mismatching ciphers");
                }

                if client.signature_algorithm != server.peer_signature_algorithm
                    || server.signature_algorithm != client.peer_signature_algorithm
                {
                    return Some("mismatching signature algorithms");
                }

                if server.authenticate_peer && server.peer_certificate.as_slice() != BOB_CERT.1 {
                    return Some("Authentication bypass");
                }

                if client.authenticate_peer && client.peer_certificate.as_slice() != ALICE_CERT.1 {
                    return Some("Authentication bypass");
                }

                match client.tls_version {
                    ClaimTLSVersion::CLAIM_TLS_VERSION_V1_2 => {
                        // TLS 1.2 Checks

                        // https://datatracker.ietf.org/doc/html/rfc5077#section-3.4
                        if !server.session_id.is_empty() && client.session_id != server.session_id {
                            return Some("Mismatching session ids");
                        }
                    }
                    ClaimTLSVersion::CLAIM_TLS_VERSION_V1_3 => {
                        // TLS 1.3 Checks
                        if client.session_id != server.session_id {
                            return Some("Mismatching session ids");
                        }

                        if !client.available_ciphers.is_empty()
                            && !server.available_ciphers.is_empty()
                        {
                            let best_cipher = {
                                let mut cipher = None;
                                for server_cipher in &server.available_ciphers {
                                    if client.available_ciphers.contains(server_cipher) {
                                        cipher = Some(*server_cipher);
                                        break;
                                    }
                                }

                                cipher
                            };

                            if let Some(best_cipher) = best_cipher {
                                if best_cipher != server.chosen_cipher {
                                    return Some("Not the best cipher choosen");
                                }
                                if best_cipher != client.chosen_cipher {
                                    return Some("Not the best cipher choosen");
                                }
                            }
                        }
                    }
                    ClaimTLSVersion::CLAIM_TLS_VERSION_UNDEFINED => {
                        return Some("Version undefined after handshake");
                    }
                }
            } else {
                // Could not choose exactly one server and client: both Finished
                // claims come from the server side, which happens when the
                // trace performs two separate connections against the same
                // reused server agent (e.g. a full handshake followed by a
                // stateful/session-ID resumption attempt crafted by the
                // attacker, with no real client agent involved).
                //
                // If both connections resumed/established the *same* session
                // (same non-empty session_id) but the ClientHello presented a
                // different SNI the second time, the server should have
                // declined resumption and fallen back to a full handshake
                // (RFC 6066 Section 3). wolfSSL's stateful session-ID
                // resumption never checks this (CVE-2026-11703): it only
                // revalidates EMS and cipher-suite membership, never SNI.
                if claim_a.0.origin == AgentType::Server && claim_b.0.origin == AgentType::Server
                {
                    let (first, second) = (claim_a.1, claim_b.1);
                    if !first.session_id.is_empty()
                        && first.session_id == second.session_id
                        && first.server_name != second.server_name
                    {
                        return Some("Resumed session under a different SNI");
                    }
                }
            }
        } else {
            // this is the case for seed_client_attacker12 which records only the server claims

            let found = claims.iter().find_map(|claim| match &claim.data {
                ClaimData::Message(ClaimDataMessage::Finished(data)) => {
                    if data.outbound {
                        None
                    } else {
                        Some((claim, data))
                    }
                }
                _ => None,
            });
            if let Some((claim, finished)) = found {
                if !finished.available_ciphers.is_empty()
                    && !finished.available_ciphers.contains(&finished.chosen_cipher)
                {
                    // available_ciphers is set with the SSL context, it's the list of accepted
                    // ciphers, chosen_cipher is the negotiated one
                    return Some("Negotiated cipher is not in agent's configured ciphers list");
                }

                let violation = finished.authenticate_peer
                    && match claim.origin {
                        AgentType::Server => finished.peer_certificate.as_slice() != BOB_CERT.1,
                        AgentType::Client => finished.peer_certificate.as_slice() != ALICE_CERT.1,
                    };

                if violation {
                    return Some("Authentication bypass");
                }
            }
        }

        None
    }
}

pub fn find_two_finished_messages(
    claims: &[TlsClaim],
) -> Option<((&TlsClaim, &Finished), (&TlsClaim, &Finished))> {
    let non_outbound = || {
        claims.iter().filter_map(|claim| match &claim.data {
            ClaimData::Message(ClaimDataMessage::Finished(data)) => {
                if data.outbound {
                    None
                } else {
                    Some((claim, data))
                }
            }
            _ => None,
        })
    };

    let two_finishes: Option<((&TlsClaim, &Finished), (&TlsClaim, &Finished))> =
        non_outbound().collect_tuple();

    if let Some(((claim_a, _), (claim_b, _))) = two_finishes {
        if claim_a.agent_name != claim_b.agent_name {
            return two_finishes;
        }
        // One agent finished twice because of session resumption: fall through to the
        // per-agent grouping below instead of returning None outright, in case a
        // *different* agent's claim(s) are also present (see below).
    }

    // An agent can emit several non-outbound Finished claims over the course of a trace
    // (e.g. `CheckServerClaimFinished` re-fires on every message past a certain state, and
    // a trace reusing the same agent/process across two connections - such as a full
    // handshake followed by a session-ID resumption attempt - produces claims for both).
    // Group by agent and keep only the last claim per agent, so this still resolves to
    // "one claim per agent" regardless of how many times any single agent's claim fired.
    //
    // Only used as a fallback (above), and only when both resulting agents are
    // Server-origin: that is the one case this is meant to support (two separate
    // connections against the same reused *server* agent, e.g. CVE-2026-11703's full
    // handshake followed by a resumption attempt - see the two-Server-claims branch in
    // `check_violation`). A real two-sided Client+Server trace that also emits more than
    // one non-outbound claim per agent (observed for some PUTs) keeps returning `None`
    // here exactly as before, since comparing two non-simultaneous snapshots there is not
    // known to be safe/meaningful the way it is for the two-Server case.
    let mut last_per_agent: Vec<(&TlsClaim, &Finished)> = Vec::new();
    for (claim, data) in non_outbound() {
        if let Some(slot) = last_per_agent
            .iter_mut()
            .find(|(c, _)| c.agent_name == claim.agent_name)
        {
            *slot = (claim, data);
        } else {
            last_per_agent.push((claim, data));
        }
    }

    if last_per_agent.len() == 2
        && last_per_agent[0].0.origin == AgentType::Server
        && last_per_agent[1].0.origin == AgentType::Server
    {
        let b = last_per_agent.pop().unwrap();
        let a = last_per_agent.pop().unwrap();
        Some((a, b))
    } else {
        None
    }
}

pub fn get_client_server<'a, T>(
    a: (&'a TlsClaim, &'a T),
    b: (&'a TlsClaim, &'a T),
) -> Option<((&'a TlsClaim, &'a T), (&'a TlsClaim, &'a T))> {
    match a.0.origin {
        AgentType::Server => match b.0.origin {
            AgentType::Server => None,
            AgentType::Client => Some((b, a)),
        },
        AgentType::Client => match b.0.origin {
            AgentType::Server => Some((a, b)),
            AgentType::Client => None,
        },
    }
}
