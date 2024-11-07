use itertools::Itertools;
use puffin::agent::{AgentType, TLSVersion};
use puffin::claims::SecurityViolationPolicy;

use crate::claims::{ClaimData, ClaimDataMessage, Finished, TlsClaim};
use crate::static_certs::{ALICE_CERT, BOB_CERT};

pub struct TlsSecurityViolationPolicy;

impl SecurityViolationPolicy for TlsSecurityViolationPolicy {
    type C = TlsClaim;

    fn check_violation(claims: &[TlsClaim]) -> Option<&'static str> {
        if let Some((claim_a, claim_b)) = find_two_finished_messages(claims) {
            if let Some(((client_claim, client), (server_claim, server))) =
                get_client_server(claim_a, claim_b)
            {
                if client_claim.protocol_version != server_claim.protocol_version {
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

                match client_claim.protocol_version {
                    TLSVersion::V1_2 => {
                        // TLS 1.2 Checks

                        // https://datatracker.ietf.org/doc/html/rfc5077#section-3.4
                        if !server.session_id.is_empty() && client.session_id != server.session_id {
                            return Some("Mismatching session ids");
                        }
                    }
                    TLSVersion::V1_3 => {
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
                }
            } else {
                // Could not choose exactly one server and client
                // possibly two server because of session resumption
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
    let two_finishes: Option<((&TlsClaim, &Finished), (&TlsClaim, &Finished))> = claims
        .iter()
        .filter_map(|claim| match &claim.data {
            ClaimData::Message(ClaimDataMessage::Finished(data)) => {
                if data.outbound {
                    None
                } else {
                    Some((claim, data))
                }
            }
            _ => None,
        })
        .collect_tuple();

    if let Some(((claim_a, _), (claim_b, _))) = two_finishes {
        if claim_a.agent_name == claim_b.agent_name {
            // One agent finished twice because of session resumption
            return None;
        }
    }

    two_finishes
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
