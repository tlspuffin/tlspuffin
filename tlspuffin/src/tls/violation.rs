use std::{any::Any, fmt::Debug, hash::Hash};

use itertools::Itertools;

use crate::{
    agent::{AgentType, TLSVersion},
    claims::{Claim, ClaimData, ClaimDataMessage},
};

pub fn is_violation(claims: &[Claim]) -> Option<&'static str> {
    if let Some((claim_a, claim_b)) = find_two_finished_messages(claims) {
        if let Some((client, server)) = get_client_server(claim_a, claim_b) {
            if client.protocol_version != server.protocol_version {
                return Some("Mismatching versions");
            }

            let client = match &client.data {
                ClaimData::Message(ClaimDataMessage::Finished(claim)) => Some(claim),
                _ => None,
            }
            .unwrap();

            let server = match &server.data {
                ClaimData::Message(ClaimDataMessage::Finished(claim)) => Some(claim),
                _ => None,
            }
            .unwrap();

            match claim_a.protocol_version {
                TLSVersion::V1_2 => {
                    // TLS 1.2 Checks
                    if client.master_secret != server.master_secret {
                        return Some("Mismatching master secrets");
                    }

                    // https://datatracker.ietf.org/doc/html/rfc5077#section-3.4
                    if !server.session_id.is_empty() && client.session_id != server.session_id {
                        return Some("Mismatching session ids");
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
                }
                TLSVersion::V1_3 => {
                    // TLS 1.3 Checks
                    if client.master_secret != server.master_secret {
                        return Some("Mismatching master secrets");
                    }

                    if client.session_id != server.session_id {
                        return Some("Mismatching session ids");
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

                    if client.available_ciphers.len() > 0 && server.available_ciphers.len() > 0 {
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

                    if client.signature_algorithm != server.peer_signature_algorithm
                        || server.signature_algorithm != client.peer_signature_algorithm
                    {
                        return Some("mismatching signature algorithms");
                    }
                }
            }
        } else {
            // Could not choose exactly one server and client
            // possibly two server because of session resumption
        }
    } else {
        // this is the case for seed_client_attacker12 which records only the server claims
    }

    None
}

pub fn find_two_finished_messages(claims: &[Claim]) -> Option<(&Claim, &Claim)> {
    let two_finishes: Option<(&Claim, &Claim)> = claims
        .iter()
        .filter(|claim| {
            matches!(
                claim.data,
                ClaimData::Message(ClaimDataMessage::Finished(_))
            ) && !claim.outbound
        })
        .collect_tuple();

    if let Some((claim_a, claim_b)) = two_finishes {
        if claim_a.agent_name == claim_b.agent_name {
            // One agent finished twice because of session resumption
            return None;
        }
    }

    two_finishes
}

pub fn get_client_server<'a>(
    claim_a: &'a Claim,
    claim_b: &'a Claim,
) -> Option<(&'a Claim, &'a Claim)> {
    match claim_a.origin {
        AgentType::Server => match claim_b.origin {
            AgentType::Server => None,
            AgentType::Client => Some((claim_b, claim_a)),
            _ => None,
        },
        AgentType::Client => match claim_b.origin {
            AgentType::Server => Some((claim_a, claim_b)),
            AgentType::Client => None,
            _ => None,
        },
        _ => None,
    }
}
