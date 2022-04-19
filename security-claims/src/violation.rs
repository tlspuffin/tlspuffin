use crate::{Claim, ClaimCipher, ClaimType};
use itertools::Itertools;
use std::any::Any;
use std::fmt::Debug;
use std::hash::Hash;

// Will be instantiated with (AgentName,Claim)
pub type ClaimMessage<AgentName>
where
    AgentName: Copy + Clone + Debug + Eq + PartialEq + Hash,
= (AgentName, Claim);

// This code is duplicated from super::super::agent, which is unfortunate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TLSVersion {
    V1_3,
    V1_2,
    Unknown,
}
// This code is duplicated from super::super::agent, which is unfortunate.
impl From<i32> for TLSVersion {
    fn from(value: i32) -> Self {
        match value {
            0x303 => TLSVersion::V1_2,
            0x304 => TLSVersion::V1_3,
            _ => TLSVersion::Unknown,
        }
    }
}

pub fn is_violation<A>(claims: &[ClaimMessage<A>]) -> Option<&'static str>
    where A: Eq {
    if let Some(((_agent_a, claim_a), (_agent_b, claim_b))) = find_two_finished_messages(claims) {
        if let Some((client, server)) = get_client_server(claim_a, claim_b) {
            if client.version != server.version {
                return Some("Mismatching versions");
            }

            let version = claim_a.version;

            match version.data.into() {
                TLSVersion::V1_2 => {
                    // TLS 1.2 Checks
                    if client.master_secret_12 != server.master_secret_12 {
                        return Some("Mismatching master secrets");
                    }

                    // https://datatracker.ietf.org/doc/html/rfc5077#section-3.4
                    if server.session_id.length != 0 && client.session_id != server.session_id {
                        return Some("Mismatching session ids");
                    }

                    if client.server_random != server.server_random {
                        return Some("Mismatching server random");
                    }
                    if client.client_random != server.client_random {
                        return Some("Mismatching client random");
                    }

                    if let Some(server_kex) = claims.iter().find(|(_agent, claim)| {
                        claim.write == 1
                            && claim.server == 1
                            && claim.typ == ClaimType::CLAIM_SERVER_DONE
                    }) {
                        if server_kex.1.tmp_skey_type != client.peer_tmp_skey_type {
                            return Some("Mismatching ephemeral kex method");
                        }
                    } else {
                        return Some("Server Done not found in server claims");
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

                    if client.tmp_skey_type != server.tmp_skey_type {
                        return Some("Mismatching ephemeral kex method");
                    }
                    if client.tmp_skey_group_id != server.tmp_skey_group_id {
                        return Some("Mismatching groups");
                    }

                    if client.chosen_cipher != server.chosen_cipher {
                        return Some("Mismatching ciphers");
                    }

                    if client.available_ciphers.length > 0 && server.available_ciphers.length > 0 {
                        let best_cipher = {
                            let mut cipher: Option<ClaimCipher> = None;
                            for server_cipher in &server.available_ciphers.ciphers
                                [..server.available_ciphers.length as usize]
                            {
                                if client.available_ciphers.ciphers.contains(server_cipher) {
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
                _ => {
                    // no checks available
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

pub fn find_two_finished_messages<A>(
    claims: &[ClaimMessage<A>],
) -> Option<(&ClaimMessage<A>, &ClaimMessage<A>)>
    where A:Eq {
    let two_finishes: Option<(&ClaimMessage<A>, &ClaimMessage<A>)> = claims
        .iter()
        .filter(|(_agent, claim)| claim.typ == ClaimType::CLAIM_FINISHED && claim.write == 0)
        .collect_tuple();

    if let Some(((agent_a, _), (agent_b, _))) = two_finishes {
        if agent_a == agent_b {
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
    match claim_a.server {
        1 => match claim_b.server {
            1 => None,
            0 => Some((claim_b, claim_a)),
            _ => None,
        },
        0 => match claim_b.server {
            1 => Some((claim_a, claim_b)),
            0 => None,
            _ => None,
        },
        _ => None,
    }
}
