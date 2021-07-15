use itertools::Itertools;
use security_claims::{Claim, ClaimType};

use openssl_sys::{TLS1_2_VERSION, TLS1_3_VERSION};

use crate::agent::AgentName;

pub fn is_violation(claims: &Vec<(AgentName, Claim)>) -> bool {
    if let Some(((agent_a, claim_a), (agent_b, claim_b))) = find_finished_messages(claims) {
        if claim_a.version != claim_b.version {
            return true;
        }

        let version = claim_a.version;

        match version.data {
            TLS1_2_VERSION => {
                // TLS 1.2 Checks
                if claim_a.master_secret_12 != claim_b.master_secret_12 {
                    return true;
                }

                if claim_a.session_id != claim_b.session_id {
                    return true;
                }

                if claim_a.server_random != claim_b.server_random {
                    return true;
                }
                if claim_a.client_random != claim_b.client_random {
                    return true;
                }


                if let Some(server_kex) = claims.iter().find(|(agent, claim)| claim.write == 1 && claim.server == 1 && claim.typ == ClaimType::CLAIM_SERVER_DONE) {
                    if let Some((client, _)) = get_client_server(claim_a, claim_b){
                        if server_kex.1.tmp_skey_type != client.peer_tmp_skey_type {
                            return true;
                        }
                    } else {
                        return true
                    }
                } else {
                    return true
                }


                if claim_a.chosen_cipher != claim_b.chosen_cipher {
                    return true;
                }

                if !(claim_a.signature_algorithm == claim_b.peer_signature_algorithm
                    || claim_b.signature_algorithm == claim_a.peer_signature_algorithm)
                {
                    return true;
                }
            },
            TLS1_3_VERSION => {
                // TLS 1.3 Checks
                if claim_a.master_secret != claim_b.master_secret {
                    return true;
                }

                if claim_a.session_id != claim_b.session_id {
                    return true;
                }

                if claim_a.server_random != claim_b.server_random {
                    return true;
                }
                if claim_a.client_random != claim_b.client_random {
                    return true;
                }

                if claim_a.tmp_skey_type != claim_b.tmp_skey_type {
                    return true;
                }
                if claim_a.tmp_skey_group_id != claim_b.tmp_skey_group_id {
                    return true;
                }

                if claim_a.chosen_cipher != claim_b.chosen_cipher {
                    return true;
                }

                if !(claim_a.signature_algorithm == claim_b.peer_signature_algorithm
                    || claim_b.signature_algorithm == claim_a.peer_signature_algorithm)
                {
                    return true;
                }
            }
            _ => {
                // no checks available
            }
        }
    } else {
        // this is the case for seed_client_attacker12 which records only the server claims
    }

    false
}

pub fn find_finished_messages(
    claims: &Vec<(AgentName, Claim)>,
) -> Option<(&(AgentName, Claim), &(AgentName, Claim))> {
    let two_finishes = claims
        .iter()
        .filter(|(agent, claim)| claim.typ == ClaimType::CLAIM_FINISHED && claim.write == 0)
        .collect_tuple();

    two_finishes
}

/*pub fn find_claim<P>(
    claims: &Vec<(AgentName, Claim)>,
    predicate: P
) -> Option<&(AgentName, Claim)> where P: FnMut(&Claim) -> bool {
     claims
        .iter()
        .find(predicate)
}*/


pub fn get_client_server<'a>(claim_a: &'a Claim, claim_b: &'a Claim) -> Option<(&'a Claim, &'a Claim)> {
    match claim_a.server {
        1 => {
            match claim_b.server {
                1 => {
                    None
                },
                0 => {
                    Some((claim_b, claim_a))
                },
                _ => {
                    None
                }
            }
        },
        0 => {
            match claim_b.server {
                1 => {
                    Some((claim_a, claim_b))
                },
                0 => {
                   None
                },
                _ => {
                    None
                }
            }
        },
        _ => {
            None
        }
    }
}
