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
        // RFC 7366 (Encrypt-then-MAC): whenever a CBC cipher suite is negotiated and a side's
        // peer offered the `encrypt_then_mac` extension, that side MUST actually use
        // Encrypt-then-MAC, never silently fall back to MAC-then-Encrypt (CVE-2026-6092).
        //
        // This check is independent of the client/server-pairing logic below: on the buggy
        // wolfSSL server, the downgrade is self-consistent (a real peer never sees the
        // extension echoed back, so it does not switch to ETM either), so comparing claims
        // against each other -- as the checks below do -- can never catch it. A single agent's
        // own claim is both necessary and sufficient here.
        for claim in claims {
            if let ClaimData::Message(ClaimDataMessage::Finished(data)) = &claim.data {
                if data.encrypt_then_mac_offered
                    && data.cbc_cipher_suite
                    && !data.encrypt_then_mac_active
                {
                    return Some("Encrypt-then-MAC was silently downgraded to MAC-then-Encrypt");
                }

                // The converse: a side must never end up actually using Encrypt-then-MAC
                // unless it was negotiated. If it were, the peer -- expecting the default
                // MAC-then-Encrypt -- would misinterpret the record layer.
                if data.encrypt_then_mac_active && !data.encrypt_then_mac_offered {
                    return Some("Encrypt-then-MAC used without having been negotiated");
                }
            }
        }

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

                // Unlike the single-claim check above (which catches CVE-2026-6092's silent,
                // self-consistent downgrade -- both sides quietly agreeing on
                // MAC-then-Encrypt), this catches a genuine client/server desync: one side
                // thinks it is doing Encrypt-then-MAC while the other does not, which would
                // break MAC verification on the record layer.
                if client.cbc_cipher_suite
                    && server.cbc_cipher_suite
                    && client.encrypt_then_mac_active != server.encrypt_then_mac_active
                {
                    return Some("Mismatching encrypt-then-MAC");
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
                        // WARNING: remove filter once RUST PUTS are removed
                        #[cfg(not(feature = "openssl_binding"))]
                        return Some("Version undefined after handshake");
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
