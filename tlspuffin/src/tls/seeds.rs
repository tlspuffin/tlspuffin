//! Implementation of  special traces. Each may represent a special TLS execution like a full
//! handshake or an execution which crashes OpenSSL.
#![allow(dead_code)]

use puffin::algebra::TermEval;
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
        rustls::msgs::{
            enums::{CipherSuite, Compression, HandshakeType, ProtocolVersion},
            handshake::{Random, ServerExtension, SessionID},
        },
        trace_helper::TraceHelper,
    },
};

pub fn seed_successful_client_auth(client: AgentName, server: AgentName) -> Trace<TlsQueryMatcher> {
    Trace {
        prior_traces: vec![],
        descriptors: vec![
            AgentDescriptor {
                name: client,
                tls_version: TLSVersion::V1_3,
                typ: AgentType::Client,
                client_authentication: true,
                ..AgentDescriptor::default()
            },
            AgentDescriptor {
                name: server,
                tls_version: TLSVersion::V1_3,
                typ: AgentType::Server,
                client_authentication: true,
                ..AgentDescriptor::default()
            },
        ],
        steps: vec![
            OutputAction::new_step(client),
            // Client Hello Client -> Server
            Step {
                agent: server,
                action: Action::Input(InputAction {
                    recipe: term! {
                        fn_client_hello(
                            ((client, 0)),
                            ((client, 0)),
                            ((client, 0)),
                            ((client, 0)),
                            ((client, 0)),
                            ((client, 0))
                        )
                    },
                }),
            },
            // Server Hello Server -> Client
            Step {
                agent: client,
                action: Action::Input(InputAction {
                    recipe: term! {
                        fn_server_hello(
                            ((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerHello)))]/ProtocolVersion),
                            ((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerHello)))]/Random),
                            ((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerHello)))]/SessionID),
                            ((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerHello)))]/CipherSuite),
                            ((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerHello)))]/Compression),
                            ((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerHello)))]/Vec<ServerExtension>)
                        )
                    },
                }),
            },
            // Encrypted Extensions Server -> Client
            Step {
                agent: client,
                action: Action::Input(InputAction {
                    recipe: term! {
                        fn_application_data(
                            ((server, 0)[Some(TlsQueryMatcher::ApplicationData)]/Vec<u8>)
                        )
                    },
                }),
            },
            // Certificate Request Server -> Client
            Step {
                agent: client,
                action: Action::Input(InputAction {
                    recipe: term! {
                        fn_application_data(
                            ((server, 1)[Some(TlsQueryMatcher::ApplicationData)]/Vec<u8>)
                        )
                    },
                }),
            },
            // Certificate Server -> Client
            Step {
                agent: client,
                action: Action::Input(InputAction {
                    recipe: term! {
                        fn_application_data(
                            ((server, 2)[Some(TlsQueryMatcher::ApplicationData)]/Vec<u8>)
                        )
                    },
                }),
            },
            // Certificate Verify Server -> Client
            Step {
                agent: client,
                action: Action::Input(InputAction {
                    recipe: term! {
                        fn_application_data(
                            ((server, 3)[Some(TlsQueryMatcher::ApplicationData)]/Vec<u8>)
                        )
                    },
                }),
            },
            // Finish Server -> Client
            Step {
                agent: client,
                action: Action::Input(InputAction {
                    recipe: term! {
                        fn_application_data(
                            ((server, 4)[Some(TlsQueryMatcher::ApplicationData)]/Vec<u8>)
                        )
                    },
                }),
            },
            // Certificate Client -> Server
            Step {
                agent: server,
                action: Action::Input(InputAction {
                    recipe: term! {
                        fn_application_data(
                            ((client, 0)[Some(TlsQueryMatcher::ApplicationData)]/Vec<u8>)
                        )
                    },
                }),
            },
            // CertificateVerify Client -> Server
            Step {
                agent: server,
                action: Action::Input(InputAction {
                    recipe: term! {
                        fn_application_data(
                            ((client, 1)[Some(TlsQueryMatcher::ApplicationData)]/Vec<u8>)
                        )
                    },
                }),
            },
            // Finished Client -> Server
            Step {
                agent: server,
                action: Action::Input(InputAction {
                    recipe: term! {
                        fn_application_data(
                            ((client, 2)[Some(TlsQueryMatcher::ApplicationData)]/Vec<u8>)
                        )
                    },
                }),
            },
        ],
    }
}

pub fn seed_successful(client: AgentName, server: AgentName) -> Trace<TlsQueryMatcher> {
    Trace {
        prior_traces: vec![],
        descriptors: vec![
            AgentDescriptor::new_client(client, TLSVersion::V1_3),
            AgentDescriptor::new_server(server, TLSVersion::V1_3),
        ],
        steps: vec![
            OutputAction::new_step(client),
            // Client Hello Client -> Server
            Step {
                agent: server,
                action: Action::Input(InputAction {
                    recipe: term! {
                        fn_client_hello(
                            ((client, 0)),
                            ((client, 0)),
                            ((client, 0)),
                            ((client, 0)),
                            ((client, 0)),
                            ((client, 0))
                        )
                    },
                }),
            },
            // Server Hello Server -> Client
            Step {
                agent: client,
                action: Action::Input(InputAction {
                    recipe: term! {
                        fn_server_hello(
                            ((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerHello)))]/ProtocolVersion),
                            ((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerHello)))]/Random),
                            ((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerHello)))]/SessionID),
                            ((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerHello)))]/CipherSuite),
                            ((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerHello)))]/Compression),
                            ((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerHello)))]/Vec<ServerExtension>)
                        )
                    },
                }),
            },
            // Encrypted Extensions Server -> Client
            Step {
                agent: client,
                action: Action::Input(InputAction {
                    recipe: term! {
                        fn_application_data(
                            ((server, 0)[Some(TlsQueryMatcher::ApplicationData)]/Vec<u8>)
                        )
                    },
                }),
            },
            // Certificate Server -> Client
            Step {
                agent: client,
                action: Action::Input(InputAction {
                    recipe: term! {
                        fn_application_data(
                            ((server, 1)[Some(TlsQueryMatcher::ApplicationData)]/Vec<u8>)
                        )
                    },
                }),
            },
            // Certificate Verify Server -> Client
            Step {
                agent: client,
                action: Action::Input(InputAction {
                    recipe: term! {
                        fn_application_data(
                            ((server, 2)[Some(TlsQueryMatcher::ApplicationData)]/Vec<u8>)
                        )
                    },
                }),
            },
            // Finish Server -> Client
            Step {
                agent: client,
                action: Action::Input(InputAction {
                    recipe: term! {
                        fn_application_data(
                            ((server, 3)[Some(TlsQueryMatcher::ApplicationData)]/Vec<u8>)
                        )
                    },
                }),
            },
            // Finished Client -> Server
            Step {
                agent: server,
                action: Action::Input(InputAction {
                    recipe: term! {
                        fn_application_data(
                            ((client, 0)[Some(TlsQueryMatcher::ApplicationData)]/Vec<u8>)
                        )
                    },
                }),
            },
        ],
    }
}

/// Seed which triggers a MITM attack. It changes the cipher suite. This should fail.
pub fn seed_successful_mitm(client: AgentName, server: AgentName) -> Trace<TlsQueryMatcher> {
    Trace {
        prior_traces: vec![],
        descriptors: vec![
            AgentDescriptor::new_client(client, TLSVersion::V1_3),
            AgentDescriptor::new_server(server, TLSVersion::V1_3),
        ],
        steps: vec![
            OutputAction::new_step(client),
            // Client Hello Client -> Server
            Step {
                agent: server,
                action: Action::Input(InputAction {
                    recipe: term! {
                        fn_client_hello(
                            ((client, 0)),
                            ((client, 0)),
                            ((client, 0)),
                            (fn_append_cipher_suite(
                                fn_new_cipher_suites,
                                fn_cipher_suite13_aes_128_gcm_sha256
                            )),
                            ((client, 0)),
                            ((client, 0))
                        )
                    },
                }),
            },
            // Server Hello Server -> Client
            Step {
                agent: client,
                action: Action::Input(InputAction {
                    recipe: term! {
                        fn_server_hello(
                            ((server, 0)),
                            ((server, 0)),
                            ((server, 0)),
                            ((server, 0)),
                            ((server, 0)),
                            ((server, 0))
                        )
                    },
                }),
            },
            // Encrypted Extensions Server -> Client
            Step {
                agent: client,
                action: Action::Input(InputAction {
                    recipe: term! {
                        fn_application_data(
                            ((server, 0)[Some(TlsQueryMatcher::ApplicationData)]/Vec<u8>)
                        )
                    },
                }),
            },
            // Certificate Server -> Client
            Step {
                agent: client,
                action: Action::Input(InputAction {
                    recipe: term! {
                        fn_application_data(
                            ((server, 1)[Some(TlsQueryMatcher::ApplicationData)]/Vec<u8>)
                        )
                    },
                }),
            },
            // Certificate Verify Server -> Client
            Step {
                agent: client,
                action: Action::Input(InputAction {
                    recipe: term! {
                        fn_application_data(
                            ((server, 2)[Some(TlsQueryMatcher::ApplicationData)]/Vec<u8>)
                        )
                    },
                }),
            },
            // Finish Server -> Client
            Step {
                agent: client,
                action: Action::Input(InputAction {
                    recipe: term! {
                        fn_application_data(
                            ((server, 3)[Some(TlsQueryMatcher::ApplicationData)]/Vec<u8>)
                        )
                    },
                }),
            },
            // Finished Client -> Server
            Step {
                agent: server,
                action: Action::Input(InputAction {
                    recipe: term! {
                        fn_application_data(
                            ((client, 0)[Some(TlsQueryMatcher::ApplicationData)]/Vec<u8>)
                        )
                    },
                }),
            },
        ],
    }
}

pub fn seed_successful12_with_tickets(
    client: AgentName,
    server: AgentName,
) -> Trace<TlsQueryMatcher> {
    let mut trace = seed_successful12(client, server);
    // NewSessionTicket, Server -> Client
    // wolfSSL 4.4.0 does not support tickets in TLS 1.2
    trace.steps.insert(
        9,
        Step {
            agent: client,
            action: Action::Input(InputAction {
                recipe: term! {
                    fn_new_session_ticket(
                        ((server, 0)/u64),
                        ((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::NewSessionTicket)))]/Vec<u8>)
                    )
                },
            }),
        },
    );

    trace.steps[11] = Step {
        agent: client,
        action: Action::Input(InputAction {
            recipe: term! {
                fn_opaque_message(
                    ((server, 6)[None])
                )
            },
        }),
    };

    trace
}

pub fn seed_successful12(client: AgentName, server: AgentName) -> Trace<TlsQueryMatcher> {
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
                            ((server, 0)),
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
            // Server Change Cipher Spec, Server -> Client
            Step {
                agent: client,
                action: Action::Input(InputAction {
                    recipe: term! {
                        fn_change_cipher_spec
                    },
                }),
            },
            // Server Handshake Finished, Server -> Client
            Step {
                agent: client,
                action: Action::Input(InputAction {
                    recipe: term! {
                        fn_opaque_message(
                            ((server, 5)[None])
                        )
                    },
                }),
            },
        ],
    }
}

pub fn seed_successful_with_ccs(client: AgentName, server: AgentName) -> Trace<TlsQueryMatcher> {
    let mut trace = seed_successful(client, server);

    // CCS Server -> Client
    trace.steps.insert(
        3,
        Step {
            agent: client,
            action: Action::Input(InputAction {
                recipe: term! {
                    fn_change_cipher_spec
                },
            }),
        },
    );

    trace.steps.insert(
        8,
        Step {
            agent: server,
            action: Action::Input(InputAction {
                recipe: term! {
                    fn_change_cipher_spec
                },
            }),
        },
    );

    trace
}

pub fn seed_successful_with_tickets(
    client: AgentName,
    server: AgentName,
) -> Trace<TlsQueryMatcher> {
    let mut trace = seed_successful_with_ccs(client, server);

    trace.steps.push(OutputAction::new_step(server));
    // Ticket
    trace.steps.push(Step {
        agent: client,
        action: Action::Input(InputAction {
            recipe: term! {
                fn_application_data(
                    ((server, 4)[Some(TlsQueryMatcher::ApplicationData)]/Vec<u8>)
                )
            },
        }),
    });
    // Ticket (wolfSSL 4.4.0 only sends a single ticket)
    #[cfg(not(feature = "wolfssl430"))]
    trace.steps.push(Step {
        agent: client,
        action: Action::Input(InputAction {
            recipe: term! {
                fn_application_data(
                    ((server, 5)[Some(TlsQueryMatcher::ApplicationData)]/Vec<u8>)
                )
            },
        }),
    });

    trace
}

pub fn seed_server_attacker_full(client: AgentName) -> Trace<TlsQueryMatcher> {
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
            (fn_server_extensions_append(
                (fn_server_extensions_append(
                    fn_server_extensions_new,
                    (fn_key_share_deterministic_server_extension((@curve)))
                )),
                fn_supported_versions13_server_extension
            ))
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

    let encrypted_extensions = term! {
        fn_encrypted_extensions(
            fn_server_extensions_new
        )
    };

    let certificate = term! {
        fn_certificate13(
            (fn_empty_bytes_vec),
            (fn_append_certificate_entry(
                (fn_certificate_entry(
                    fn_alice_cert
                )),
              fn_empty_certificate_chain
            ))
        )
    };

    let encrypted_extensions_transcript = term! {
        fn_append_transcript(
            (@server_hello_transcript),
            (@encrypted_extensions) // plaintext EncryptedExtensions
        )
    };

    let certificate_transcript = term! {
        fn_append_transcript(
            (@encrypted_extensions_transcript),
            (@certificate) // plaintext Certificate
        )
    };

    let certificate_verify = term! {
        fn_certificate_verify(
            fn_rsa_pss_signature_algorithm,
            (fn_rsa_sign_server(
                (@certificate_transcript),
                fn_alice_key,
                fn_rsa_pss_signature_algorithm
            ))
        )
    };

    let certificate_verify_transcript = term! {
        fn_append_transcript(
            (@certificate_transcript),
            (@certificate_verify) // plaintext CertificateVerify
        )
    };

    let server_finished = term! {
        fn_finished(
            (fn_verify_data_server(
                (@certificate_verify_transcript),
                //(fn_server_finished_transcript(((client, 0)))),
                (@server_hello_transcript),
                (fn_get_client_key_share(((client, 0)), (@curve))),
                (@curve),
                fn_no_psk
            ))
        )
    };

    Trace {
        prior_traces: vec![],
        descriptors: vec![AgentDescriptor {
            name: client,
            tls_version: TLSVersion::V1_3,
            typ: AgentType::Client,
            ..AgentDescriptor::default()
        }],
        steps: vec![
            OutputAction::new_step(client),
            Step {
                agent: client,
                action: Action::Input(InputAction {
                    recipe: server_hello,
                }),
            },
            Step {
                agent: client,
                action: Action::Input(InputAction {
                    recipe: term! {
                        fn_encrypt_handshake(
                            (@encrypted_extensions),
                            (@server_hello_transcript),
                            (fn_get_client_key_share(((client, 0)), (@curve))),
                            fn_no_psk,
                            (@curve),
                            fn_false,
                            fn_seq_0  // sequence 0
                        )
                    },
                }),
            },
            Step {
                agent: client,
                action: Action::Input(InputAction {
                    recipe: term! {
                        fn_encrypt_handshake(
                            (@certificate),
                            (@server_hello_transcript),
                            (fn_get_client_key_share(((client, 0)), (@curve))),
                            fn_no_psk,
                            (@curve),
                            fn_false,
                            fn_seq_1  // sequence 1
                        )
                    },
                }),
            },
            Step {
                agent: client,
                action: Action::Input(InputAction {
                    recipe: term! {
                        fn_encrypt_handshake(
                            (@certificate_verify),
                            (@server_hello_transcript),
                            (fn_get_client_key_share(((client, 0)), (@curve))),
                            fn_no_psk,
                            (@curve),
                            fn_false,
                            fn_seq_2  // sequence 2
                        )
                    },
                }),
            },
            Step {
                agent: client,
                action: Action::Input(InputAction {
                    recipe: term! {
                        fn_encrypt_handshake(
                            (@server_finished),
                            (@server_hello_transcript),
                            (fn_get_client_key_share(((client, 0)), (@curve))),
                            fn_no_psk,
                            (@curve),
                            fn_false,
                            fn_seq_3  // sequence 3
                        )
                    },
                }),
            },
        ],
    }
}

pub fn seed_client_attacker_auth(server: AgentName) -> Trace<TlsQueryMatcher> {
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

    /*let encrypted_extensions = term! {
        fn_decrypt_handshake(
            ((server, 0)[Some(TlsQueryMatcher::ApplicationData)]), // Ticket from last session
            (fn_server_hello_transcript(((server, 0)))),
            (fn_get_server_key_share(((server, 0)))),
            fn_no_psk,
            fn_named_group_secp384r1,
            fn_true,
            fn_seq_0
        )
    };*/

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

    let certificate = term! {
        fn_certificate13(
            (fn_get_context((@certificate_request_message))),
            (fn_append_certificate_entry(
                (fn_certificate_entry(
                    fn_bob_cert
                )),
              fn_empty_certificate_chain
            ))
        )
    };

    let certificate_verify = term! {
        fn_certificate_verify(
            fn_rsa_pss_signature_algorithm,
            (fn_rsa_sign_client(
                (fn_certificate_transcript(((server, 0)))),
                fn_bob_key,
                fn_rsa_pss_signature_algorithm
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
                            (@certificate_verify),
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
    }
}

pub fn seed_client_attacker(server: AgentName) -> Trace<TlsQueryMatcher> {
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

    Trace {
        prior_traces: vec![],
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
            OutputAction::new_step(server),
        ],
    }
}

pub fn seed_client_attacker12(server: AgentName) -> Trace<TlsQueryMatcher> {
    _seed_client_attacker12(server).0
}

pub fn _seed_client_attacker12(
    server: AgentName,
) -> (Trace<TlsQueryMatcher>, TermEval<TlsQueryMatcher>) {
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
                        (fn_client_extensions_append(
                            (fn_client_extensions_append(
                                (fn_client_extensions_append(
                                    fn_client_extensions_new,
                                    (fn_support_group_extension(fn_named_group_secp384r1))
                                )),
                                fn_signature_algorithm_extension
                            )),
                            fn_ec_point_formats_extension
                        )),
                        fn_signed_certificate_timestamp_extension
                    )),
                     // Enable Renegotiation
                    (fn_renegotiation_info_extension(fn_empty_bytes_vec))
                )),
                // Add signature cert extension
                fn_signature_algorithm_cert_extension
            ))
        )
    };

    let server_hello_transcript = term! {
        fn_append_transcript(
            (fn_append_transcript(
                fn_new_transcript12,
                (@client_hello) // ClientHello
            )),
            ((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerHello)))]) // plaintext ServerHello
        )
    };

    let certificate_transcript = term! {
        fn_append_transcript(
            (@server_hello_transcript),
            ((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::Certificate)))]) // Certificate
        )
    };

    let server_key_exchange_transcript = term! {
      fn_append_transcript(
            (@certificate_transcript),
            ((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerKeyExchange)))]) // ServerKeyExchange
        )
    };

    let server_hello_done_transcript = term! {
      fn_append_transcript(
            (@server_key_exchange_transcript),
            ((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerHelloDone)))]) // ServerHelloDone
        )
    };

    let client_key_exchange = term! {
        fn_client_key_exchange(
            (fn_encode_ec_pubkey12(
                (fn_new_pubkey12(fn_named_group_secp384r1))
            ))
        )
    };

    let client_key_exchange_transcript = term! {
      fn_append_transcript(
            (@server_hello_done_transcript),
            (@client_key_exchange)
        )
    };

    let client_verify_data = term! {
        fn_sign_transcript(
            ((server, 0)),
            (fn_decode_ecdh_pubkey(
                ((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerKeyExchange)))]/Vec<u8>) // ServerECDHParams
            )),
            (@client_key_exchange_transcript),
            fn_named_group_secp384r1
        )
    };

    let trace = Trace {
        prior_traces: vec![],
        descriptors: vec![AgentDescriptor::new_server(server, TLSVersion::V1_2)],
        steps: vec![
            Step {
                agent: server,
                action: Action::Input(InputAction {
                    recipe: client_hello,
                }),
            },
            Step {
                agent: server,
                action: Action::Input(InputAction {
                    recipe: client_key_exchange,
                }),
            },
            Step {
                agent: server,
                action: Action::Input(InputAction {
                    recipe: term! { fn_change_cipher_spec },
                }),
            },
            Step {
                agent: server,
                action: Action::Input(InputAction {
                    recipe: term! {
                        fn_encrypt12(
                            (fn_finished((@client_verify_data))),
                            ((server, 0)),
                            (fn_decode_ecdh_pubkey(
                                ((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerKeyExchange)))]/Vec<u8>) // ServerECDHParams
                            )),
                            fn_named_group_secp384r1,
                            fn_true,
                            fn_seq_0
                        )
                    },
                }),
            },
        ],
    };

    (trace, client_verify_data)
}

pub fn seed_session_resumption_dhe(
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
                            (fn_client_extensions_append(
                                (fn_client_extensions_append(
                                    fn_client_extensions_new,
                                    (fn_support_group_extension(fn_named_group_secp384r1))
                                )),
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

    let resumption_client_finished = term! {
        fn_finished(
            (fn_verify_data(
                (fn_server_finished_transcript(((server, 0)))),
                (fn_server_hello_transcript(((server, 0)))),
                (fn_get_server_key_share(((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerHello)))]))),
                (fn_psk((@psk))),
                fn_named_group_secp384r1
            ))
        )
    };

    Trace {
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
                        fn_encrypt_handshake(
                            (@resumption_client_finished),
                            (fn_server_hello_transcript(((server, 0)))),
                            (fn_get_server_key_share(((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerHello)))]))),
                            (fn_psk((@psk))),
                            fn_named_group_secp384r1,
                            fn_true,
                            fn_seq_0  // sequence 0
                        )
                    },
                }),
            },
        ],
    }
}

pub fn seed_session_resumption_ke(
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
                            (fn_client_extensions_append(
                                (fn_client_extensions_append(
                                    fn_client_extensions_new,
                                    (fn_support_group_extension(fn_named_group_secp384r1))
                                )),
                                fn_signature_algorithm_extension
                            )),
                            fn_supported_versions13_extension
                        )),
                        (fn_key_share_deterministic_extension(fn_named_group_secp384r1))
                    )),
                    fn_psk_exchange_mode_ke_extension
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

    let resumption_client_finished = term! {
        fn_finished(
            (fn_verify_data(
                (fn_server_finished_transcript(((server, 0)))),
                (fn_server_hello_transcript(((server, 0)))),
                fn_no_key_share,
                (fn_psk((@psk))),
                fn_named_group_secp384r1
            ))
        )
    };

    Trace {
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
                        fn_encrypt_handshake(
                            (@resumption_client_finished),
                            (fn_server_hello_transcript(((server, 0)))),
                            fn_no_key_share,
                            (fn_psk((@psk))),
                            fn_named_group_secp384r1,
                            fn_true,
                            fn_seq_0  // sequence 0
                        )
                    },
                }),
            },
        ],
    }
}

pub fn seed_client_attacker_full(server: AgentName) -> Trace<TlsQueryMatcher> {
    _seed_client_attacker_full(server).0
}

/// Seed which contains the whole transcript in the tree. This is rather huge >300 symbols
pub fn _seed_client_attacker_full(
    server: AgentName,
) -> (
    Trace<TlsQueryMatcher>,
    TermEval<TlsQueryMatcher>,
    TermEval<TlsQueryMatcher>,
    TermEval<TlsQueryMatcher>,
) {
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

    let server_hello_transcript = term! {
        fn_append_transcript(
            (fn_append_transcript(
                fn_new_transcript,
                (@client_hello) // ClientHello
            )),
            ((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerHello)))]) // plaintext ServerHello
        )
    };

    // ((0, 1)) could be a CCS the server sends one

    let encrypted_extensions = term! {
        fn_decrypt_handshake(
            ((server, 0)[Some(TlsQueryMatcher::ApplicationData)]), // Encrypted Extensions
            (@server_hello_transcript),
            (fn_get_server_key_share(((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerHello)))]))),
            fn_no_psk,
            fn_named_group_secp384r1,
            fn_true,
            fn_seq_0  // sequence 0
        )
    };

    let encrypted_extension_transcript = term! {
        fn_append_transcript(
            (@server_hello_transcript),
            (@encrypted_extensions) // plaintext Encrypted Extensions
        )
    };

    let server_certificate = term! {
        fn_decrypt_handshake(
            ((server, 1)[Some(TlsQueryMatcher::ApplicationData)]),// Server Certificate
            (@server_hello_transcript),
            (fn_get_server_key_share(((server, 0)))),
            fn_no_psk,
            fn_named_group_secp384r1,
            fn_true,
            fn_seq_1 // sequence 1
        )
    };

    let server_certificate_transcript = term! {
        fn_append_transcript(
            (@encrypted_extension_transcript),
            (@server_certificate) // plaintext Server Certificate
        )
    };

    let server_certificate_verify = term! {
        fn_decrypt_handshake(
            ((server, 2)[Some(TlsQueryMatcher::ApplicationData)]), // Server Certificate Verify
            (@server_hello_transcript),
            (fn_get_server_key_share(((server, 0)))),
            fn_no_psk,
            fn_named_group_secp384r1,
            fn_true,
            fn_seq_2 // sequence 2
        )
    };

    let server_certificate_verify_transcript = term! {
        fn_append_transcript(
            (@server_certificate_transcript),
            (@server_certificate_verify) // plaintext Server Certificate Verify
        )
    };

    let server_finished = term! {
        fn_decrypt_handshake(
            ((server, 3)[Some(TlsQueryMatcher::ApplicationData)]), // Server Handshake Finished
            (@server_hello_transcript),
            (fn_get_server_key_share(((server, 0)))),
            fn_no_psk,
            fn_named_group_secp384r1,
            fn_true,
            fn_seq_3 // sequence 3
        )
    };

    let server_finished_transcript = term! {
        fn_append_transcript(
            (@server_certificate_verify_transcript),
            (@server_finished) // plaintext Server Handshake Finished
        )
    };

    let client_finished = term! {
        fn_finished(
            (fn_verify_data(
                (@server_finished_transcript),
                (@server_hello_transcript),
                (fn_get_server_key_share(((server, 0)))),
                fn_no_psk,
                fn_named_group_secp384r1
            ))
        )
    };

    let client_finished_transcript = term! {
        fn_append_transcript(
            (@server_finished_transcript),
            (@client_finished)
        )
    };

    let trace = Trace {
        prior_traces: vec![],
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
            OutputAction::new_step(server),
            Step {
                agent: server,
                action: Action::Input(InputAction {
                    recipe: term! {
                        fn_encrypt_handshake(
                            (@client_finished),
                            (@server_hello_transcript),
                            (fn_get_server_key_share(((server, 0)))),
                            fn_no_psk,
                            fn_named_group_secp384r1,
                            fn_true,
                            fn_seq_0  // sequence 0
                        )
                    },
                }),
            },
            OutputAction::new_step(server),
            /*Step {
                agent: server,
                action: Action::Input(InputAction {
                    recipe: term! {
                         fn_encrypt_application(
                            fn_alert_close_notify,
                            (@server_hello_transcript),
                            (@server_finished_transcript),
                            (fn_get_server_key_share(((server, 0)))),
                            fn_no_psk,
                            fn_named_group_secp384r1,
                            fn_seq_0  // sequence 0
                        )
                    },
                }),
            },
            OutputAction::new_step(server),*/
        ],
    };

    (
        trace,
        server_hello_transcript,
        server_finished_transcript,
        client_finished_transcript,
    )
}

/// Seed which contains the whole transcript in the tree. This is rather huge 10k symbols. It grows
/// exponentially.
pub fn seed_session_resumption_dhe_full(
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
                            (fn_client_extensions_append(
                                (fn_client_extensions_append(
                                    fn_client_extensions_new,
                                    (fn_support_group_extension(fn_named_group_secp384r1))
                                )),
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

    let resumption_server_hello_transcript = term! {
        fn_append_transcript(
            (fn_append_transcript(
                fn_new_transcript,
                (@full_client_hello) // ClientHello
            )),
            ((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerHello)))]) // plaintext ServerHello
        )
    };

    let resumption_encrypted_extensions = term! {
        fn_decrypt_handshake(
            ((server, 0)[Some(TlsQueryMatcher::ApplicationData)]), // Encrypted Extensions
            (@resumption_server_hello_transcript),
            (fn_get_server_key_share(((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerHello)))]))), //
            (fn_psk((@psk))),
            fn_named_group_secp384r1,
            fn_true,
            fn_seq_0  // sequence 0
        )
    };

    let resumption_encrypted_extension_transcript = term! {
        fn_append_transcript(
            (@resumption_server_hello_transcript),
            (@resumption_encrypted_extensions) // plaintext Encrypted Extensions
        )
    };

    let resumption_server_finished = term! {
        fn_decrypt_handshake(
            ((server, 1)[Some(TlsQueryMatcher::ApplicationData)]), // Server Handshake Finished
            (@resumption_server_hello_transcript),
            (fn_get_server_key_share(((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerHello)))]))), //
            (fn_psk((@psk))),
            fn_named_group_secp384r1,
            fn_true,
            fn_seq_1 // sequence 1
        )
    };

    let resumption_server_finished_transcript = term! {
        fn_append_transcript(
            (@resumption_encrypted_extension_transcript),
            (@resumption_server_finished) // plaintext Server Handshake Finished
        )
    };

    let resumption_client_finished = term! {
        fn_finished(
            (fn_verify_data(
                (@resumption_server_finished_transcript),
                (@resumption_server_hello_transcript),
                (fn_get_server_key_share(((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerHello)))]))),
                (fn_psk((@psk))),
                fn_named_group_secp384r1
            ))
        )
    };

    Trace {
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
                        fn_encrypt_handshake(
                            (@resumption_client_finished),
                            (@resumption_server_hello_transcript),
                            (fn_get_server_key_share(((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerHello)))]))),
                            (fn_psk((@psk))),
                            fn_named_group_secp384r1,
                            fn_true,
                            fn_seq_0  // sequence 0
                        )
                    },
                }),
            },
            /*Step {
                agent: server,
                action: Action::Input(InputAction {
                    recipe: term! {
                         fn_encrypt_application(
                            fn_alert_close_notify,
                            (@resumption_server_hello_transcript),
                            (@resumption_server_finished_transcript),
                            (fn_get_server_key_share(((server, 0)))),
                            (fn_psk((@psk))),
                            fn_seq_0  // sequence 0
                        )
                    },
                }),
            },*/
        ],
    }
}

macro_rules! corpus {
    ( $( $func:ident $(: $meta:meta)* ),* ) => {
        {
            let mut corpus = Vec::new();

            $(
                $( #[$meta] )*
                corpus.push(($func.build_trace(), $func.fn_name()));
            )*

            corpus
        }
    };
}

pub fn create_corpus() -> Vec<(Trace<TlsQueryMatcher>, &'static str)> {
    corpus!(
        // Full Handshakes
        seed_successful: cfg(feature = "tls13"),
        seed_successful_with_ccs: cfg(feature = "tls13"),
        seed_successful_with_tickets: cfg(feature = "tls13"),
        seed_successful12: cfg(not(feature = "tls12-session-resumption")),
        seed_successful12_with_tickets: cfg(feature = "tls12-session-resumption"),
        // Client Attackers
        seed_client_attacker: cfg(feature = "tls13"),
        seed_client_attacker_auth: cfg(all(feature = "tls13", feature = "client-authentication-transcript-extraction")),
        seed_client_attacker12: cfg(feature = "tls12"),
        // Session resumption
        seed_session_resumption_dhe: cfg(all(feature = "tls13", feature = "tls13-session-resumption")),
        seed_session_resumption_ke: cfg(all(feature = "tls13", feature = "tls13-session-resumption")),
        // Server Attackers
        seed_server_attacker_full: cfg(feature = "tls13")
    )
}

#[cfg(test)]
pub mod tests {

    use log::debug;
    use puffin::algebra::error::FnError;
    use puffin::algebra::{Payloads, replace_payloads, TermType, term::evaluate_lazy_test};
    use puffin::codec::Codec;
    use puffin::trace::TraceContext;
    use puffin::{agent::AgentName, trace::Action};
    use test_log::test;

    use super::*;
    use crate::protocol::TLSProtocolBehavior;
    use crate::tls::rustls::msgs::message::OpaqueMessage;
    use crate::{put_registry::TLS_PUT_REGISTRY, tls::trace_helper::TraceHelper};
    use puffin::fuzzer::harness::default_put_options;
    use puffin::libafl::inputs::HasBytesVec;
    use puffin::protocol::{OpaqueProtocolMessage, ProtocolBehavior, ProtocolMessage};
    use puffin::put::PutOptions;
    use puffin::trace::Action::Input;

    #[test]
    fn test_version() {
        TLS_PUT_REGISTRY.version_strings();
    }

    #[test]
    #[cfg(feature = "tls12")]
    fn test_seed_client_attacker12() {
        use crate::tls::trace_helper::TraceExecutor;

        let ctx = seed_client_attacker12.execute_trace();
        assert!(ctx.agents_successful());
    }

    #[cfg(feature = "tls13")] // require version which supports TLS 1.3
    #[cfg(feature = "transcript-extraction")] // this depends on extracted transcripts -> claims are required
    #[test]
    fn test_seed_client_attacker() {
        use crate::tls::trace_helper::TraceExecutor;

        let ctx = seed_client_attacker.execute_trace();
        assert!(ctx.agents_successful());
    }

    #[cfg(feature = "tls13")] // require version which supports TLS 1.3
    #[cfg(feature = "client-authentication-transcript-extraction")]
    #[test]
    fn test_seed_client_attacker_auth() {
        use crate::tls::trace_helper::TraceExecutor;

        let ctx = seed_client_attacker_auth.execute_trace();
        assert!(ctx.agents_successful());
    }

    #[cfg(feature = "tls13")] // require version which supports TLS 1.3
    #[test]
    fn test_seed_client_attacker_full() {
        use crate::tls::trace_helper::TraceExecutor;

        let ctx = seed_client_attacker_full.execute_trace();
        assert!(ctx.agents_successful());
    }

    #[cfg(feature = "tls13")] // require version which supports TLS 1.3
    #[test]
    fn test_seed_server_attacker_full() {
        use crate::tls::trace_helper::TraceExecutor;

        let ctx = seed_server_attacker_full.execute_trace();
        assert!(ctx.agents_successful());
    }

    #[cfg(all(feature = "tls13", feature = "tls13-session-resumption"))]
    #[cfg(not(feature = "wolfssl-disable-postauth"))]
    #[test]
    fn test_seed_session_resumption_dhe() {
        use crate::tls::trace_helper::TraceExecutor;

        let ctx = seed_session_resumption_dhe.execute_trace();
        assert!(ctx.agents_successful());
    }

    #[cfg(all(feature = "tls13", feature = "tls13-session-resumption"))]
    #[cfg(not(feature = "wolfssl-disable-postauth"))]
    #[test]
    fn test_seed_session_resumption_dhe_full() {
        use crate::tls::trace_helper::TraceExecutor;

        let ctx = seed_session_resumption_dhe_full.execute_trace();
        assert!(ctx.agents_successful());
    }

    #[cfg(all(feature = "tls13", feature = "tls13-session-resumption"))]
    #[cfg(not(feature = "wolfssl-disable-postauth"))]
    #[test]
    fn test_seed_session_resumption_ke() {
        use crate::tls::trace_helper::TraceExecutor;

        let ctx = seed_session_resumption_ke.execute_trace();
        assert!(ctx.agents_successful());
    }

    #[cfg(feature = "tls13")] // require version which supports TLS 1.3
    #[test]
    fn test_seed_successful() {
        use crate::tls::trace_helper::TraceExecutor;

        let ctx = seed_successful.execute_trace();
        assert!(ctx.agents_successful());
    }

    #[cfg(feature = "tls13")] // require version which supports TLS 1.3
    #[test]
    fn test_seed_successful_client_auth() {
        use crate::tls::trace_helper::TraceExecutor;

        let ctx = seed_successful_client_auth.execute_trace();
        assert!(ctx.agents_successful());
    }

    #[cfg(feature = "tls13")] // require version which supports TLS 1.3
    #[test]
    // Cases:
    // expected = "Not the best cipher choosen", // in case MITM attack succeeded because transcript is ignored -> We detect the MITM and error
    // expected = "decryption failed or bad record mac"  // in case MITM attack did fail
    #[should_panic]
    fn test_seed_successful_mitm() {
        use crate::tls::trace_helper::TraceExecutor;

        let ctx = seed_successful_mitm.execute_trace();
        assert!(ctx.agents_successful());
    }

    #[cfg(feature = "tls13")] // require version which supports TLS 1.3
    #[test]
    fn test_seed_successful_with_ccs() {
        use crate::tls::trace_helper::TraceExecutor;

        let ctx = seed_successful_with_ccs.execute_trace();
        assert!(ctx.agents_successful());
    }

    // require version which supports TLS 1.3 and session resumption (else no tickets are sent)
    // LibreSSL does not yet support PSK
    #[cfg(all(feature = "tls13", feature = "tls13-session-resumption"))]
    #[test]
    fn test_seed_successful_with_tickets() {
        use crate::tls::trace_helper::TraceExecutor;

        let ctx = seed_successful_with_tickets.execute_trace();
        assert!(ctx.agents_successful());
    }

    #[test]
    #[cfg(feature = "tls12")]
    fn test_seed_successful12() {
        use crate::tls::trace_helper::TraceExecutor;

        #[cfg(feature = "tls12-session-resumption")]
        let ctx = seed_successful12_with_tickets.execute_trace();
        #[cfg(not(feature = "tls12-session-resumption"))]
        let ctx = seed_successful12.execute_trace();
        assert!(ctx.agents_successful());
    }

    #[test]
    fn test_corpus_file_sizes() {
        let client = AgentName::first();
        let _server = client.next();

        for (trace, name) in create_corpus() {
            for step in &trace.steps {
                match &step.action {
                    Action::Input(input) => {
                        // should be below a certain threshold, else we should increase max_term_size in fuzzer setup
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

    #[test]
    fn test_term_sizes() {
        let client = AgentName::first();
        let _server = client.next();

        for (name, trace) in [
            seed_successful_client_auth.build_named_trace(),
            seed_successful.build_named_trace(),
            seed_successful_mitm.build_named_trace(),
            seed_successful12_with_tickets.build_named_trace(),
            seed_successful12.build_named_trace(),
            seed_successful_with_ccs.build_named_trace(),
            seed_successful_with_tickets.build_named_trace(),
            seed_server_attacker_full.build_named_trace(),
            seed_client_attacker_auth.build_named_trace(),
            seed_client_attacker.build_named_trace(),
            seed_client_attacker12.build_named_trace(),
            seed_session_resumption_dhe.build_named_trace(),
            seed_session_resumption_ke.build_named_trace(),
            seed_client_attacker_full.build_named_trace(),
            // _full can be large: seed_session_resumption_dhe_full.build_named_trace(),
        ] {
            for step in &trace.steps {
                match &step.action {
                    Action::Input(input) => {
                        // should be below a certain threshold, else we should increase max_term_size in fuzzer setup
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

    pub mod serialization {
        use puffin::{
            algebra::{set_deserialize_signature, Matcher},
            trace::Trace,
        };
        use test_log::test;

        use crate::tls::{seeds::*, trace_helper::TraceHelper, TLS_SIGNATURE};

        fn test_postcard_serialization<M: Matcher>(trace: Trace<M>) {
            let _ = set_deserialize_signature(&TLS_SIGNATURE);

            let serialized1 = trace.serialize_postcard().unwrap();
            let deserialized_trace =
                Trace::<TlsQueryMatcher>::deserialize_postcard(serialized1.as_ref()).unwrap();
            let serialized2 = deserialized_trace.serialize_postcard().unwrap();

            assert_eq!(serialized1, serialized2);
        }

        fn test_json_serialization<M: Matcher>(trace: Trace<M>) {
            let _ = set_deserialize_signature(&TLS_SIGNATURE);

            let serialized1 = serde_json::to_string_pretty(&trace).unwrap();
            let deserialized_trace =
                serde_json::from_str::<Trace<TlsQueryMatcher>>(serialized1.as_str()).unwrap();
            let serialized2 = serde_json::to_string_pretty(&deserialized_trace).unwrap();

            assert_eq!(serialized1, serialized2);
        }

        #[test]
        fn test_serialisation_seed_seed_session_resumption_dhe_json() {
            let trace = seed_session_resumption_dhe.build_trace();
            test_json_serialization(trace);
        }

        #[test]
        fn test_serialisation_seed_seed_session_resumption_ke_json() {
            let trace = seed_session_resumption_ke.build_trace();
            test_json_serialization(trace);
        }

        #[test]
        fn test_serialisation_seed_client_attacker12_json() {
            let trace = seed_client_attacker12.build_trace();
            test_json_serialization(trace);
        }

        #[test]
        fn test_serialisation_seed_successful_json() {
            let trace = seed_successful.build_trace();
            test_json_serialization(trace);
        }

        #[test]
        fn test_serialisation_seed_successful_postcard() {
            let trace = seed_successful.build_trace();
            test_postcard_serialization(trace);
        }

        #[test]
        fn test_serialisation_seed_successful12_json() {
            let trace = seed_successful12.build_trace();
            test_json_serialization(trace);
        }

        #[test]
        fn test_serialisation_seed_client_attacker_auth_json() {
            let trace = seed_client_attacker_auth.build_trace();
            test_json_serialization(trace);
        }

        #[test]
        fn test_serialisation_seed_client_attacker_auth_postcard() {
            let trace = seed_client_attacker_auth.build_trace();
            test_postcard_serialization(trace);
        }

        #[test]
        fn test_serialisation_seed_server_attacker_full_json() {
            let trace = seed_server_attacker_full.build_trace();
            test_json_serialization(trace);
        }

        #[test]
        fn test_serialisation_seed_server_attacker_full_postcard() {
            let trace = seed_server_attacker_full.build_trace();
            test_postcard_serialization(trace);
        }
    }

    pub mod rustls {
        use std::convert::TryFrom;

        use puffin::codec::Reader;
        use test_log::test;

        use crate::tls::rustls::msgs::{
            base::Payload,
            enums::{ContentType, HandshakeType, ProtocolVersion},
            handshake::{
                ClientHelloPayload, HandshakeMessagePayload, HandshakePayload, Random, SessionID,
            },
            message::{Message, MessagePayload::Handshake, OpaqueMessage, PlainMessage},
        };

        fn create_message(opaque_message: OpaqueMessage) -> Message {
            Message::try_from(opaque_message.into_plain_message()).unwrap()
        }

        #[test]
        fn test_rustls_message_stability_ch() {
            let hello_client_hex = "1603010136010001320303aa1795f64f48fcfcd0121368f88f176fe2570b07\
        68bbc85e9f2c80c557553d7d20e1e15d0028932f4f7479cf256302b7847d81a68e708525f9d38d94fc6ef742a30\
        03e130213031301c02cc030009fcca9cca8ccaac02bc02f009ec024c028006bc023c0270067c00ac0140039c009\
        c0130033009d009c003d003c0035002f00ff010000ab00000012001000000d6d6178616d6d616e6e2e6f7267000\
        b000403000102000a000c000a001d0017001e00190018002300000016000000170000000d0030002e0403050306\
        03080708080809080a080b080408050806040105010601030302030301020103020202040205020602002b00090\
        80304030303020301002d00020101003300260024001d00209b8a24e29770f7ed95bf330e7e3929b21090350a41\
        5ab4cdf01b04e9ffc0fc50";

            let hello_client = hex::decode(hello_client_hex).unwrap();

            let opaque_message =
                OpaqueMessage::read(&mut Reader::init(hello_client.as_slice())).unwrap();
            create_message(opaque_message);
        }

        #[test]
        fn test_heartbleed_ch() {
            // Derived from "openssl s_client -msg -connect localhost:44330" and then pressing R
            let hello_client_hex = "
            16 03 03 00  dc 01 00 00 d8 03 03 53
            43 5b 90 9d 9b 72 0b bc  0c bc 2b 92 a8 48 97 cf
            bd 39 04 cc 16 0a 85 03  90 9f 77 04 33 d4 de 00
            00 66 c0 14 c0 0a c0 22  c0 21 00 39 00 38 00 88
            00 87 c0 0f c0 05 00 35  00 84 c0 12 c0 08 c0 1c
            c0 1b 00 16 00 13 c0 0d  c0 03 00 0a c0 13 c0 09
            c0 1f c0 1e 00 33 00 32  00 9a 00 99 00 45 00 44
            c0 0e c0 04 00 2f 00 96  00 41 c0 11 c0 07 c0 0c
            c0 02 00 05 00 04 00 15  00 12 00 09 00 14 00 11
            00 08 00 06 00 03 00 ff  01 00 00 49 00 0b 00 04
            03 00 01 02 00 0a 00 34  00 32 00 0e 00 0d 00 19
            00 0b 00 0c 00 18 00 09  00 0a 00 16 00 17 00 08
            00 06 00 07 00 14 00 15  00 04 00 05 00 12 00 13
            00 01 00 02 00 03 00 0f  00 10 00 11 00 23 00 00
            00 0f 00 01 01";

            let hello_client =
                hex::decode(hello_client_hex.to_string().replace([' ', '\n'], "")).unwrap();
            //hexdump::hexdump(&hello_client);

            let opaque_message =
                OpaqueMessage::read(&mut Reader::init(hello_client.as_slice())).unwrap();
            create_message(opaque_message);
        }

        #[test]
        fn test_rustls_message_stability_ch_renegotiation() {
            // Derived from "openssl s_client -msg -connect localhost:44330" and then pressing R
            let hello_client_hex = "16030300cc\
        010000c8030368254f1b232142c49512b09ac3929df07b6d461dc15473c064\
        e1ffdfbfd5cc9d000036c02cc030009fcca9cca8ccaac02bc02f009ec024c028006bc023c0270067c00ac014003\
        9c009c0130033009d009c003d003c0035002f01000069ff01000d0cdcf098f907352157bc31b073000b00040300\
        0102000a000c000a001d0017001e00190018002300000016000000170000000d0030002e0403050306030807080\
        80809080a080b080408050806040105010601030302030301020103020202040205020602";

            let hello_client = hex::decode(hello_client_hex).unwrap();
            //hexdump::hexdump(&hello_client);

            let opaque_message =
                OpaqueMessage::read(&mut Reader::init(hello_client.as_slice())).unwrap();
            create_message(opaque_message);
        }

        /// https://github.com/tlspuffin/rustls/commit/d5d26a119f5a0edee43ebcd77f3bbae8bbd1db7d
        #[test]
        fn test_server_hello_parsing() {
            let hex = "160303004a020000460303de257a3941501c11fa7898af1b1b2aea4f5e39e521b35dc84ffab\
        e830e9a98ec20e1cb49645b1cd6e2d0aa5c87b5a3837bcf33334e96c37a77a79c9df63413dc15c02f00";
            let binary = hex::decode(hex).unwrap();
            let opaque_message = OpaqueMessage::read(&mut Reader::init(binary.as_slice())).unwrap();
            create_message(opaque_message);
        }

        #[test]
        fn test_encrypted_tls12_messages() {
            let hexn = vec![
                "1603030028155e38ddd323ca97440b4bb44fe810e9f4d10e5280795ca0660c7d8c8dddcd95355538a3d2cc0256",
                "16030300280d8d288b7a398d5c078280388c71106391756b19d1bb5c95ec18f5de8a0c772062df0d18f24e02b5",
                "16030300280032e43a49aa2134ac20d701f3427aee8cf7c397eb2b9ed88a09bfba4c9fe94a10e6c88be89a7a67",
                "1603030028149ee35e3205a0fea0fd2f14555c7fd0b6acc2bf926a674841375ed061dbf359ac64905c8c616095",
                "1603030028182bdc85dc708633cc973b23173fd1e9a7296c744ce44443c678b2be0d9c0b050b3b26f9cd697ed9",
                "160303002805330e9cee1941f19b744f7ddab94a8caf2afcc8ceb97e4389c4f7c0b329219bcbf4d68c1fc71266",
                "1603030028fe4121bb8fb7467a63b25cc96f2eb3df1ef61fc31431a37db61825a7680d85b9fc04e980055e65db",
            ];

            for hex in hexn {
                let binary = hex::decode(hex).unwrap();
                let opaque_message =
                    OpaqueMessage::read(&mut Reader::init(binary.as_slice())).unwrap();
                create_message(opaque_message);
            }
        }

        #[test]
        fn test_rustls_message_stability_cert() {
            let cert_hex = "16030309b50b0009b1000009ad00053a308205363082041ea00302010202120400ca59\
        61d39c1622093596f2132488f93e300d06092a864886f70d01010b05003032310b3009060355040613025553311\
        63014060355040a130d4c6574277320456e6372797074310b3009060355040313025233301e170d323130333238\
        3031343335385a170d3231303632363031343335385a301c311a3018060355040313117777772e6d6178616d6d6\
        16e6e2e6f726730820122300d06092a864886f70d01010105000382010f003082010a0282010100b8ad1a3825f4\
        aa8f8cdf5221a5d98d29f93be72f470397e07e1ceca379376bf1b148d19feaf6c5d3b01b344369bcc50dd33f967\
        b281eec6edf4e9ee6b1a134589d40b3d3c2b2d51814ecafebcd59da1b01aea221af57f50e523694ac7603bf363b\
        3a5380d48bef06cffbae66123046a7cfb3055f35755b50c71c93aef4c2a0bc8badb56b37d07be0d3319cac9b2f2\
        10a29115b4b6377734b647088adcbc12cc82a59a5f10fe2478ab2937f4ed667fbbdda3c468148f974da14dda787\
        234811457d4a2d99677f27a3eae68f782c1291243e02653a4fe70ca4cb3d3eda66ba47926e25b25045b92ef8c20\
        a89b1b5fce69ac18091f1229d9be473f96f23ed40d43f0203010001a382025a30820256300e0603551d0f0101ff\
        0404030205a0301d0603551d250416301406082b0601050507030106082b06010505070302300c0603551d13010\
        1ff04023000301d0603551d0e0416041412b43a1e54091741afc831d1e4de7babcb110ebe301f0603551d230418\
        30168014142eb317b75856cbae500940e61faf9d8b14c2c6305506082b0601050507010104493047302106082b0\
        60105050730018615687474703a2f2f72332e6f2e6c656e63722e6f7267302206082b0601050507300286166874\
        74703a2f2f72332e692e6c656e63722e6f72672f302b0603551d1104243022820d6d6178616d6d616e6e2e6f726\
        782117777772e6d6178616d6d616e6e2e6f7267304c0603551d20044530433008060667810c0102013037060b2b\
        0601040182df130101013028302606082b06010505070201161a687474703a2f2f6370732e6c657473656e63727\
        970742e6f726730820103060a2b06010401d6790204020481f40481f100ef0076004494652eb0eeceafc44007d8\
        a8fe28c0dae682bed8cb31b53fd33396b5b681a80000017876b7770e000004030047304502201c5b58adfa5df8a\
        bf6077d94b765750a24d32b49b3af2dcf5c65efaf32c949d6022100866e2301bf3633cf54a33124459c9dc69e6f\
        953c9b2200f7c73919cefee849150075007d3ef2f88fff88556824c2c0ca9e5289792bc50e78097f2e6a9768997\
        e22f0d70000017876b7772e00000403004630440220030a54d2296566cab9b5fa3e6505566e5e014d48f15f6cd8\
        727896e2cc352eb302207aff1ae19ca44c14dc0e136583dde241f742f141ec518adf26c5b08d59d92936300d060\
        92a864886f70d01010b050003820101008c770bcf525fc99d9f8f04d279b724bbb2bebc42184e671aa392b05826\
        5b097de2d9f668f64e696d0048a00023ad2c6dfd5cc6f41bde11810d0fbad97822c6863012a4f0e8430a385cfeb\
        699278e99622af1cca45419cb61d59dcbb80464cf65ff07d15c05f69caf2a69970cae8b4533f5a006b9b9414cba\
        a6d8a8ac862c430dadb8149e6c151ff75efe0a69b17658b85dbd95a6eb363e52784b9f11c78bbe906ca303f58bb\
        eab8748e92d31344a6c297dfab4738351602951622cd3730f2b94ba7e68ecc1f678a79f5535f6758be357cf0a8a\
        9efa907c2980b2d281c270b7fb97d8c3e1d3af37089002d09e7524d8d441950da466ee77489d25018e5cfa05fe0\
        000000469308204653082034da0030201020210400175048314a4c8218c84a90c16cddf300d06092a864886f70d\
        01010b0500303f31243022060355040a131b4469676974616c205369676e617475726520547275737420436f2e3\
        11730150603550403130e44535420526f6f74204341205833301e170d3230313030373139323134305a170d3231\
        303932393139323134305a3032310b300906035504061302555331163014060355040a130d4c6574277320456e6\
        372797074310b300906035504031302523330820122300d06092a864886f70d01010105000382010f003082010a\
        0282010100bb021528ccf6a094d30f12ec8d5592c3f882f199a67a4288a75d26aab52bb9c54cb1af8e6bf975c8a\
        3d70f4794145535578c9ea8a23919f5823c42a94e6ef53bc32edb8dc0b05cf35938e7edcf69f05a0b1bbec09424\
        2587fa3771b313e71cace19befdbe43b45524596a9c153ce34c852eeb5aeed8fde6070e2a554abb66d0e97a5403\
        46b2bd3bc66eb66347cfa6b8b8f572999f830175dba726ffb81c5add286583d17c7e709bbf12bf786dcc1da715d\
        d446e3ccad25c188bc60677566b3f118f7a25ce653ff3a88b647a5ff1318ea9809773f9d53f9cf01e5f5a670171\
        4af63a4ff99b3939ddc53a706fe48851da169ae2575bb13cc5203f5ed51a18bdb150203010001a3820168308201\
        6430120603551d130101ff040830060101ff020100300e0603551d0f0101ff040403020186304b06082b0601050\
        5070101043f303d303b06082b06010505073002862f687474703a2f2f617070732e6964656e74727573742e636f\
        6d2f726f6f74732f647374726f6f74636178332e703763301f0603551d23041830168014c4a7b1a47b2c71fadbe\
        14b9075ffc4156085891030540603551d20044d304b3008060667810c010201303f060b2b0601040182df130101\
        013030302e06082b060105050702011622687474703a2f2f6370732e726f6f742d78312e6c657473656e6372797\
        0742e6f7267303c0603551d1f043530333031a02fa02d862b687474703a2f2f63726c2e6964656e74727573742e\
        636f6d2f445354524f4f544341583343524c2e63726c301d0603551d0e04160414142eb317b75856cbae500940e\
        61faf9d8b14c2c6301d0603551d250416301406082b0601050507030106082b06010505070302300d06092a8648\
        86f70d01010b05000382010100d94ce0c9f584883731dbbb13e2b3fc8b6b62126c58b7497e3c02b7a81f2861ebc\
        ee02e73ef49077a35841f1dad68f0d8fe56812f6d7f58a66e3536101c73c3e5bd6d5e01d76e72fb2aa0b8d35764\
        e55bc269d4d0b2f77c4bc3178e887273dcfdfc6dbde3c90b8e613a16587d74362b55803dc763be8443c639a10e6\
        b579e3f29c180f6b2bd47cbaa306cb732e159540b1809175e636cfb96673c1c730c938bc611762486de400707e4\
        7d2d66b525a39658c8ea80eecf693b96fce68dc033f389f8292d14142d7ef06170955df70be5c0fb24faec8ecb6\
        1c8ee637128a82c053b77ef9b5e0364f051d1e485535cb00297d47ec634d2ce1000e4b1df3ac2ea17be0000";

            let cert = hex::decode(cert_hex).unwrap();

            let mut opaque_message =
                OpaqueMessage::read(&mut Reader::init(cert.as_slice())).unwrap();
            // Required for choosing the correct parsing function
            opaque_message.version = ProtocolVersion::TLSv1_3;
            create_message(opaque_message);
        }

        #[test]
        fn test_encrypted_tls12_into_message() {
            let opaque_message = OpaqueMessage {
                typ: ContentType::Handshake,
                version: ProtocolVersion::TLSv1_2,
                payload: Payload::new(vec![1, 2, 3]),
            };

            create_message(opaque_message);
        }

        #[test]
        fn test_rustls_message_stability() {
            let random = [0u8; 32];
            let message = Message {
                version: ProtocolVersion::TLSv1_2,
                payload: Handshake(HandshakeMessagePayload {
                    typ: HandshakeType::ClientHello,
                    payload: HandshakePayload::ClientHello(ClientHelloPayload {
                        client_version: ProtocolVersion::TLSv1_3,
                        random: Random::from(random),
                        session_id: SessionID::empty(),
                        cipher_suites: vec![],
                        compression_methods: vec![],
                        extensions: vec![],
                    }),
                }),
            };

            let mut out: Vec<u8> = Vec::new();
            out.append(
                &mut PlainMessage::from(message)
                    .into_unencrypted_opaque()
                    .encode(),
            );
            //hexdump::hexdump(&out);

            let opaque_message = OpaqueMessage::read(&mut Reader::init(out.as_slice())).unwrap();
            create_message(opaque_message);
        }
    }
}
