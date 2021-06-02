use rustls::internal::msgs::handshake::{CertificatePayload, ServerKeyExchangePayload};
use rustls::msgs::message::Message;
use rustls::{
    internal::msgs::{
        base::Payload,
        enums::Compression,
        handshake::{ClientExtension, Random, ServerExtension, SessionID},
    },
    CipherSuite, ProtocolVersion,
};

use crate::agent::TLSVersion;
use crate::tls::fn_impl::*;
use crate::trace::AgentDescriptor;
use crate::{
    agent::AgentName,
    term::{Signature, Term},
    trace::{Action, InputAction, OutputAction, Step, Trace, TraceContext},
};
use crate::{app, app1, app_const, var};

pub fn seed_successful(client: AgentName, server: AgentName) -> Trace {
    let mut sig = Signature::default();
    let op_client_hello = sig.new_op(&op_client_hello);
    let op_server_hello = sig.new_op(&op_server_hello);
    let op_change_cipher_spec = sig.new_op(&op_change_cipher_spec);
    let op_application_data = sig.new_op(&op_application_data);

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
                    recipe: Term::Application {
                        op: op_client_hello,
                        args: vec![
                            Term::Variable(sig.new_var::<ProtocolVersion>((0, 0))),
                            Term::Variable(sig.new_var::<Random>((0, 0))),
                            Term::Variable(sig.new_var::<SessionID>((0, 0))),
                            Term::Variable(sig.new_var::<Vec<CipherSuite>>((0, 0))),
                            Term::Variable(sig.new_var::<Vec<Compression>>((0, 0))),
                            Term::Variable(sig.new_var::<Vec<ClientExtension>>((0, 0))),
                        ],
                    },
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
                    recipe: Term::Application {
                        op: op_server_hello,
                        args: vec![
                            Term::Variable(sig.new_var::<ProtocolVersion>((1, 0))),
                            Term::Variable(sig.new_var::<Random>((1, 0))),
                            Term::Variable(sig.new_var::<SessionID>((1, 0))),
                            Term::Variable(sig.new_var::<CipherSuite>((1, 0))),
                            Term::Variable(sig.new_var::<Compression>((1, 0))),
                            Term::Variable(sig.new_var::<Vec<ServerExtension>>((1, 0))),
                        ],
                    },
                }),
            },
            // CCS Server -> Client
            Step {
                agent: client,
                action: Action::Input(InputAction {
                    recipe: Term::Application {
                        op: op_change_cipher_spec.clone(),
                        args: vec![],
                    },
                }),
            },
            // Encrypted Extensions Server -> Client
            Step {
                agent: client,
                action: Action::Input(InputAction {
                    recipe: Term::Application {
                        op: op_application_data.clone(),
                        args: vec![Term::Variable(sig.new_var::<Vec<u8>>((1, 2)))],
                    },
                }),
            },
            // Certificate Server -> Client
            Step {
                agent: client,
                action: Action::Input(InputAction {
                    recipe: Term::Application {
                        op: op_application_data.clone(),
                        args: vec![Term::Variable(sig.new_var::<Vec<u8>>((1, 3)))],
                    },
                }),
            },
            // Certificate Verify Server -> Client
            Step {
                agent: client,
                action: Action::Input(InputAction {
                    recipe: Term::Application {
                        op: op_application_data.clone(),
                        args: vec![Term::Variable(sig.new_var::<Vec<u8>>((1, 4)))],
                    },
                }),
            },
            // Finish Server -> Client
            Step {
                agent: client,
                action: Action::Input(InputAction {
                    recipe: Term::Application {
                        op: op_application_data.clone(),
                        args: vec![Term::Variable(sig.new_var::<Vec<u8>>((1, 5)))],
                    },
                }),
            },
            Step {
                agent: client,
                action: Action::Output(OutputAction { id: 2 }),
            },
            Step {
                agent: server,
                action: Action::Input(InputAction {
                    recipe: Term::Application {
                        op: op_change_cipher_spec.clone(),
                        args: vec![],
                    },
                }),
            },
            // Finished Client -> Server
            Step {
                agent: server,
                action: Action::Input(InputAction {
                    recipe: Term::Application {
                        op: op_application_data.clone(),
                        args: vec![Term::Variable(sig.new_var::<Vec<u8>>((2, 1)))],
                    },
                }),
            },
            Step {
                agent: server,
                action: Action::Output(OutputAction { id: 3 }),
            },
            Step {
                agent: client,
                action: Action::Input(InputAction {
                    recipe: Term::Application {
                        op: op_application_data.clone(),
                        args: vec![Term::Variable(sig.new_var::<Vec<u8>>((3, 0)))],
                    },
                }),
            },
            Step {
                agent: client,
                action: Action::Input(InputAction {
                    recipe: Term::Application {
                        op: op_application_data.clone(),
                        args: vec![Term::Variable(sig.new_var::<Vec<u8>>((3, 1)))],
                    },
                }),
            },
        ],
    }
}

pub fn seed_successful12(client: AgentName, server: AgentName) -> Trace {
    let mut sig = Signature::default();
    let op_client_hello = sig.new_op(&op_client_hello);
    let op_server_hello = sig.new_op(&op_server_hello);
    let op_server_certificate = sig.new_op(&op_server_certificate);
    let op_server_key_exchange = sig.new_op(&op_server_key_exchange);
    let op_server_hello_done = sig.new_op(&op_server_hello_done);
    let op_client_key_exchange = sig.new_op(&op_client_key_exchange);
    let op_change_cipher_spec12 = sig.new_op(&op_change_cipher_spec12);
    let op_handshake_finished12 = sig.new_op(&op_opaque_handshake_message);

    Trace {
        steps: vec![
            Step {
                agent: client,
                action: Action::Output(OutputAction { id: 0 }),
            },
            // Client Hello, Client -> Server
            Step {
                agent: server,
                action: Action::Input(InputAction {
                    recipe: Term::Application {
                        op: op_client_hello.clone(),
                        args: vec![
                            Term::Variable(sig.new_var::<ProtocolVersion>((0, 0))),
                            Term::Variable(sig.new_var::<Random>((0, 0))),
                            Term::Variable(sig.new_var::<SessionID>((0, 0))),
                            Term::Variable(sig.new_var::<Vec<CipherSuite>>((0, 0))),
                            Term::Variable(sig.new_var::<Vec<Compression>>((0, 0))),
                            Term::Variable(sig.new_var::<Vec<ClientExtension>>((0, 0))),
                        ],
                    },
                }),
            },
            Step {
                agent: server,
                action: Action::Output(OutputAction { id: 1 }),
            },
            // Server Hello, Server -> Client
            Step {
                agent: client,
                action: Action::Input(InputAction {
                    recipe: Term::Application {
                        op: op_server_hello,
                        args: vec![
                            Term::Variable(sig.new_var::<ProtocolVersion>((1, 0))),
                            Term::Variable(sig.new_var::<Random>((1, 0))),
                            Term::Variable(sig.new_var::<SessionID>((1, 0))),
                            Term::Variable(sig.new_var::<CipherSuite>((1, 0))),
                            Term::Variable(sig.new_var::<Compression>((1, 0))),
                            Term::Variable(sig.new_var::<Vec<ServerExtension>>((1, 0))),
                        ],
                    },
                }),
            },
            // Server Certificate, Server -> Client
            Step {
                agent: client,
                action: Action::Input(InputAction {
                    recipe: Term::Application {
                        op: op_server_certificate.clone(),
                        args: vec![Term::Variable(sig.new_var::<CertificatePayload>((1, 1)))],
                    },
                }),
            },
            // Server Key Exchange, Server -> Client
            Step {
                agent: client,
                action: Action::Input(InputAction {
                    recipe: Term::Application {
                        op: op_server_key_exchange.clone(),
                        args: vec![Term::Variable(sig.new_var::<Vec<u8>>((1, 2)))],
                    },
                }),
            },
            // Server Hello Done, Server -> Client
            Step {
                agent: client,
                action: Action::Input(InputAction {
                    recipe: Term::Application {
                        op: op_server_hello_done.clone(),
                        args: vec![],
                    },
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
                    recipe: Term::Application {
                        op: op_client_key_exchange.clone(),
                        args: vec![Term::Variable(sig.new_var::<Vec<u8>>((2, 0)))],
                    },
                }),
            },
            // Client Change Cipher Spec, Client -> Server
            Step {
                agent: server,
                action: Action::Input(InputAction {
                    recipe: Term::Application {
                        op: op_change_cipher_spec12.clone(),
                        args: vec![],
                    },
                }),
            },
            // Client Handshake Finished, Client -> Server
            Step {
                agent: server,
                action: Action::Input(InputAction {
                    recipe: Term::Application {
                        op: op_handshake_finished12.clone(),
                        args: vec![Term::Variable(sig.new_var::<Vec<u8>>((2, 2)))],
                    },
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
                    recipe: Term::Application {
                        op: op_change_cipher_spec12.clone(),
                        args: vec![],
                    },
                }),
            },
            // Server Handshake Finished, Server -> Client
            Step {
                agent: client,
                action: Action::Input(InputAction {
                    recipe: Term::Application {
                        op: op_handshake_finished12.clone(),
                        args: vec![Term::Variable(sig.new_var::<Vec<u8>>((3, 1)))],
                    },
                }),
            },
        ],
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
    }
}

pub fn seed_client_attacker(client: AgentName, server: AgentName) -> Trace {
    let mut s = Signature::default();

    let client_hello = app!(
        s,
        op_client_hello,
        app_const!(s, op_protocol_version12),
        app_const!(s, op_random),
        app_const!(s, op_session_id),
        // force TLS13_AES_128_GCM_SHA256
        app_const!(s, op_cipher_suites),
        app_const!(s, op_compressions),
        app!(
            s,
            op_extensions_append,
            app!(
                s,
                op_extensions_append,
                app!(
                    s,
                    op_extensions_append,
                    app!(
                        s,
                        op_extensions_append,
                        app_const!(s, op_extensions_new),
                        app_const!(s, op_x25519_support_group_extension),
                    ),
                    app_const!(s, op_signature_algorithm_extension)
                ),
                app_const!(s, op_key_share_extension)
            ),
            app_const!(s, op_supported_versions_extension)
        ),
    );

    let server_hello_transcript = app!(
        s,
        op_append_transcript,
        app!(
            s,
            op_append_transcript,
            app_const!(s, op_new_transcript),
            client_hello.clone(), // ClientHello
        ),
        var!(s, Message, (0, 0)), // plaintext ServerHello
    );

    let encrypted_extensions = app!(
        s,
        op_decrypt,
        var!(s, Message, (0, 2)), // Encrypted Extensions
        var!(s, Vec<ServerExtension>, (0, 0)),
        server_hello_transcript.clone(),
        app_const!(s, op_seq_0), // sequence 0
    );

    let encrypted_extension_transcript = app!(
        s,
        op_append_transcript,
        server_hello_transcript.clone(),
        encrypted_extensions.clone() // plaintext Encrypted Extensions
    );
    let server_certificate = app!(
        s,
        op_decrypt,
        var!(s, Message, (0, 3)), // Server Certificate
        var!(s, Vec<ServerExtension>, (0, 0)),
        server_hello_transcript.clone(),
        app_const!(s, op_seq_1), // sequence 1
    );

    let server_certificate_transcript = app!(
        s,
        op_append_transcript,
        encrypted_extension_transcript.clone(),
        server_certificate.clone() // plaintext Server Certificate
    );

    let server_certificate_verify = app!(
        s,
        op_decrypt,
        var!(s, Message, (0, 4)), // Server Certificate Verify
        var!(s, Vec<ServerExtension>, (0, 0)),
        server_hello_transcript.clone(),
        app_const!(s, op_seq_2) // sequence 2
    );

    let server_certificate_verify_transcript = app!(
        s,
        op_append_transcript,
        server_certificate_transcript.clone(),
        server_certificate_verify.clone() // plaintext Server Certificate Verify
    );

    let server_finished = app!(
        s,
        op_decrypt,
        var!(s, Message, (0, 5)), // Server Handshake Finished
        var!(s, Vec<ServerExtension>, (0, 0)),
        server_hello_transcript.clone(),
        app_const!(s, op_seq_3) // sequence 3
    );

    let server_finished_transcript = app!(
        s,
        op_append_transcript,
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
                        s,
                        op_encrypt,
                        app!(
                            s,
                            op_finished,
                            app!(
                                s,
                                op_verify_data,
                                var!(s, Vec<ServerExtension>, (0, 0)),
                                server_finished_transcript.clone(),
                                server_hello_transcript.clone()
                            )
                        ),
                        var!(s, Vec<ServerExtension>, (0, 0)),
                        server_hello_transcript.clone(),
                        app_const!(s, op_seq_0) // sequence 0
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

pub fn seed_client_attacker12(client: AgentName, server: AgentName) -> (Trace, Term) {
    let mut s = Signature::default();

    let client_hello = app!(
        s,
        op_client_hello,
        app_const!(s, op_protocol_version12),
        app_const!(s, op_random),
        app_const!(s, op_session_id),
        // force TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        app_const!(s, op_cipher_suites12),
        app_const!(s, op_compressions),
        // todo CertificateStatusRequest Extension
        app!(
            s,
            op_extensions_append,
            app!(
                s,
                op_extensions_append,
                app!(
                    s,
                    op_extensions_append,
                    app!(
                        s,
                        op_extensions_append,
                        app!(
                            s,
                            op_extensions_append,
                            app!(
                                s,
                                op_extensions_append,
                                app_const!(s, op_extensions_new),
                                app_const!(s, op_x25519_support_group_extension),
                            ),
                            app_const!(s, op_signature_algorithm_extension)
                        ),
                        app_const!(s, op_ec_point_formats)
                    ),
                    app_const!(s, op_signature_algorithm_cert_extension)
                ),
                app_const!(s, op_signed_certificate_timestamp)
            ),
            // Enable Renegotiation
            app!(s, op_renegotiation_info, app_const!(s, op_empty_bytes_vec)),
        )
    );

    let server_hello_transcript = app!(
        s,
        op_append_transcript,
        app!(
            s,
            op_append_transcript,
            app_const!(s, op_new_transcript12),
            client_hello.clone(), // ClientHello
        ),
        var!(s, Message, (0, 0)), // plaintext ServerHello
    );

    let certificate_transcript = app!(
        s,
        op_append_transcript,
        server_hello_transcript.clone(),
        var!(s, Message, (0, 1)), // Certificate
    );

    let server_key_exchange_transcript = app!(
        s,
        op_append_transcript,
        certificate_transcript.clone(),
        var!(s, Message, (0, 2)), // ServerKeyExchange
    );

    let server_hello_done_transcript = app!(
        s,
        op_append_transcript,
        server_key_exchange_transcript.clone(),
        var!(s, Message, (0, 3)), // ServerHelloDone
    );

    let client_key_exchange = app!(
        s,
        op_client_key_exchange,
        app!(
            s,
            op_new_pubkey12,
            app!(s, op_decode_ecdh_params, var!(s, Vec<u8>, (0, 2)))
        )
    );

    let client_key_exchange_transcript = app!(
        s,
        op_append_transcript,
        server_hello_done_transcript.clone(),
        client_key_exchange.clone()
    );

    let client_verify_data = app!(
        s,
        op_sign_transcript,
        var!(s, Random, (0, 0)),
        app!(s, op_decode_ecdh_params, var!(s, Vec<u8>, (0, 2))), // ServerECDHParams
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
                    recipe: app_const!(s, op_change_cipher_spec12),
                }),
            },
            Step {
                agent: server,
                action: Action::Input(InputAction {
                    recipe: app!(
                        s,
                        op_encrypt12,
                        app1!(s, op_finished12(client_verify_data.clone(),)),
                        var!(s, Random, (0, 0)),
                        app!(s, op_decode_ecdh_params, var!(s, Vec<u8>, (0, 2))), // ServerECDHParams
                        app_const!(s, op_seq_0)
                    ),
                }),
            },
            Step {
                agent: server,
                action: Action::Output(OutputAction { id: 1 }),
            },
        ],
    };

    (trace, client_verify_data)
}

// todo https://gitlab.inria.fr/mammann/tlspuffin/-/issues/40
// todo it seems this needs to be encrypted? somehow the server is not processing this data
pub fn seed_cve_2021_3449(client: AgentName, server: AgentName) -> Trace {
    let mut s = Signature::default();

    let (mut trace, client_verify_data) = seed_client_attacker12(client, server);

    let renegotiation_client_hello = app!(
        s,
        op_client_hello,
        app_const!(s, op_protocol_version12),
        app_const!(s, op_random),
        app_const!(s, op_session_id),
        // force TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        app_const!(s, op_cipher_suites12),
        app_const!(s, op_compressions),
        app!(
            s,
            op_attack_cve_2021_3449,
            app!(
                s,
                op_extensions_append,
                app!(
                    s,
                    op_extensions_append,
                    app!(
                        s,
                        op_extensions_append,
                        app!(
                            s,
                            op_extensions_append,
                            app!(
                                s,
                                op_extensions_append,
                                app_const!(s, op_extensions_new),
                                app_const!(s, op_x25519_support_group_extension),
                            ),
                            app_const!(s, op_signature_algorithm_extension)
                        ),
                        app_const!(s, op_ec_point_formats)
                    ),
                    app_const!(s, op_signature_algorithm_cert_extension)
                ),
                // Enable Renegotiation
                app!(s, op_renegotiation_info, client_verify_data),
            )
        )
    );

    /*    trace.steps.push(Step {
            agent: server,
            action: Action::Input(InputAction {
                recipe: app!(
                    s,
                    op_encrypt12,
                    app_const!(s, op_alert_close_notify),
                    var!(s, Random, (0, 0)),
                    app!(s, op_decode_ecdh_params, var!(s, Vec<u8>, (0, 2))), // ServerECDHParams
                    app_const!(s, op_seq_1)
                ),
            }),
        });
    */
    trace.steps.push(Step {
        agent: server,
        action: Action::Input(InputAction {
            recipe: app!(
                s,
                op_encrypt12,
                renegotiation_client_hello.clone(),
                var!(s, Random, (0, 0)),
                app!(s, op_decode_ecdh_params, var!(s, Vec<u8>, (0, 2))), // ServerECDHParams
                app_const!(s, op_seq_1)
            ),
        }),
    });

    trace.steps.push(Step {
        agent: server,
        action: Action::Output(OutputAction { id: 10 }),
    });

    trace
}
