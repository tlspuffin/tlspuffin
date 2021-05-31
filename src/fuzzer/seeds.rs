use rustls::{
    CipherSuite,
    internal::msgs::{
        base::Payload,
        enums::Compression,
        handshake::{ClientExtension, Random, ServerExtension, SessionID},
    }, ProtocolVersion,
};
use rustls::internal::msgs::handshake::{
    CertificatePayload, ECDHEServerKeyExchange, ServerKeyExchangePayload,
};

use crate::{
    agent::AgentName,
    term::{
        op_impl::{op_application_data, op_change_cipher_spec, op_client_hello, op_server_hello},
        Signature, Term,
    },
    trace::{Action, InputAction, OutputAction, Step, Trace, TraceContext},
};
use crate::term::op_impl::{
    op_attack_cve_2021_3449, op_change_cipher_spec12, op_client_key_exchange,
    op_handshake_finished12, op_server_certificate, op_server_hello_done, op_server_key_exchange,
};
use crate::trace::AgentDescriptor;

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
                server: false,
            },
            AgentDescriptor {
                name: server,
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
                        args: vec![Term::Variable(sig.new_var::<Payload>((1, 2)))],
                    },
                }),
            },
            // Certificate Server -> Client
            Step {
                agent: client,
                action: Action::Input(InputAction {
                    recipe: Term::Application {
                        op: op_application_data.clone(),
                        args: vec![Term::Variable(sig.new_var::<Payload>((1, 3)))],
                    },
                }),
            },
            // Certificate Verify Server -> Client
            Step {
                agent: client,
                action: Action::Input(InputAction {
                    recipe: Term::Application {
                        op: op_application_data.clone(),
                        args: vec![Term::Variable(sig.new_var::<Payload>((1, 4)))],
                    },
                }),
            },
            // Finish Server -> Client
            Step {
                agent: client,
                action: Action::Input(InputAction {
                    recipe: Term::Application {
                        op: op_application_data.clone(),
                        args: vec![Term::Variable(sig.new_var::<Payload>((1, 5)))],
                    },
                }),
            },
            Step {
                agent: client,
                action: Action::Output(OutputAction { id: 2 }),
            },
            /*
            // CCS Client -> Server
            Step {
                agent: server_openssl,
                action: Action::Input(InputAction {
                    recipe: Term::Application {
                        op: op_change_cipher_spec.clone(),
                        args: vec![],
                    },
                }),
            },*/
            // todo missing:
            //      CCS Client -> Server
            // Finished Client -> Server
            Step {
                agent: server,
                action: Action::Input(InputAction {
                    recipe: Term::Application {
                        op: op_application_data.clone(),
                        args: vec![Term::Variable(sig.new_var::<Payload>((2, 0)))],
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
                        args: vec![Term::Variable(sig.new_var::<Payload>((3, 0)))],
                    },
                }),
            },
            Step {
                agent: client,
                action: Action::Input(InputAction {
                    recipe: Term::Application {
                        op: op_application_data.clone(),
                        args: vec![Term::Variable(sig.new_var::<Payload>((3, 1)))],
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
    let op_handshake_finished12 = sig.new_op(&op_handshake_finished12);

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
                        args: vec![
                            Term::Variable(sig.new_var::<ServerKeyExchangePayload>((1, 2))),
                            //Term::Variable(sig.new_var::<ECDHEServerKeyExchange>((1, 2))),
                        ],
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
                        args: vec![Term::Variable(sig.new_var::<Payload>((2, 0)))],
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
                        args: vec![Term::Variable(sig.new_var::<Payload>((2, 2)))],
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
                        args: vec![Term::Variable(sig.new_var::<Payload>((3, 1)))],
                    },
                }),
            },
        ],
        descriptors: vec![
            AgentDescriptor {
                name: client,
                server: false,
            },
            AgentDescriptor {
                name: server,
                server: true,
            },
        ],
    }
}

// todo https://gitlab.inria.fr/mammann/tlspuffin/-/issues/40
// todo it seems this needs to be encrypted? somehow the server is not processing this data
pub fn seed_cve_2021_3449(client: AgentName, server: AgentName) -> Trace {
    let mut sig = Signature::default();
    let op_client_hello = sig.new_op(&op_client_hello);
    let op_attack_cve_2021_3449 = sig.new_op(&op_attack_cve_2021_3449);

    let mut trace = seed_successful12(client, server);

    trace.steps.push(
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
                        Term::Application {
                            op: op_attack_cve_2021_3449,
                            args: vec![Term::Variable(
                                sig.new_var::<Vec<ClientExtension>>((0, 0)),
                            )],
                        },
                    ],
                },
            }),
        }
    );

    trace.steps.push(
        Step {
            agent: server,
            action: Action::Output(OutputAction { id: 4 }),
        },
    );

    trace
}
