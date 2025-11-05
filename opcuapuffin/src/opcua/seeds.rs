//! Implementation of special traces, used to start the fuzzing.
//! Each may represent a special execution of OPC UA, like a full handshake
//! or the execution of a known attack.
#![allow(dead_code)]

use opcua::puffin::messages::EncryptedBody;
//use opcua::puffin::query::OpcuaQueryMatcher;
use opcua::puffin::signature::fn_client_hello;
use opcua::puffin::signature::fn_impl::*;

use opcua::puffin::types::{OpcuaDescriptorConfig, OpcuaProtocolTypes};

use puffin::agent::AgentName;
use puffin::{input_action, term};
use puffin::trace::{Action, InputAction, Step, Trace};

use crate::protocol::OpcuaProtocolBehavior;

pub fn create_corpus(
    _put: &dyn puffin::put_registry::Factory<OpcuaProtocolBehavior>,
) -> Vec<(Trace<OpcuaProtocolTypes>, &'static str)> {
    vec![
        (seed_a_hello_bob(AgentName::first()), "seed_a_hello_bob"),
        (seed_b_client_open_secure_channel(AgentName::first()), "seed_b_client_open_secure_channel"),
        (seed_client_open_unsecure_channel(AgentName::first()), "seed_client_open_unsecure_channel")
    ]
}

pub fn seed_A_hello_bob (
    server: AgentName,
) -> Trace<OpcuaProtocolTypes> {
    Trace {
    prior_traces: vec![],
        descriptors: vec![
            OpcuaDescriptorConfig::new_server(server)
        ],
        steps: vec![
            Step {
                agent: server,
                action: Action::Input(input_action! { term! {
                        fn_client_hello (
                            fn_bob_endpoint,
                            fn_default_size,
                            fn_default_size
                        )
                    }
                }),
            },


        ]
    }
}

pub fn seed_b_client_open_secure_channel (
    server: AgentName,
) -> Trace<OpcuaProtocolTypes> {
    Trace {
        prior_traces: vec![],
        descriptors: vec![
            OpcuaDescriptorConfig::new_server(server)
        ],
        steps: vec![
            Step {
                agent: server,
                action: Action::Input(input_action! { term! {
                        fn_client_hello (
                            fn_bob_endpoint,
                            fn_default_size,
                            fn_default_size
                        )
                    }
                }),
            },
            Step {
                agent: server,
                action: Action::Input(input_action! { term! {
                    fn_open_message (
                        (fn_open_header(
                            (fn_header(fn_open, fn_seq_0)),
                            fn_basic256sha256,
                            fn_mallory_cert,
                            fn_bob_cert,
                            (fn_request(
                                (fn_sequence_header(fn_seq_0, fn_seq_0)),
                                (fn_client_open(
                                    (fn_request_header(fn_sa_token_zero, fn_seq_0)),
                                    fn_issue,
                                    fn_mode_sign,
                                    fn_channel_nonce_1
                                ))
                            ))
                        )),
                        (fn_asym_encrypt(
                            fn_basic256sha256,
                            fn_mallory_cert,
                            fn_bob_cert,
                            (fn_data_to_encrypt(
                                fn_basic256sha256,
                                fn_bob_cert,
                                (fn_request(
                                    (fn_sequence_header(fn_seq_0, fn_seq_0)),
                                    (fn_client_open(
                                        (fn_request_header(fn_sa_token_zero, fn_seq_0)),
                                        fn_issue,
                                        fn_mode_sign,
                                        fn_channel_nonce_1
                                    ))
                                )),
                                (fn_sign(
                                    (fn_data_to_sign(
                                        (fn_open_header(
                                            (fn_header(fn_open, fn_seq_0)),
                                            fn_basic256sha256,
                                            fn_mallory_cert,
                                            fn_bob_cert,
                                            (fn_request(
                                                (fn_sequence_header(fn_seq_0, fn_seq_0)),
                                                (fn_client_open(
                                                    (fn_request_header(fn_sa_token_zero, fn_seq_0)),
                                                    fn_issue,
                                                    fn_mode_sign,
                                                    fn_channel_nonce_1
                                                ))
                                            ))
                                        )),
                                        fn_basic256sha256,
                                        fn_mallory_cert,
                                        fn_bob_cert,
                                        (fn_request(
                                            (fn_sequence_header(fn_seq_0, fn_seq_0)),
                                            (fn_client_open(
                                                (fn_request_header(fn_sa_token_zero, fn_seq_0)),
                                                fn_issue,
                                                fn_mode_sign,
                                                fn_channel_nonce_1
                                            ))
                                        ))
                                    )),
                                    fn_basic256sha256,
                                    fn_mallory_cert,
                                    fn_mallory_sk
                                ))
                           ))
                        ))
                    )
                    }
                }),
            },

            Step {
                agent: server,
                action: Action::Input(input_action! { term! {
                    fn_message (
                        (fn_mac_header(
                            fn_basic256sha256,
                            (fn_header(fn_close, ((server, 1)[None]/u32))),  // needs channel id!
                            (fn_request(
                                (fn_sequence_header(fn_seq_1, fn_seq_1)),
                                (fn_client_close(
                                    (fn_request_header(fn_sa_token_zero, fn_seq_1))
                                ))
                            ))
                        )),
                        (fn_body(
                            (fn_get_channel_token(
                                (fn_asym_decrypt(
                                    ((server, 1)[None]/EncryptedBody),
                                    fn_mallory_sk))
                            )),
                            (fn_sequence_header(fn_seq_1, fn_seq_1)),
                            (fn_client_close(
                                (fn_request_header(fn_sa_token_zero, fn_seq_1))
                            )),
                            (fn_mac(
                                (fn_data_to_mac(
                                    (fn_mac_header(
                                        fn_basic256sha256,
                                        (fn_header(fn_close, ((server, 1)[None]/u32))),  // needs channel id!
                                        (fn_request(
                                            (fn_sequence_header(fn_seq_1, fn_seq_1)),
                                            (fn_client_close(
                                                (fn_request_header(fn_sa_token_zero, fn_seq_1))
                                            ))
                                        ))
                                    )),
                                    (fn_get_channel_token(
                                        (fn_asym_decrypt(
                                            ((server, 1)[None]/EncryptedBody),
                                            fn_mallory_sk))
                                    )),
                                    (fn_request(
                                        (fn_sequence_header(fn_seq_1, fn_seq_1)),
                                        (fn_client_close(
                                            (fn_request_header(fn_sa_token_zero, fn_seq_1))
                                        ))
                                    ))
                                )),
                                fn_basic256sha256,
                                (fn_client_mac_key(
                                    fn_basic256sha256,
                                    fn_channel_nonce_1,
                                    (fn_get_server_nonce(
                                        (fn_asym_decrypt(((server, 1)[None]/EncryptedBody), fn_mallory_sk))
                                    ))
                                ))
                            ))
                        ))
                    )
                    }
                }),
            },

        ]
    }
}

pub fn seed_client_open_unsecure_channel (
    server: AgentName,
) -> Trace<OpcuaProtocolTypes> {
    Trace {
        prior_traces: vec![],
        descriptors: vec![
            OpcuaDescriptorConfig::new_server(server)
        ],
        steps: vec![
            Step {
                agent: server,
                action: Action::Input(input_action! { term! {
                        fn_client_hello (
                            fn_bob_endpoint,
                            fn_default_size,
                            fn_default_size
                        )
                    }
                }),
            },
            Step {
                agent: server,
                action: Action::Input(input_action! { term! {
                    fn_open_message (
                        (fn_open_header(
                            fn_dummy_chunker_header // Fail to deserialize this!!
                            //  fn_security_policy_none
                        )),
                        (fn_no_bytes())
                    )
                    }
                }),
            },
        ]
    }
}