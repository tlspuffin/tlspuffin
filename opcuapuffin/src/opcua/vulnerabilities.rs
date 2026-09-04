//! Implementation of special traces, used to start the fuzzing.
//! Each may represent a special execution of OPC UA, like a full handshake
//! or the execution of a known attack.
#![allow(dead_code)]

use opcua::puffin::messages::EncryptedBody;
use opcua::puffin::query::OpcuaQueryMatcher;
use opcua::puffin::signature::fn_client_hello;
use opcua::puffin::signature::fn_impl::*;
use opcua::puffin::types::{ApplicationConfig, OpcuaProtocolTypes};
use opcua::types::{ByteString, NodeId, UAString};
use puffin::agent::AgentName;
use puffin::trace::{Action, InputAction, Step, Trace};
use puffin::{input_action, term};

pub fn seed_bug_dead_session(server: AgentName) -> Trace<OpcuaProtocolTypes> {
    let open_request = term! {
        fn_service(
            (fn_sequence_header(fn_seq_0, fn_seq_0)),
            (fn_client_open(
                (fn_request_header(fn_sa_token_zero, fn_seq_0)),
                fn_issue,
                fn_mode_sign,
                fn_channel_nonce_1
            ))
        )
    };
    let create_request = term! {
        fn_create_request(
            (fn_request_header(fn_sa_token_zero, fn_seq_1)),
            fn_bob_endpoint,
            fn_session_nonce_1,
            fn_mallory_cert
        )
    };
    let hmac_key = term! {
        fn_client_mac_key(
            fn_basic256sha256,
            fn_channel_nonce_1,
            (fn_get_server_nonce(
                (fn_decrypted_body(
                    (fn_asym_decrypt(
                        fn_basic256sha256,
                        ((server, 1)[None]/EncryptedBody),
                        fn_mallory_sk)),
                    fn_mallory_sk
                ))
            ))
        )
    };
    let activate_certificate = term! {
        fn_activate_request(
            (fn_request_header(
                ((server, 3)[Some(OpcuaQueryMatcher::CreateSessionResponse)]/NodeId), // SA_Token!
                fn_seq_2
            )),
            fn_basic256sha256,
            (fn_sign(
                (fn_signature_data(
                    fn_bob_cert,
                    ((server, 0)[Some(OpcuaQueryMatcher::CreateSessionResponse)]/ByteString) // S_nonce!
                )),
                fn_basic256sha256,
                fn_mallory_cert,
                fn_mallory_sk
            )),
            (fn_user_cert(
              ((server, 0)[Some(OpcuaQueryMatcher::PolicyIdCertificate)]/UAString), // PolicyId!
              fn_mallory_cert
            )),
            (fn_sign(
                (fn_signature_data(
                    fn_bob_cert,
                    ((server, 0)[Some(OpcuaQueryMatcher::CreateSessionResponse)]/ByteString) // S_nonce!
                )),
                fn_basic256sha256,
                fn_mallory_cert,
                fn_mallory_sk
            ))
        )
    };
    let simple_request = term! {
        fn_read_current_time(
            (fn_request_header(
                ((server, 3)[Some(OpcuaQueryMatcher::CreateSessionResponse)]/NodeId), // SA_Token!
                fn_seq_3
            ))
        )
    };
    let close_session = term! {
        fn_close_request(
            (fn_request_header(
                ((server, 3)[Some(OpcuaQueryMatcher::CreateSessionResponse)]/NodeId), // SA_Token!
                fn_seq_4))
        )
    };
    Trace {
        prior_traces: vec![],
        metadata_trace: Default::default(),
        descriptors: vec![ApplicationConfig::new_server(server)],
        steps: vec![
            Step {
                agent: server,
                action: Action::Input(input_action! { term! {
                    fn_client_hello (
                        fn_tcp_1,
                        fn_bob_endpoint,
                        fn_default_size,
                        fn_default_size
                    )}
                }),
            },
            Step {
                agent: server,
                action: Action::Input(input_action! { term! {
                    fn_open_message (
                        fn_tcp_1,
                        (fn_open_header(
                            (fn_header(fn_open, fn_seq_0)),
                            fn_basic256sha256,
                            fn_mallory_cert,
                            fn_bob_cert,
                            (@open_request)
                        )),
                        (fn_asym_header(
                            fn_basic256sha256,
                            fn_mallory_cert,
                            fn_bob_cert
                        )),
                        (fn_asym_encrypt(
                            fn_basic256sha256,
                            fn_bob_cert,
                            (fn_data_to_encrypt(
                                fn_basic256sha256,
                                fn_bob_cert,
                                (@open_request),
                                (fn_sign(
                                    (fn_data_to_sign(
                                        (fn_open_header(
                                            (fn_header(fn_open, fn_seq_0)),
                                            fn_basic256sha256,
                                            fn_mallory_cert,
                                            fn_bob_cert,
                                            (@open_request)
                                        )),
                                        fn_basic256sha256,
                                        fn_mallory_cert,
                                        fn_bob_cert,
                                        (@open_request)
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
                        fn_tcp_1,
                        (fn_msg_header(
                            fn_basic256sha256,
                            (fn_header(fn_final,
                                ((server, 1)[Some(OpcuaQueryMatcher::OpenSecureChannelResponse)]/u32))),
                            (fn_service_size((@create_request)))
                        )),
                        (fn_body(
                            (fn_get_channel_token(
                                (fn_decrypted_body(
                                    (fn_asym_decrypt(
                                        fn_basic256sha256,
                                        ((server, 1)[None]/EncryptedBody),
                                        fn_mallory_sk)),
                                    fn_mallory_sk
                                ))
                            )),
                            (fn_sequence_header(fn_seq_1, fn_seq_1)),
                            (@create_request),
                            (fn_mac(
                                (fn_data_to_mac(
                                    (fn_msg_header(
                                        fn_basic256sha256,
                                        (fn_header(fn_final,
                                            ((server, 1)[Some(OpcuaQueryMatcher::OpenSecureChannelResponse)]/u32))),
                                        (fn_service_size((@create_request)))
                                    )),
                                    (fn_get_channel_token(
                                        (fn_decrypted_body(
                                            (fn_asym_decrypt(
                                                fn_basic256sha256,
                                                ((server, 1)[None]/EncryptedBody),
                                                fn_mallory_sk)),
                                            fn_mallory_sk
                                        ))
                                    )),
                                    (fn_service(
                                        (fn_sequence_header(fn_seq_1, fn_seq_1)),
                                        (@create_request)
                                    ))
                                )),
                                fn_basic256sha256,
                                (@hmac_key)
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
                        fn_tcp_1,
                        (fn_msg_header(
                            fn_basic256sha256,
                            (fn_header(fn_final,
                                ((server, 1)[Some(OpcuaQueryMatcher::OpenSecureChannelResponse)]/u32))),
                            (fn_service_size((@activate_certificate)))
                        )),
                        (fn_body(
                            (fn_get_channel_token(
                                (fn_decrypted_body(
                                    (fn_asym_decrypt(
                                        fn_basic256sha256,
                                        ((server, 1)[None]/EncryptedBody),
                                        fn_mallory_sk)),
                                    fn_mallory_sk
                                ))
                            )),
                            (fn_sequence_header(fn_seq_2, fn_seq_2)),
                            (@activate_certificate),
                            (fn_mac(
                                (fn_data_to_mac(
                                    (fn_msg_header(
                                        fn_basic256sha256,
                                        (fn_header(fn_final,
                                            ((server, 1)[Some(OpcuaQueryMatcher::OpenSecureChannelResponse)]/u32))),
                                        (fn_service_size((@activate_certificate)))
                                    )),
                                    (fn_get_channel_token(
                                        (fn_decrypted_body(
                                            (fn_asym_decrypt(
                                                fn_basic256sha256,
                                                ((server, 1)[None]/EncryptedBody),
                                                fn_mallory_sk)),
                                            fn_mallory_sk
                                        ))
                                    )),
                                    (fn_service(
                                        (fn_sequence_header(fn_seq_2, fn_seq_2)),
                                        (@activate_certificate)
                                    ))
                                )),
                                fn_basic256sha256,
                                (@hmac_key)
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
                        fn_tcp_1,
                        (fn_msg_header(
                            fn_basic256sha256,
                            (fn_header(fn_final,
                                ((server, 1)[Some(OpcuaQueryMatcher::OpenSecureChannelResponse)]/u32))),
                            (fn_service_size((@simple_request)))
                        )),
                        (fn_body(
                            (fn_get_channel_token(
                                (fn_decrypted_body(
                                    (fn_asym_decrypt(
                                        fn_basic256sha256,
                                        ((server, 1)[None]/EncryptedBody),
                                        fn_mallory_sk)),
                                    fn_mallory_sk
                                ))
                            )),
                            (fn_sequence_header(fn_seq_3, fn_seq_3)),
                            (@simple_request),
                            (fn_mac(
                                (fn_data_to_mac(
                                    (fn_msg_header(
                                        fn_basic256sha256,
                                        (fn_header(fn_final,
                                            ((server, 1)[Some(OpcuaQueryMatcher::OpenSecureChannelResponse)]/u32))),
                                        (fn_service_size((@simple_request)))
                                    )),
                                    (fn_get_channel_token(
                                        (fn_decrypted_body(
                                            (fn_asym_decrypt(
                                                fn_basic256sha256,
                                                ((server, 1)[None]/EncryptedBody),
                                                fn_mallory_sk)),
                                            fn_mallory_sk
                                        ))
                                    )),
                                    (fn_service(
                                        (fn_sequence_header(fn_seq_3, fn_seq_3)),
                                        (@simple_request)
                                    ))
                                )),
                                fn_basic256sha256,
                                (@hmac_key)
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
                        fn_tcp_1,
                        (fn_msg_header(
                            fn_basic256sha256,
                            (fn_header(fn_final,
                                ((server, 1)[Some(OpcuaQueryMatcher::OpenSecureChannelResponse)]/u32))),
                            (fn_service_size((@close_session)))
                        )),
                        (fn_body(
                            (fn_get_channel_token(
                                (fn_decrypted_body(
                                    (fn_asym_decrypt(
                                        fn_basic256sha256,
                                        ((server, 1)[None]/EncryptedBody),
                                        fn_mallory_sk)),
                                    fn_mallory_sk
                                ))
                            )),
                            (fn_sequence_header(fn_seq_4, fn_seq_4)),
                            (@close_session),
                            (fn_mac(
                                (fn_data_to_mac(
                                    (fn_msg_header(
                                        fn_basic256sha256,
                                        (fn_header(fn_final,
                                            ((server, 1)[Some(OpcuaQueryMatcher::OpenSecureChannelResponse)]/u32))),
                                        (fn_service_size((@close_session)))
                                    )),
                                    (fn_get_channel_token(
                                        (fn_decrypted_body(
                                            (fn_asym_decrypt(
                                                fn_basic256sha256,
                                                ((server, 1)[None]/EncryptedBody),
                                                fn_mallory_sk)),
                                            fn_mallory_sk
                                        ))
                                    )),
                                    (fn_service(
                                        (fn_sequence_header(fn_seq_4, fn_seq_4)),
                                        (@close_session)
                                    ))
                                )),
                                fn_basic256sha256,
                                (@hmac_key)
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
                        fn_tcp_1,
                        (fn_msg_header(
                            fn_basic256sha256,
                            (fn_header(fn_final,
                                ((server, 1)[Some(OpcuaQueryMatcher::OpenSecureChannelResponse)]/u32))),
                            (fn_service_size((@activate_certificate)))
                        )),
                        (fn_body(
                            (fn_get_channel_token(
                                (fn_decrypted_body(
                                    (fn_asym_decrypt(
                                        fn_basic256sha256,
                                        ((server, 1)[None]/EncryptedBody),
                                        fn_mallory_sk)),
                                    fn_mallory_sk
                                ))
                            )),
                            (fn_sequence_header(fn_seq_5, fn_seq_5)),
                            (@activate_certificate),
                            (fn_mac(
                                (fn_data_to_mac(
                                    (fn_msg_header(
                                        fn_basic256sha256,
                                        (fn_header(fn_final,
                                            ((server, 1)[Some(OpcuaQueryMatcher::OpenSecureChannelResponse)]/u32))),
                                        (fn_service_size((@activate_certificate)))
                                    )),
                                    (fn_get_channel_token(
                                        (fn_decrypted_body(
                                            (fn_asym_decrypt(
                                                fn_basic256sha256,
                                                ((server, 1)[None]/EncryptedBody),
                                                fn_mallory_sk)),
                                            fn_mallory_sk
                                        ))
                                    )),
                                    (fn_service(
                                        (fn_sequence_header(fn_seq_2, fn_seq_2)), // <- Here is the mutation to do.
                                        (@activate_certificate)
                                    ))
                                )),
                                fn_basic256sha256,
                                (@hmac_key)
                            ))
                        ))
                    )
                    }
                }),
            },
        ],
    }
}

pub fn seed_bad_switch(server: AgentName) -> Trace<OpcuaProtocolTypes> {
    let open_request_1 = term! {
        fn_service(
            (fn_sequence_header(fn_seq_0, fn_seq_0)),
            (fn_client_open(
                (fn_request_header(fn_sa_token_zero, fn_seq_0)),
                fn_issue,
                fn_mode_sign,
                fn_channel_nonce_1
            ))
        )
    };
    let create_request = term! {
        fn_create_request(
            (fn_request_header(fn_sa_token_zero, fn_seq_1)),
            fn_bob_endpoint,
            fn_session_nonce_1,
            fn_mallory_cert
        )
    };
    let hmac_key_1 = term! {
        fn_client_mac_key(
            fn_basic256sha256,
            fn_channel_nonce_1,
            (fn_get_server_nonce(
                (fn_decrypted_body(
                    (fn_asym_decrypt(
                        fn_basic256sha256,
                        ((server, 1)[None]/EncryptedBody),
                        fn_mallory_sk)),
                    fn_mallory_sk
                ))
            ))
        )
    };
    let activate_certificate = term! {
        fn_activate_request(
            (fn_request_header(
                ((server, 3)[Some(OpcuaQueryMatcher::CreateSessionResponse)]/NodeId), // SA_Token!
                fn_seq_2
            )),
            fn_basic256sha256,
            (fn_sign(
                (fn_signature_data(
                    fn_bob_cert,
                    ((server, 0)[Some(OpcuaQueryMatcher::CreateSessionResponse)]/ByteString) // S_nonce!
                )),
                fn_basic256sha256,
                fn_mallory_cert,
                fn_mallory_sk
            )),
            (fn_user_cert(
              ((server, 0)[Some(OpcuaQueryMatcher::PolicyIdCertificate)]/UAString), // PolicyId!
              fn_mallory_cert
            )),
            (fn_sign(
                (fn_signature_data(
                    fn_bob_cert,
                    ((server, 0)[Some(OpcuaQueryMatcher::CreateSessionResponse)]/ByteString) // S_nonce!
                )),
                fn_basic256sha256,
                fn_mallory_cert,
                fn_mallory_sk
            ))
        )
    };
    let close_request_1 = term! {
        fn_client_close(
            (fn_request_header(fn_sa_token_zero, fn_seq_3))
        )
    };

    let open_request_2 = term! {
        fn_service(
            (fn_sequence_header(fn_seq_4, fn_seq_4)),
            (fn_client_open(
                (fn_request_header(fn_sa_token_zero, fn_seq_4)),
                fn_issue,
                fn_mode_sign,
                fn_channel_nonce_2
            ))
        )
    };
    let hmac_key_2 = term! {
        fn_client_mac_key(
            fn_basic256sha256,
            fn_channel_nonce_2,
            (fn_get_server_nonce(
                (fn_decrypted_body(
                    (fn_asym_decrypt(
                        fn_basic256sha256,
                        ((server, 2)[None]/EncryptedBody),
                        fn_mallory_sk)),
                    fn_mallory_sk
                ))
            ))
        )
    };
    let switch_certificate = term! {
        fn_activate_request(
            (fn_request_header(
                ((server, 3)[Some(OpcuaQueryMatcher::CreateSessionResponse)]/NodeId), // SA_Token!
                fn_seq_5
            )),
            fn_basic256sha256,
            (fn_sign(
                (fn_signature_data(
                    fn_bob_cert,
                    ((server, 0)[Some(OpcuaQueryMatcher::ActivateSessionResponse)]/ByteString) // S_nonce!
                )),
                fn_basic256sha256,
                fn_mallory_cert,
                fn_mallory_sk
            )),
            (fn_user_cert(
              ((server, 0)[Some(OpcuaQueryMatcher::PolicyIdCertificate)]/UAString), // PolicyId!
              fn_alice_cert
            )),
            (fn_sign(
                (fn_signature_data(
                    fn_bob_cert,
                    ((server, 0)[Some(OpcuaQueryMatcher::ActivateSessionResponse)]/ByteString) // S_nonce!
                )),
                fn_basic256sha256,
                fn_alice_cert,
                fn_alice_sk
            ))
        )
    };
    let close_session = term! {
        fn_close_request(
            (fn_request_header(
                ((server, 3)[Some(OpcuaQueryMatcher::CreateSessionResponse)]/NodeId), // SA_Token!
                fn_seq_6))
        )
    };
    let close_request_2 = term! {
        fn_client_close(
            (fn_request_header(fn_sa_token_zero, fn_seq_7))
        )
    };

    Trace {
        prior_traces: vec![],
        metadata_trace: Default::default(),
        descriptors: vec![ApplicationConfig::new_server(server)],
        steps: vec![
            /* Open secure channel #1 */
            Step {
                agent: server,
                action: Action::Input(input_action! { term! {
                    fn_client_hello (
                        fn_tcp_1,
                        fn_bob_endpoint,
                        fn_default_size,
                        fn_default_size
                    )}
                }),
            },
            Step {
                agent: server,
                action: Action::Input(input_action! { term! {
                    fn_open_message (
                        fn_tcp_1,
                        (fn_open_header(
                            (fn_header(fn_open, fn_seq_0)),
                            fn_basic256sha256,
                            fn_mallory_cert,
                            fn_bob_cert,
                            (@open_request_1)
                        )),
                        (fn_asym_header(
                            fn_basic256sha256,
                            fn_mallory_cert,
                            fn_bob_cert
                        )),
                        (fn_asym_encrypt(
                            fn_basic256sha256,
                            fn_bob_cert,
                            (fn_data_to_encrypt(
                                fn_basic256sha256,
                                fn_bob_cert,
                                (@open_request_1),
                                (fn_sign(
                                    (fn_data_to_sign(
                                        (fn_open_header(
                                            (fn_header(fn_open, fn_seq_0)),
                                            fn_basic256sha256,
                                            fn_mallory_cert,
                                            fn_bob_cert,
                                            (@open_request_1)
                                        )),
                                        fn_basic256sha256,
                                        fn_mallory_cert,
                                        fn_bob_cert,
                                        (@open_request_1)
                                    )),
                                    fn_basic256sha256,
                                    fn_mallory_cert,
                                    fn_mallory_sk
                                ))
                           ))
                        ))
                    )}
                }),
            },
            /* Open secure channel #2 */
            Step {
                agent: server,
                action: Action::Input(input_action! { term! {
                    fn_client_hello (
                        fn_tcp_2,
                        fn_bob_endpoint,
                        fn_default_size,
                        fn_default_size
                    )}
                }),
            },
            Step {
                agent: server,
                action: Action::Input(input_action! { term! {
                    fn_open_message (
                        fn_tcp_2,
                        (fn_open_header(
                            (fn_header(fn_open, fn_seq_0)),
                            fn_basic256sha256,
                            fn_mallory_cert,
                            fn_bob_cert,
                            (@open_request_2)
                        )),
                        (fn_asym_header(
                            fn_basic256sha256,
                            fn_mallory_cert,
                            fn_bob_cert
                        )),
                        (fn_asym_encrypt(
                            fn_basic256sha256,
                            fn_bob_cert,
                            (fn_data_to_encrypt(
                                fn_basic256sha256,
                                fn_bob_cert,
                                (@open_request_2),
                                (fn_sign(
                                    (fn_data_to_sign(
                                        (fn_open_header(
                                            (fn_header(fn_open, fn_seq_0)),
                                            fn_basic256sha256,
                                            fn_mallory_cert,
                                            fn_bob_cert,
                                            (@open_request_2)
                                        )),
                                        fn_basic256sha256,
                                        fn_mallory_cert,
                                        fn_bob_cert,
                                        (@open_request_2)
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
                        fn_tcp_1,
                        (fn_msg_header(
                            fn_basic256sha256,
                            (fn_header(fn_final,
                                ((server, 1)[Some(OpcuaQueryMatcher::OpenSecureChannelResponse)]/u32))),
                            (fn_service_size((@create_request)))
                        )),
                        (fn_body(
                            (fn_get_channel_token(
                                (fn_decrypted_body(
                                    (fn_asym_decrypt(
                                        fn_basic256sha256,
                                        ((server, 1)[None]/EncryptedBody),
                                        fn_mallory_sk)),
                                    fn_mallory_sk
                                ))
                            )),
                            (fn_sequence_header(fn_seq_1, fn_seq_1)),
                            (@create_request),
                            (fn_mac(
                                (fn_data_to_mac(
                                    (fn_msg_header(
                                        fn_basic256sha256,
                                        (fn_header(fn_final,
                                            ((server, 1)[Some(OpcuaQueryMatcher::OpenSecureChannelResponse)]/u32))),
                                        (fn_service_size((@create_request)))
                                    )),
                                    (fn_get_channel_token(
                                        (fn_decrypted_body(
                                            (fn_asym_decrypt(
                                                fn_basic256sha256,
                                                ((server, 1)[None]/EncryptedBody),
                                                fn_mallory_sk)),
                                            fn_mallory_sk
                                        ))
                                    )),
                                    (fn_service(
                                        (fn_sequence_header(fn_seq_1, fn_seq_1)),
                                        (@create_request)
                                    ))
                                )),
                                fn_basic256sha256,
                                (@hmac_key_1)
                            ))
                        ))
                    )}
                }),
            },
            Step {
                agent: server,
                action: Action::Input(input_action! { term! {
                    fn_message (
                        fn_tcp_1,
                        (fn_msg_header(
                            fn_basic256sha256,
                            (fn_header(fn_final,
                                ((server, 1)[Some(OpcuaQueryMatcher::OpenSecureChannelResponse)]/u32))),
                            (fn_service_size((@activate_certificate)))
                        )),
                        (fn_body(
                            (fn_get_channel_token(
                                (fn_decrypted_body(
                                    (fn_asym_decrypt(
                                        fn_basic256sha256,
                                        ((server, 1)[None]/EncryptedBody),
                                        fn_mallory_sk)),
                                    fn_mallory_sk
                                ))
                            )),
                            (fn_sequence_header(fn_seq_2, fn_seq_2)),
                            (@activate_certificate),
                            (fn_mac(
                                (fn_data_to_mac(
                                    (fn_msg_header(
                                        fn_basic256sha256,
                                        (fn_header(fn_final,
                                            ((server, 1)[Some(OpcuaQueryMatcher::OpenSecureChannelResponse)]/u32))),
                                        (fn_service_size((@activate_certificate)))
                                    )),
                                    (fn_get_channel_token(
                                        (fn_decrypted_body(
                                            (fn_asym_decrypt(
                                                fn_basic256sha256,
                                                ((server, 1)[None]/EncryptedBody),
                                                fn_mallory_sk)),
                                            fn_mallory_sk
                                        ))
                                    )),
                                    (fn_service(
                                        (fn_sequence_header(fn_seq_2, fn_seq_2)),
                                        (@activate_certificate)
                                    ))
                                )),
                                fn_basic256sha256,
                                (@hmac_key_1)
                            ))
                        ))
                    )}
                }),
            },
            Step {
                agent: server,
                action: Action::Input(input_action! { term! {
                    fn_message (
                        fn_tcp_1,
                        (fn_msg_header(
                            fn_basic256sha256,
                            (fn_header(fn_close, // needs channel id:
                                ((server, 1)[Some(OpcuaQueryMatcher::OpenSecureChannelResponse)]/u32))),
                            (fn_service_size((@close_request_1)))
                        )),
                        (fn_body(
                            (fn_get_channel_token(
                                (fn_decrypted_body(
                                    (fn_asym_decrypt(
                                        fn_basic256sha256,
                                        ((server, 1)[None]/EncryptedBody),
                                        fn_mallory_sk)),
                                    fn_mallory_sk
                                ))
                            )),
                            (fn_sequence_header(fn_seq_3, fn_seq_3)),
                            (@close_request_1),
                            (fn_mac(
                                (fn_data_to_mac(
                                    (fn_msg_header(
                                        fn_basic256sha256,
                                        (fn_header(fn_close, // needs channel id:
                                            ((server, 1)[Some(OpcuaQueryMatcher::OpenSecureChannelResponse)]/u32))),
                                        (fn_service_size((@close_request_1)))
                                    )),
                                    (fn_get_channel_token(
                                        (fn_decrypted_body(
                                            (fn_asym_decrypt(
                                                fn_basic256sha256,
                                                ((server, 1)[None]/EncryptedBody),
                                                fn_mallory_sk)),
                                            fn_mallory_sk
                                        ))
                                    )),
                                    (fn_service(
                                        (fn_sequence_header(fn_seq_3, fn_seq_3)),
                                        (@close_request_1)
                                    ))
                                )),
                                fn_basic256sha256,
                                (@hmac_key_1)
                            ))
                        ))
                    )}
                }),
            },
            Step {
                agent: server,
                action: Action::Input(input_action! { term! {
                    fn_message (
                        fn_tcp_2,
                        (fn_msg_header(
                            fn_basic256sha256,
                            (fn_header(fn_final,
                                ((server, 2)[Some(OpcuaQueryMatcher::OpenSecureChannelResponse)]/u32))),
                            (fn_service_size((@switch_certificate)))
                        )),
                        (fn_body(
                            (fn_get_channel_token(
                                (fn_decrypted_body(
                                    (fn_asym_decrypt(
                                        fn_basic256sha256,
                                        ((server, 2)[None]/EncryptedBody),
                                        fn_mallory_sk)),
                                    fn_mallory_sk
                                ))
                            )),
                            (fn_sequence_header(fn_seq_5, fn_seq_5)),
                            (@switch_certificate),
                            (fn_mac(
                                (fn_data_to_mac(
                                    (fn_msg_header(
                                        fn_basic256sha256,
                                        (fn_header(fn_final,
                                            ((server, 2)[Some(OpcuaQueryMatcher::OpenSecureChannelResponse)]/u32))),
                                        (fn_service_size((@switch_certificate)))
                                    )),
                                    (fn_get_channel_token(
                                        (fn_decrypted_body(
                                            (fn_asym_decrypt(
                                                fn_basic256sha256,
                                                ((server, 2)[None]/EncryptedBody),
                                                fn_mallory_sk)),
                                            fn_mallory_sk
                                        ))
                                    )),
                                    (fn_service(
                                        (fn_sequence_header(fn_seq_5, fn_seq_5)),
                                        (@switch_certificate)
                                    ))
                                )),
                                fn_basic256sha256,
                                (@hmac_key_2)
                            ))
                        ))
                    )}
                }),
            },
            Step {
                agent: server,
                action: Action::Input(input_action! { term! {
                    fn_message (
                        fn_tcp_2,
                        (fn_msg_header(
                            fn_basic256sha256,
                            (fn_header(fn_final,
                                ((server, 2)[Some(OpcuaQueryMatcher::OpenSecureChannelResponse)]/u32))),
                            (fn_service_size((@close_session)))
                        )),
                        (fn_body(
                            (fn_get_channel_token(
                                (fn_decrypted_body(
                                    (fn_asym_decrypt(
                                        fn_basic256sha256,
                                        ((server, 2)[None]/EncryptedBody),
                                        fn_mallory_sk)),
                                    fn_mallory_sk
                                ))
                            )),
                            (fn_sequence_header(fn_seq_6, fn_seq_6)),
                            (@close_session),
                            (fn_mac(
                                (fn_data_to_mac(
                                    (fn_msg_header(
                                        fn_basic256sha256,
                                        (fn_header(fn_final,
                                            ((server, 2)[Some(OpcuaQueryMatcher::OpenSecureChannelResponse)]/u32))),
                                        (fn_service_size((@close_session)))
                                    )),
                                    (fn_get_channel_token(
                                        (fn_decrypted_body(
                                            (fn_asym_decrypt(
                                                fn_basic256sha256,
                                                ((server, 2)[None]/EncryptedBody),
                                                fn_mallory_sk)),
                                            fn_mallory_sk
                                        ))
                                    )),
                                    (fn_service(
                                        (fn_sequence_header(fn_seq_6, fn_seq_6)),
                                        (@close_session)
                                    ))
                                )),
                                fn_basic256sha256,
                                (@hmac_key_2)
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
                        fn_tcp_2,
                        (fn_msg_header(
                            fn_basic256sha256,
                            (fn_header(fn_close, // needs channel id:
                                ((server, 2)[Some(OpcuaQueryMatcher::OpenSecureChannelResponse)]/u32))),
                            (fn_service_size((@close_request_2)))
                        )),
                        (fn_body(
                            (fn_get_channel_token(
                                (fn_decrypted_body(
                                    (fn_asym_decrypt(
                                        fn_basic256sha256,
                                        ((server, 2)[None]/EncryptedBody),
                                        fn_mallory_sk)),
                                    fn_mallory_sk
                                ))
                            )),
                            (fn_sequence_header(fn_seq_7, fn_seq_7)),
                            (@close_request_2),
                            (fn_mac(
                                (fn_data_to_mac(
                                    (fn_msg_header(
                                        fn_basic256sha256,
                                        (fn_header(fn_close, // needs channel id:
                                            ((server, 2)[Some(OpcuaQueryMatcher::OpenSecureChannelResponse)]/u32))),
                                        (fn_service_size((@close_request_2)))
                                    )),
                                    (fn_get_channel_token(
                                        (fn_decrypted_body(
                                            (fn_asym_decrypt(
                                                fn_basic256sha256,
                                                ((server, 2)[None]/EncryptedBody),
                                                fn_mallory_sk)),
                                            fn_mallory_sk
                                        ))
                                    )),
                                    (fn_service(
                                        (fn_sequence_header(fn_seq_7, fn_seq_7)),
                                        (@close_request_2)
                                    ))
                                )),
                                fn_basic256sha256,
                                (@hmac_key_2)
                            ))
                        ))
                    )
                    }
                }),
            },
        ],
    }
}

#[cfg(test)]
pub mod tests {

    use opcua::puffin::signature::OPCUA_SIGNATURE;
    use puffin::algebra::dynamic_function::DescribableFunction;
    use puffin::algebra::{DYTerm, TermType};
    use puffin::execution::run_in_subprocess;
    use puffin::fuzzer::mutations::{ReplaceMatchMutator, ScopeWeights};
    use puffin::fuzzer::utils::TermConstraints;
    use puffin::libafl::corpus::InMemoryCorpus;
    use puffin::libafl::mutators::Mutator;
    use puffin::libafl::state::StdState;
    use puffin::libafl_bolts::rands::{RomuDuoJrRand, StdRand};
    use puffin::test_utils::AssertExecution;

    #[allow(unused_imports)]
    use super::*;

    pub type TestTrace = Trace<OpcuaProtocolTypes>;

    fn create_state(
    ) -> StdState<InMemoryCorpus<TestTrace>, TestTrace, RomuDuoJrRand, InMemoryCorpus<TestTrace>>
    {
        let rand = StdRand::with_seed(1235);
        let corpus: InMemoryCorpus<TestTrace> = InMemoryCorpus::new();
        StdState::new(rand, corpus, InMemoryCorpus::new(), &mut (), &mut ()).unwrap()
    }

    // Requires a vendor built with the `Bug-dead-session` patch: `.expect_crash()` only holds
    // against that planted PUT. Both planted bugs are disabled by default (see
    // vendors/open62541/builder.cmake), so on the clean vendor this cannot crash; run it explicitly
    // with `--ignored` after building the planted vendor.
    #[test]
    #[ignore = "requires open62541 built with Bug-dead-session; expect_crash only holds on the planted PUT"]
    fn test_mutant_seed_bug_dead_session() {
        let mut state = create_state();

        run_in_subprocess(
            move || {
                for _i in 0..5 {
                    let mut attempts = 0;
                    let mut trace = seed_bug_dead_session(AgentName::first());
                    let constraints = TermConstraints::default();

                    // Test if we can replace the sequence number

                    // (0,0,1): individual-occurrence replacement (pre-scoped-mutation semantics)
                    let mut mutator = ReplaceMatchMutator::new(
                        constraints,
                        &OPCUA_SIGNATURE,
                        true,
                        false, // with_bit: this repro drives DY mutations only
                        ScopeWeights::new(0, 0, 1),
                    );

                    loop {
                        attempts += 1;
                        let mut mutant = trace.clone();
                        mutator.mutate(&mut state, &mut mutant).unwrap();

                        if let Some(last) = mutant.steps.iter().last() {
                            match &last.action {
                                Action::Input(input) => match &input.recipe.term {
                                    DYTerm::Variable(_) => {}
                                    DYTerm::Application(_, subterms) => {
                                        if let Some(last_subterm) = subterms.iter().last() {
                                            if last_subterm.name() == fn_seq_2.name() {
                                                trace = mutant;
                                                break;
                                            }
                                        }
                                    }
                                },
                                Action::Output(_) => {}
                            }
                        }
                    }
                    println!("attempts: {}", attempts);
                }
            },
            std::time::Duration::from_secs(60),
        )
        .expect_crash();
    }
}
