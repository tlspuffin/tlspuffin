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
              fn_oscar_cert
            )),
            (fn_sign(
                (fn_signature_data(
                    fn_bob_cert,
                    ((server, 0)[Some(OpcuaQueryMatcher::CreateSessionResponse)]/ByteString) // S_nonce!
                )),
                fn_basic256sha256,
                fn_oscar_cert,
                fn_oscar_sk
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
                                ((server, 1)[Some(OpcuaQueryMatcher::OpenSecureChannelResponse)]/u32))))),
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
                            fn_basic256sha256,
                                    (fn_msg_header(
                                        fn_basic256sha256,
                                        (fn_header(fn_final,
                                            ((server, 1)[Some(OpcuaQueryMatcher::OpenSecureChannelResponse)]/u32))))),
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
                                ((server, 1)[Some(OpcuaQueryMatcher::OpenSecureChannelResponse)]/u32))))),
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
                            fn_basic256sha256,
                                    (fn_msg_header(
                                        fn_basic256sha256,
                                        (fn_header(fn_final,
                                            ((server, 1)[Some(OpcuaQueryMatcher::OpenSecureChannelResponse)]/u32))))),
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
                                ((server, 1)[Some(OpcuaQueryMatcher::OpenSecureChannelResponse)]/u32))))),
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
                            fn_basic256sha256,
                                    (fn_msg_header(
                                        fn_basic256sha256,
                                        (fn_header(fn_final,
                                            ((server, 1)[Some(OpcuaQueryMatcher::OpenSecureChannelResponse)]/u32))))),
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
                                ((server, 1)[Some(OpcuaQueryMatcher::OpenSecureChannelResponse)]/u32))))),
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
                            fn_basic256sha256,
                                    (fn_msg_header(
                                        fn_basic256sha256,
                                        (fn_header(fn_final,
                                            ((server, 1)[Some(OpcuaQueryMatcher::OpenSecureChannelResponse)]/u32))))),
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
                                ((server, 1)[Some(OpcuaQueryMatcher::OpenSecureChannelResponse)]/u32))))),
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
                            fn_basic256sha256,
                                    (fn_msg_header(
                                        fn_basic256sha256,
                                        (fn_header(fn_final,
                                            ((server, 1)[Some(OpcuaQueryMatcher::OpenSecureChannelResponse)]/u32))))),
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
    // Attack: switch presents user identity ALICE while the session was created/activated as
    // OSCAR (client stays MALLORY) -> user-identity mismatch -> OOB in Service_ActivateSession.
    seed_bad_switch_cfg(server, true, true, true, false)
}

/// Parameterised variant of [`seed_bad_switch`] for the seed-distance (dichotomy)
/// evaluation. Byte-identical to `seed_bad_switch` except the four identity leaves
/// of `switch_certificate` (the 2nd/switch activation), each Alice (true) or
/// Mallory (false):
///   * `uc_alice`       -> user-token cert (fn_user_cert)
///   * `uts_cert_alice` -> userTokenSignature cert
///   * `uts_key_alice`  -> userTokenSignature signing key
///   * `csig_alice`     -> clientSignature cert AND key (over-replace variant)
/// Committed attack = (false, true, true, false).
pub fn seed_bad_switch_cfg(
    server: AgentName,
    uc_alice: bool,
    uts_cert_alice: bool,
    uts_key_alice: bool,
    csig_alice: bool,
) -> Trace<OpcuaProtocolTypes> {
    // Identity model (client != user, baked in): client/channel = MALLORY, session user = OSCAR,
    // switch-to attacker identity = ALICE, server = BOB. The switch presents ALICE (attack) or
    // OSCAR (legit, matches the stored user) at the user-token positions; the clientSignature is
    // ALWAYS the client (MALLORY). `_csig_alice` is retained for signature compatibility but the
    // clientSignature no longer varies (flipping it would break the channel, never the bug).
    let _ = csig_alice;
    let uc_cert   = if uc_alice       { term! { fn_alice_cert } } else { term! { fn_oscar_cert } };
    let uts_cert  = if uts_cert_alice { term! { fn_alice_cert } } else { term! { fn_oscar_cert } };
    let uts_key   = if uts_key_alice  { term! { fn_alice_sk } }   else { term! { fn_oscar_sk } };
    let csig_cert = term! { fn_mallory_cert };
    let csig_key  = term! { fn_mallory_sk };
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
            (fn_sign(                                   // clientSignature = client (MALLORY)
                (fn_signature_data(
                    fn_bob_cert,
                    ((server, 0)[Some(OpcuaQueryMatcher::CreateSessionResponse)]/ByteString) // S_nonce!
                )),
                fn_basic256sha256,
                fn_mallory_cert,
                fn_mallory_sk
            )),
            (fn_user_cert(                              // stored session user = OSCAR
              ((server, 0)[Some(OpcuaQueryMatcher::PolicyIdCertificate)]/UAString), // PolicyId!
              fn_oscar_cert
            )),
            (fn_sign(                                   // userTokenSignature = user (OSCAR)
                (fn_signature_data(
                    fn_bob_cert,
                    ((server, 0)[Some(OpcuaQueryMatcher::CreateSessionResponse)]/ByteString) // S_nonce!
                )),
                fn_basic256sha256,
                fn_oscar_cert,
                fn_oscar_sk
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
                (@csig_cert),
                (@csig_key)
            )),
            (fn_user_cert(
              ((server, 0)[Some(OpcuaQueryMatcher::PolicyIdCertificate)]/UAString), // PolicyId!
              (@uc_cert)
            )),
            (fn_sign(
                (fn_signature_data(
                    fn_bob_cert,
                    ((server, 0)[Some(OpcuaQueryMatcher::ActivateSessionResponse)]/ByteString) // S_nonce!
                )),
                fn_basic256sha256,
                (@uts_cert),
                (@uts_key)
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
                                ((server, 1)[Some(OpcuaQueryMatcher::OpenSecureChannelResponse)]/u32))))),
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
                            fn_basic256sha256,
                                    (fn_msg_header(
                                        fn_basic256sha256,
                                        (fn_header(fn_final,
                                            ((server, 1)[Some(OpcuaQueryMatcher::OpenSecureChannelResponse)]/u32))))),
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
                                ((server, 1)[Some(OpcuaQueryMatcher::OpenSecureChannelResponse)]/u32))))),
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
                            fn_basic256sha256,
                                    (fn_msg_header(
                                        fn_basic256sha256,
                                        (fn_header(fn_final,
                                            ((server, 1)[Some(OpcuaQueryMatcher::OpenSecureChannelResponse)]/u32))))),
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
                                ((server, 1)[Some(OpcuaQueryMatcher::OpenSecureChannelResponse)]/u32))))),
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
                            fn_basic256sha256,
                                    (fn_msg_header(
                                        fn_basic256sha256,
                                        (fn_header(fn_close, // needs channel id:
                                            ((server, 1)[Some(OpcuaQueryMatcher::OpenSecureChannelResponse)]/u32))))),
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
                                ((server, 2)[Some(OpcuaQueryMatcher::OpenSecureChannelResponse)]/u32))))),
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
                            fn_basic256sha256,
                                    (fn_msg_header(
                                        fn_basic256sha256,
                                        (fn_header(fn_final,
                                            ((server, 2)[Some(OpcuaQueryMatcher::OpenSecureChannelResponse)]/u32))))),
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
                                ((server, 2)[Some(OpcuaQueryMatcher::OpenSecureChannelResponse)]/u32))))),
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
                            fn_basic256sha256,
                                    (fn_msg_header(
                                        fn_basic256sha256,
                                        (fn_header(fn_final,
                                            ((server, 2)[Some(OpcuaQueryMatcher::OpenSecureChannelResponse)]/u32))))),
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
                                ((server, 2)[Some(OpcuaQueryMatcher::OpenSecureChannelResponse)]/u32))))),
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
                            fn_basic256sha256,
                                    (fn_msg_header(
                                        fn_basic256sha256,
                                        (fn_header(fn_close, // needs channel id:
                                            ((server, 2)[Some(OpcuaQueryMatcher::OpenSecureChannelResponse)]/u32))))),
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

/// Rewrite a bad-switch trace so the USER-TOKEN identity becomes Oscar, distinct from the Mallory
/// CLIENT / channel identity. Changes ONLY the user-token leaves (in every activation), leaving the
/// whole client/channel side Mallory. Then `fn_oscar_*` marks ONLY the user-token role, so a single
/// per-step scoped mutation (oscar -> alice on the switch step) flips exactly the user identity
/// (all its spliced copies) without touching the channel.
///
/// User-token leaves are identified by their position inside `fn_activate_request`:
///   user_cert cert = suffix [3,1];  userTokenSignature cert = [4,2];  userTokenSignature key = [4,3].
pub fn make_user_oscar(trace: &mut Trace<OpcuaProtocolTypes>) {
    use puffin::algebra::TermType;
    use puffin::fuzzer::utils::{find_all_term_filtered, find_term_mut, TermConstraints};
    let c = TermConstraints::default();
    let oscar_cert = term! { fn_oscar_cert };
    let oscar_sk = term! { fn_oscar_sk };
    // certs: change Mallory -> Oscar ONLY at user-token cert positions ([3,1] user_cert, [4,2] uts cert)
    for p in find_all_term_filtered(trace, |t| t.name().ends_with("fn_mallory_cert"), &c) {
        let s = &p.1[p.1.len().saturating_sub(2)..];
        if matches!(s, [3, 1] | [4, 2]) {
            if let Some(tm) = find_term_mut(trace, &p) {
                tm.mutate(oscar_cert.clone());
            }
        }
    }
    // keys: change Mallory -> Oscar ONLY at the userTokenSignature key position ([4,3])
    for p in find_all_term_filtered(trace, |t| t.name().ends_with("fn_mallory_sk"), &c) {
        let s = &p.1[p.1.len().saturating_sub(2)..];
        if matches!(s, [4, 3]) {
            if let Some(tm) = find_term_mut(trace, &p) {
                tm.mutate(oscar_sk.clone());
            }
        }
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

    /// FINE-GRAINED: classify each corpus trace by its ALICE identity composition, to pinpoint
    /// exactly where the fuzzer stalls. Crash needs alice_cert AND alice_sk together at the switch.
    /// Buckets: none / cert-only / key-only / BOTH(crash-capable). If cert-only+key-only >> both,
    /// the missing step is COORDINATING the two swaps (supports a dedicated identity-swap mutation).
    /// Run: CORPUS_DIR=<dir> cargo test -p opcuapuffin badswitch_identity_histogram -- --nocapture
    #[test]
    fn test_badswitch_identity_histogram() {
        use puffin::fuzzer::utils::{find_all_term_filtered, TermConstraints};
        let dir = match std::env::var("CORPUS_DIR") { Ok(d)=>d, Err(_)=>{println!("set CORPUS_DIR");return;} };
        let c = TermConstraints::default();
        let (mut total,mut none,mut cert_only,mut key_only,mut both,mut switchcap,mut both_structured)=(0,0,0,0,0,0,0);
        for entry in std::fs::read_dir(&dir).unwrap().flatten() {
            let p=entry.path();
            if p.extension().and_then(|e|e.to_str())!=Some("trace") {continue;}
            let Ok(bytes)=std::fs::read(&p) else {continue};
            let Ok(t)=Trace::<OpcuaProtocolTypes>::deserialize_postcard(&bytes) else {continue};
            total+=1;
            let ac=!find_all_term_filtered(&t,|x|x.name().ends_with("fn_alice_cert"),&c).is_empty();
            let ak=!find_all_term_filtered(&t,|x|x.name().ends_with("fn_alice_sk"),&c).is_empty();
            if t.steps.len()>=10 {switchcap+=1;}
            if ac&&ak&&t.steps.len()>=10 { both_structured+=1; if std::env::var("LIST_BOTH").is_ok() { println!("BOTHPATH {}", p.display()); } }
            match (ac,ak){ (false,false)=>none+=1,(true,false)=>cert_only+=1,(false,true)=>key_only+=1,(true,true)=>both+=1 }
        }
        let pc=|x:usize| if total>0 {100.0*x as f64/total as f64} else {0.0};
        println!("\n=== identity histogram: {dir} (total={total}) ===");
        println!("  switch-capable (>=10 steps) = {switchcap} ({:.1}%)", pc(switchcap));
        println!("  alice NEITHER   = {none} ({:.1}%)", pc(none));
        println!("  alice CERT-only = {cert_only} ({:.1}%)   [partial: inconsistent -> rejected]", pc(cert_only));
        println!("  alice KEY-only  = {key_only} ({:.1}%)   [partial: inconsistent -> rejected]", pc(key_only));
        println!("  alice BOTH      = {both} ({:.1}%)   [<< CRASH-CAPABLE; if ~0 while partials>0, coordination is the gap]", pc(both));
        println!("  alice BOTH + >=10 steps = {both_structured} ({:.1}%)   [ALL switch conditions present structurally;", pc(both_structured));
        println!("      if >0 yet no crash -> ingredients present but SPOILED (hitchhiker breakage earlier / not scheduled)]");
    }

    /// Quantify the HITCHHIKER effect of stacked mutations: the mutational stage applies n=2..256
    /// mutations/input; if the bundle gains coverage the WHOLE bundle is stored, though maybe only 1
    /// mutation was needed. Measures, from the d1key seed (1 swap from attack):
    ///   (A) single ReplaceMatch (n=1): P(reach crash-capable), and P(clean = ONLY the switch step
    ///       changed vs the seed)
    ///   (B) stacked HavocScheduledMutator (n=2..256): same, plus the "hitchhiker rate" = among
    ///       reaches, fraction that ALSO altered a non-switch step (junk that bloats/corrupts corpus).
    /// Run: cargo test -p opcuapuffin badswitch_hitchhiker -- --nocapture
    #[test]
    fn test_badswitch_hitchhiker() {
        use puffin::fuzzer::utils::{find_all_term_filtered, TermConstraints};
        use puffin::fuzzer::mutations::{dy_mutations, MutationConfig, ReplaceMatchMutator, ScopeWeights};
        use puffin::libafl::mutators::scheduled::HavocScheduledMutator;
        let a = AgentName::first();
        let base = seed_bad_switch_cfg(a, true, true, false, false); // d1key: needs uts_key oscar->alice
        let c = TermConstraints::default();
        let sw = 7usize;
        let base_r: Vec<_> = base.steps.iter().map(|s| match &s.action { Action::Input(i)=>Some(i.recipe.clone()),_=>None}).collect();
        let cnt7=|t:&TestTrace,nm:&'static str| find_all_term_filtered(t,move|x|x.name().ends_with(nm),&c)
            .into_iter().filter(|p|format!("{:?}",p.0)==format!("{sw}")).count();
        // crash-capable = switch step: no oscar user leaf left, alice present
        let capable=|m:&TestTrace| cnt7(m,"fn_oscar_cert")==0 && cnt7(m,"fn_oscar_sk")==0 && cnt7(m,"fn_alice_cert")>0 && cnt7(m,"fn_alice_sk")>0;
        // count non-switch steps changed vs base (hitchhikers)
        let other_changed=|m:&TestTrace| -> usize {
            if m.steps.len()!=base.steps.len() { return 99; }
            (0..m.steps.len()).filter(|&i| i!=sw).filter(|&i| match &m.steps[i].action { Action::Input(x)=>base_r[i].as_ref()!=Some(&x.recipe),_=>false}).count()
        };
        let registry = crate::put_registry::opcua_registry();
        let n:u64=50_000;

        // (A) n=1 single ReplaceMatch
        { let mut st=create_state();
          let mut m1=ReplaceMatchMutator::new(c,&OPCUA_SIGNATURE,true,false,ScopeWeights::new(1,1,1));
          let (mut reach,mut clean)=(0u64,0u64);
          for _ in 0..n { let mut m=base.clone(); let _=puffin::libafl::mutators::Mutator::mutate(&mut m1,&mut st,&mut m); if capable(&m){reach+=1; if other_changed(&m)==0{clean+=1;}} }
          println!("\n[n=1 single ReplaceMatch] reach={reach}/{n}={:.5}  of which CLEAN(no other step touched)={clean} ({:.0}%)",
            reach as f64/n as f64, if reach>0 {100.0*clean as f64/reach as f64} else {0.0}); }

        // (B) stacked HavocScheduledMutator (n=2..256)
        { let mut st=create_state();
          let mut mh=HavocScheduledMutator::new(dy_mutations::<_,OpcuaProtocolTypes,_>(MutationConfig::default(),&OPCUA_SIGNATURE,&registry));
          let (mut reach,mut clean,mut sum_hitch)=(0u64,0u64,0u64);
          for _ in 0..n { let mut m=base.clone(); let _=puffin::libafl::mutators::Mutator::mutate(&mut mh,&mut st,&mut m);
            if capable(&m){reach+=1; let oc=other_changed(&m); if oc==0{clean+=1;} else {sum_hitch+=oc as u64;}} }
          println!("[stacked n=2..256]        reach={reach}/{n}={:.5}  of which CLEAN={clean} ({:.0}%)  avg hitchhiker steps among dirty={:.2}",
            reach as f64/n as f64, if reach>0{100.0*clean as f64/reach as f64}else{0.0}, if reach>clean {sum_hitch as f64/(reach-clean) as f64} else {0.0});
          println!("=> HITCHHIKER RISK = fraction of coverage-gaining reaches that drag junk into other steps (1 - CLEAN%).\n"); }
    }

    /// "Why can't the fuzzer do ONE swap?" — measure per-mutation P(reach crash-capable identity)
    /// starting from each ladder seed IN ISOLATION (no corpus dilution). d1key needs only the key
    /// swap; d1cert needs only the cert swap; legit needs both. "crash-capable" = switch step has no
    /// oscar in the user token and alice cert+key present (mismatched identity that fires the OOB).
    /// Also decomposes: P(pick a user oscar leaf at all) vs P(flip it to alice) vs (1/3 step scope).
    /// Run: cargo test -p opcuapuffin badswitch_one_swap -- --nocapture
    #[test]
    fn test_badswitch_one_swap() {
        use puffin::fuzzer::utils::{find_all_term_filtered, TermConstraints};
        use puffin::fuzzer::mutations::{dy_mutations, MutationConfig};
        use puffin::libafl::mutators::scheduled::HavocScheduledMutator;
        use puffin::algebra::TermType;

        let a = AgentName::first();
        let seeds: Vec<(&str, TestTrace)> = vec![
            ("d1key (needs KEY swap only)",  { let mut t=seed_bad_switch_cfg(a,true,true,false,false); make_user_oscar(&mut t); t }),
            ("d1cert (needs CERT swap only)",{ let mut t=seed_bad_switch_cfg(a,false,false,true,false); make_user_oscar(&mut t); t }),
            ("legit (needs BOTH swaps)",     { let mut t=seed_bad_switch_cfg(a,false,false,false,false); make_user_oscar(&mut t); t }),
        ];
        let c = TermConstraints::default();
        let registry = crate::put_registry::opcua_registry();

        for (label, seed) in &seeds {
            // switch step = the step whose recipe differs from the true attack
            let mut d0 = seed_bad_switch_cfg(a,true,true,true,false); make_user_oscar(&mut d0);
            let sw = (0..seed.steps.len()).find(|&i| match (&seed.steps[i].action,&d0.steps[i].action){
                (Action::Input(x),Action::Input(y))=>x.recipe!=y.recipe,_=>false}).unwrap_or(usize::MAX);
            let cnt7=|t:&TestTrace,nm:&'static str| find_all_term_filtered(t,move|x|x.name().ends_with(nm),&c)
                .into_iter().filter(|p|format!("{:?}",p.0)==format!("{sw}")).count();
            let (boc,bok,bac,bak)=(cnt7(seed,"fn_oscar_cert"),cnt7(seed,"fn_oscar_sk"),cnt7(seed,"fn_alice_cert"),cnt7(seed,"fn_alice_sk"));
            // total selectable subterms in whole trace (approx denominator for picking a leaf)
            let total_nodes: usize = seed.steps.iter().map(|s| match &s.action { Action::Input(i)=>i.recipe.size(), _=>0 }).sum();
            let user_oscar_leaves = boc + bok; // leaves that must be flipped

            let mut state = create_state();
            let mut mutator = HavocScheduledMutator::new(dy_mutations::<_,OpcuaProtocolTypes,_>(
                MutationConfig::default(), &OPCUA_SIGNATURE, &registry));
            let n:u64=50_000;
            let (mut capable, mut touched_user)=(0u64,0u64);
            for _ in 0..n {
                let mut m=seed.clone(); let _=mutator.mutate(&mut state,&mut m);
                if m.steps.len()!=seed.steps.len(){continue;}
                let (oc,ok,ac,ak)=(cnt7(&m,"fn_oscar_cert"),cnt7(&m,"fn_oscar_sk"),cnt7(&m,"fn_alice_cert"),cnt7(&m,"fn_alice_sk"));
                // crash-capable: no oscar in user token, alice cert AND key present in switch step
                if oc==0 && ok==0 && ac>0 && ak>0 { capable+=1; }
                // did any user oscar leaf change at all (flipped away from oscar)?
                if oc<boc || ok<bok { touched_user+=1; }
            }
            println!("\n[{label}] sw={sw} user_oscar_leaves={user_oscar_leaves} (cert={boc} key={bok}, already alice: cert={bac} key={bak}) total_nodes={total_nodes}");
            println!("    P(touched a user oscar leaf)     = {:.5} ({}/{n})", touched_user as f64/n as f64, touched_user);
            println!("    P(crash-capable identity reached) = {:.5} ({}/{n})", capable as f64/n as f64, capable);
        }
    }

    /// Investigation: WHERE does dedup lose the switch==attack rate? Break one HavocScheduledMutator
    /// application into components on the distinct+dedup seed:
    ///   - are the two ACTIVATE copies (body + MAC) structurally identical? (bug check)
    ///   - P(>=1 step-7 oscar_cert flipped to alice)   [selection of the cert leaf]
    ///   - P(>=1 step-7 oscar_sk flipped to alice)      [selection of the key leaf]
    ///   - P(identity FULLY alice in step7: no oscar left, alice present)  [loose success]
    ///   - P(switch step == d0 exactly)                 [strict success]
    /// If loose >> strict~0 -> the flip happens, exact-match metric is too strict (campaign uses
    /// execution). If loose~0 -> dedup really suppressed selection. Run:
    ///   cargo test -p opcuapuffin badswitch_flip_components -- --nocapture
    #[test]
    fn test_badswitch_flip_components() {
        use puffin::algebra::TermType;
        use puffin::fuzzer::utils::{find_all_term_filtered, TermConstraints};
        use puffin::fuzzer::mutations::{dy_mutations, MutationConfig};
        use puffin::libafl::mutators::scheduled::HavocScheduledMutator;

        let a = AgentName::first();
        let mut legit = seed_bad_switch_cfg(a, false, false, false, false); make_user_oscar(&mut legit);
        let mut d0 = seed_bad_switch_cfg(a, true, true, true, false); make_user_oscar(&mut d0);
        let c = TermConstraints::default();
        let sw = (0..legit.steps.len()).find(|&i| match (&legit.steps[i].action, &d0.steps[i].action){
            (Action::Input(x),Action::Input(y))=>x.recipe!=y.recipe,_=>false}).unwrap();
        let d0_sw = match &d0.steps[sw].action { Action::Input(i)=>i.recipe.clone(), _=>unreachable!() };

        // BUG CHECK: are the two fn_activate_request (ServiceMessage) copies in the switch step
        // structurally identical? Collect subterms named fn_activate_request in step sw.
        let acts = find_all_term_filtered(&legit, |t| t.name().ends_with("fn_activate_request"), &c)
            .into_iter().filter(|p| format!("{:?}",p.0)==format!("{sw}")).collect::<Vec<_>>();
        println!("\n=== flip components (dedup, sw={sw}) ===");
        println!("switch-step fn_activate_request copies found = {}", acts.len());
        if acts.len()>=2 {
            use puffin::fuzzer::utils::find_term;
            let a0=find_term(&legit,&acts[0]).unwrap(); let a1=find_term(&legit,&acts[1]).unwrap();
            println!("copy0 == copy1 structurally? {}", a0==a1);
        }

        let cnt7=|t:&TestTrace,nm:&'static str| find_all_term_filtered(t,move|x|x.name().ends_with(nm),&c)
            .into_iter().filter(|p|format!("{:?}",p.0)==format!("{sw}")).count();
        let base_oc=cnt7(&legit,"fn_oscar_cert"); let base_ok=cnt7(&legit,"fn_oscar_sk");
        println!("legit step{sw}: oscar_cert={base_oc} oscar_sk={base_ok}");

        let registry = crate::put_registry::opcua_registry();
        let mut state = create_state();
        let mut mutator = HavocScheduledMutator::new(dy_mutations::<_,OpcuaProtocolTypes,_>(
            MutationConfig::default(), &OPCUA_SIGNATURE, &registry));
        let n:u64=50_000;
        let (mut fc,mut fk,mut fully,mut exact,mut anyalice_anywhere)=(0u64,0u64,0u64,0u64,0u64);
        for _ in 0..n {
            let mut m=legit.clone(); let _=mutator.mutate(&mut state,&mut m);
            if m.steps.len()!=legit.steps.len(){continue;}
            let oc=cnt7(&m,"fn_oscar_cert"); let ok=cnt7(&m,"fn_oscar_sk");
            let ac=cnt7(&m,"fn_alice_cert"); let ak=cnt7(&m,"fn_alice_sk");
            if ac>0 && oc<base_oc {fc+=1;}
            if ak>0 && ok<base_ok {fk+=1;}
            if oc==0 && ok==0 && ac>0 && ak>0 {fully+=1;}
            if find_all_term_filtered(&m,|x|x.name().ends_with("fn_alice_cert")||x.name().ends_with("fn_alice_sk"),&c).len()>0 {anyalice_anywhere+=1;}
            if let Action::Input(i)=&m.steps[sw].action { if i.recipe==d0_sw {exact+=1;} }
        }
        let p=|x:u64| x as f64/n as f64;
        println!("P(>=1 step{sw} oscar_cert->alice) = {:.5}", p(fc));
        println!("P(>=1 step{sw} oscar_sk->alice)   = {:.5}", p(fk));
        println!("P(identity FULLY alice in step{sw}, loose) = {:.5}", p(fully));
        println!("P(switch step == d0, strict)       = {:.5}", p(exact));
        println!("P(any fn_alice_* introduced anywhere) = {:.5}", p(anyalice_anywhere));
    }

    /// Diagnostic: does the IDEAL step-scope identity flip (all fn_oscar_* -> fn_alice_* in the
    /// switch step) reproduce d0 exactly? Isolates "can the mutation in principle reach d0" from
    /// mutator sampling. Run: `cargo test -p opcuapuffin badswitch_ideal_flip -- --nocapture`
    #[test]
    fn test_badswitch_ideal_flip() {
        use puffin::algebra::TermType;
        use puffin::fuzzer::utils::{find_all_term_filtered, find_term_mut, TermConstraints};
        let a = AgentName::first();
        let mut legit = seed_bad_switch_cfg(a, false, false, false, false); make_user_oscar(&mut legit);
        let mut d0 = seed_bad_switch_cfg(a, true, true, true, false); make_user_oscar(&mut d0);
        let c = TermConstraints::default();
        // find switch step
        let sw = (0..legit.steps.len()).find(|&i| {
            match (&legit.steps[i].action, &d0.steps[i].action) {
                (Action::Input(x), Action::Input(y)) => x.recipe != y.recipe, _ => false }
        }).expect("switch step");
        // counts in switch step
        let cnt = |t: &TestTrace, nm: &'static str| find_all_term_filtered(t, move |x| x.name().ends_with(nm), &c)
            .into_iter().filter(|p| format!("{:?}", p.0) == format!("{sw}")).count();
        println!("\n=== ideal-flip diagnostic (sw={sw}) ===");
        println!("legit step{sw}: oscar_cert={} oscar_sk={} alice_cert={} alice_sk={}",
            cnt(&legit,"fn_oscar_cert"), cnt(&legit,"fn_oscar_sk"), cnt(&legit,"fn_alice_cert"), cnt(&legit,"fn_alice_sk"));
        println!("d0    step{sw}: oscar_cert={} oscar_sk={} alice_cert={} alice_sk={}",
            cnt(&d0,"fn_oscar_cert"), cnt(&d0,"fn_oscar_sk"), cnt(&d0,"fn_alice_cert"), cnt(&d0,"fn_alice_sk"));
        // manual ideal flip on legit: all oscar_cert->alice_cert, oscar_sk->alice_sk in step sw
        let alice_cert = term!{ fn_alice_cert }; let alice_sk = term!{ fn_alice_sk };
        for p in find_all_term_filtered(&legit, |x| x.name().ends_with("fn_oscar_cert"), &c) {
            if format!("{:?}", p.0) == format!("{sw}") { if let Some(tm)=find_term_mut(&mut legit,&p){tm.mutate(alice_cert.clone());} }
        }
        for p in find_all_term_filtered(&legit, |x| x.name().ends_with("fn_oscar_sk"), &c) {
            if format!("{:?}", p.0) == format!("{sw}") { if let Some(tm)=find_term_mut(&mut legit,&p){tm.mutate(alice_sk.clone());} }
        }
        let eq = match (&legit.steps[sw].action, &d0.steps[sw].action) {
            (Action::Input(x), Action::Input(y)) => x.recipe == y.recipe, _ => false };
        println!("after ideal flip, switch step == d0 switch step? {eq}");
        let all_eq = legit.steps.iter().zip(&d0.steps).all(|(x,y)| match (&x.action,&y.action){
            (Action::Input(a),Action::Input(b))=>a.recipe==b.recipe,_=>false});
        println!("after ideal flip, WHOLE trace == d0? {all_eq}");
    }

    /// Corpus-dilution measurement: scan a finished campaign's corpus and count how many entries
    /// still have the switch structure (>= 8 steps, i.e. usable as a base that can reach the attack).
    /// P(scheduling such a base) ~= that fraction; multiply by the isolated P(reach|clean seed) to
    /// predict campaign finds. Run:
    ///   CORPUS_DIR=/home/.../fuzz_campaigns/distinct_1/corpus \
    ///   cargo test -p opcuapuffin badswitch_corpus_dilution -- --nocapture
    #[test]
    fn test_badswitch_corpus_dilution() {
        let dir = match std::env::var("CORPUS_DIR") {
            Ok(d) => d,
            Err(_) => { println!("set CORPUS_DIR to a campaign corpus dir; skipping"); return; }
        };
        let seed_steps = {
            let a = AgentName::first();
            let mut t = seed_bad_switch_cfg(a, false, false, false, false);
            make_user_oscar(&mut t);
            t.steps.len()
        };
        let mut total = 0usize;
        let mut hist: std::collections::BTreeMap<usize, usize> = std::collections::BTreeMap::new();
        let mut full_structure = 0usize;
        for entry in std::fs::read_dir(&dir).unwrap().flatten() {
            let p = entry.path();
            if p.extension().and_then(|e| e.to_str()) != Some("trace") { continue; }
            if let Ok(bytes) = std::fs::read(&p) {
                if let Ok(t) = Trace::<OpcuaProtocolTypes>::deserialize_postcard(&bytes) {
                    total += 1;
                    let ns = t.steps.len();
                    *hist.entry(ns).or_default() += 1;
                    if ns >= seed_steps { full_structure += 1; }
                }
            }
        }
        println!("\n=== corpus dilution: {dir} ===");
        println!("  seed switch structure = {seed_steps} steps");
        println!("  total corpus entries  = {total}");
        println!("  entries with >= {seed_steps} steps (switch-capable base) = {full_structure} = {:.4}",
            full_structure as f64 / total.max(1) as f64);
        println!("  step-count histogram (steps: count):");
        for (k, v) in &hist { println!("      {k:>3}: {v}"); }
        // How many corpus entries still carry the user-token OSCAR identity (the flippable marker)?
        // If ~0, the identity structure is destroyed and never preserved (no coverage reward).
        use puffin::fuzzer::utils::{find_all_term_filtered, TermConstraints};
        let c = TermConstraints::default();
        let mut with_oscar_sk = 0usize;
        let mut entries: Vec<TestTrace> = vec![];
        for entry in std::fs::read_dir(&dir).unwrap().flatten() {
            let p = entry.path();
            if p.extension().and_then(|e| e.to_str()) != Some("trace") { continue; }
            if let Ok(bytes) = std::fs::read(&p) {
                if let Ok(t) = Trace::<OpcuaProtocolTypes>::deserialize_postcard(&bytes) {
                    if !find_all_term_filtered(&t, |x| x.name().ends_with("fn_oscar_sk"), &c).is_empty() {
                        with_oscar_sk += 1;
                    }
                    entries.push(t);
                }
            }
        }
        println!("  entries retaining fn_oscar_sk (user-token identity marker) = {with_oscar_sk} = {:.4}",
            with_oscar_sk as f64 / total.max(1) as f64);

        // DECISIVE: measured P(reach attack) using ACTUAL corpus entries as the mutation base
        // (mirrors the campaign), vs 0.37% from the pristine seed.
        let a = AgentName::first();
        let mut d0 = seed_bad_switch_cfg(a, true, true, true, false);
        make_user_oscar(&mut d0);
        let d0_r: Vec<_> = d0.steps.iter().map(|s| match &s.action { Action::Input(i) => Some(i.recipe.clone()), _ => None }).collect();
        use puffin::fuzzer::mutations::{dy_mutations, MutationConfig};
        use puffin::libafl::mutators::scheduled::HavocScheduledMutator;
        let registry = crate::put_registry::opcua_registry();
        let mut state = create_state();
        let mut mutator = HavocScheduledMutator::new(dy_mutations::<_, OpcuaProtocolTypes, _>(
            MutationConfig::default(), &OPCUA_SIGNATURE, &registry));
        let trials: u64 = 100_000;
        let mut reached = 0u64;
        for k in 0..trials {
            let base = &entries[(k as usize) % entries.len()];
            let mut m = base.clone();
            let _ = mutator.mutate(&mut state, &mut m);
            if m.steps.len() == d0.steps.len()
               && m.steps.iter().zip(&d0_r).all(|(s, dr)| match (&s.action, dr) {
                   (Action::Input(i), Some(r)) => &i.recipe == r, _ => false }) {
                reached += 1;
            }
        }
        println!("  DECISIVE P(reach attack | random CORPUS entry as base) = {reached}/{trials} = {:.6}", reached as f64/trials as f64);
        println!("     (compare to 0.0037 from the pristine seed; the gap is the real campaign blocker)");
    }

    /// ISOLATED end-to-end mutation test (no corpus dilution): apply the REAL campaign DY mutator
    /// (HavocScheduledMutator over dy_mutations -- same stacking the campaign uses) directly to the
    /// distinct-identity legit switch seed, and measure how often ONE application reaches the exact
    /// attack (all step-7 user-token leaves -> Alice, channel/other steps intact). This is the
    /// per-scheduled-call probability the campaign WOULD have if it always mutated this seed; the
    /// gap vs the campaign quantifies corpus dilution.
    /// Run: `cargo test -p opcuapuffin badswitch_isolated_mutator -- --nocapture`
    #[test]
    fn test_badswitch_isolated_mutator() {
        use crate::put_registry::opcua_registry;
        use puffin::fuzzer::mutations::{dy_mutations, MutationConfig};
        use puffin::libafl::mutators::scheduled::HavocScheduledMutator;

        fn step_recipes(t: &TestTrace) -> Vec<Option<&puffin::algebra::Term<OpcuaProtocolTypes>>> {
            t.steps.iter().map(|s| match &s.action {
                Action::Input(i) => Some(&i.recipe),
                _ => None,
            }).collect()
        }

        let a = AgentName::first();
        let mut legit = seed_bad_switch_cfg(a, false, false, false, false);
        make_user_oscar(&mut legit);            // user token = Oscar (distinct from Mallory channel)
        let mut d0 = seed_bad_switch_cfg(a, true, true, true, false);
        make_user_oscar(&mut d0);               // attack: switch user = Alice, stored = Oscar
        let n_steps = legit.steps.len();
        let legit_r = step_recipes(&legit);
        let d0_r = step_recipes(&d0);
        // Derive the switch step: the ONLY step where legit and d0 differ.
        let diff_steps: Vec<usize> = (0..n_steps).filter(|&i| legit_r[i] != d0_r[i]).collect();
        assert_eq!(diff_steps.len(), 1, "legit and d0 must differ in exactly one step, got {diff_steps:?}");
        let sw = diff_steps[0];
        println!("(switch step index = {sw} of {n_steps})");

        let registry = opcua_registry();
        let mut state = create_state();
        let mut mutator = HavocScheduledMutator::new(dy_mutations::<_, OpcuaProtocolTypes, _>(
            MutationConfig::default(),
            &OPCUA_SIGNATURE,
            &registry,
        ));

        let n: u64 = 50_000;
        let (mut reached_attack, mut switch_alice, mut structure_ok) = (0u64, 0u64, 0u64);
        for k in 0..n {
            let mut m = legit.clone();
            let _ = mutator.mutate(&mut state, &mut m);
            if m.steps.len() == n_steps {
                let mr = step_recipes(&m);
                // channel/session setup intact = every step except the switch equals legit
                let others_intact = (0..n_steps).all(|i| i == sw || mr[i] == legit_r[i]);
                if others_intact { structure_ok += 1; }
                // switch step became exactly the attack
                let switch_is_attack = mr[sw] == d0_r[sw];
                if switch_is_attack { switch_alice += 1; }
                if others_intact && switch_is_attack { reached_attack += 1; }
            }
            if (k + 1) % 5000 == 0 {
                println!("  progress {}/{n}: reached_attack={reached_attack} switch==attack={switch_alice} structure_ok={structure_ok}", k + 1);
            }
        }
        println!("\n=== ISOLATED real-mutator test (distinct identity, {n} applications of HavocScheduledMutator/dy_mutations) ===");
        println!("  P(reached EXACT attack)        = {reached_attack}/{n} = {:.6}", reached_attack as f64/n as f64);
        println!("  P(switch step == attack)       = {switch_alice}/{n} = {:.6}", switch_alice as f64/n as f64);
        println!("  P(all other steps intact)      = {structure_ok}/{n} = {:.6}", structure_ok as f64/n as f64);
        println!("  => if P(reached attack) >> campaign rate, the campaign blocker is corpus dilution, not the mutation.\n");
        // informational only (do not fail the suite on a probabilistic 0)
        if reached_attack == 0 {
            println!("  NOTE: 0 exact-attack reaches in {n} applications (see switch==attack / structure_ok for why)");
        }
    }

    /// Distinct-client-identity experiment: with client=Oscar and user-token=Mallory, does a
    /// per-step scoped mallory->alice reach the attack? Verifies the transform and measures P.
    /// Run: `cargo test -p opcuapuffin badswitch_distinct_identity -- --nocapture`
    #[test]
    fn test_badswitch_distinct_identity() {
        use puffin::fuzzer::utils::find_all_term_filtered;

        fn recipes_eq(a: &TestTrace, b: &TestTrace) -> bool {
            a.steps.len() == b.steps.len()
                && a.steps.iter().zip(&b.steps).all(|(x, y)| match (&x.action, &y.action) {
                    (Action::Input(xi), Action::Input(yi)) => xi.recipe == yi.recipe,
                    _ => false,
                })
        }

        let a = AgentName::first();
        let mut legit = seed_bad_switch_cfg(a, false, false, false, false); // user token Mallory -> Oscar
        make_user_oscar(&mut legit);
        let mut d0 = seed_bad_switch_cfg(a, true, true, true, false); // switch user Alice; activate#1 -> Oscar
        make_user_oscar(&mut d0);
        let c = TermConstraints::default();
        let cnt = |t: &TestTrace, name: &'static str| {
            find_all_term_filtered(t, move |x| x.name().ends_with(name), &c).len()
        };
        // step-7 (switch) only counts
        let cnt7 = |t: &TestTrace, name: &'static str| {
            find_all_term_filtered(t, move |x| x.name().ends_with(name), &c)
                .into_iter()
                .filter(|p| format!("{:?}", p.0) == "7")
                .count()
        };
        println!("\n=== distinct-identity transform check (client=Oscar, user=Mallory) ===");
        println!("legit: mallory_cert={} mallory_sk={} oscar_cert={} oscar_sk={} alice_cert={} alice_sk={}",
            cnt(&legit,"fn_mallory_cert"), cnt(&legit,"fn_mallory_sk"), cnt(&legit,"fn_oscar_cert"),
            cnt(&legit,"fn_oscar_sk"), cnt(&legit,"fn_alice_cert"), cnt(&legit,"fn_alice_sk"));
        println!("d0:    mallory_cert={} mallory_sk={} oscar_cert={} oscar_sk={} alice_cert={} alice_sk={}",
            cnt(&d0,"fn_mallory_cert"), cnt(&d0,"fn_mallory_sk"), cnt(&d0,"fn_oscar_cert"),
            cnt(&d0,"fn_oscar_sk"), cnt(&d0,"fn_alice_cert"), cnt(&d0,"fn_alice_sk"));
        // user token is now OSCAR; the triggering mutation is oscar -> alice on the switch step.
        println!("step7 legit: oscar_cert={} oscar_sk={} (user token) | step7 d0: oscar_cert={} oscar_sk={} (d0 step7 should be 0/0)",
            cnt7(&legit,"fn_oscar_cert"), cnt7(&legit,"fn_oscar_sk"),
            cnt7(&d0,"fn_oscar_cert"), cnt7(&d0,"fn_oscar_sk"));

        let n: u64 = 30_000;
        for (label, sw) in [
            ("default (1,1,1)", ScopeWeights::new(1, 1, 1)),
            ("step (0,1,0)", ScopeWeights::new(0, 1, 0)),
            ("individual (0,0,1)", ScopeWeights::new(0, 0, 1)),
        ] {
            let mut state = create_state();
            let mut mutator =
                ReplaceMatchMutator::new(c, &OPCUA_SIGNATURE, true, false, sw);
            let mut exact = 0u64; // one mutation reaches full attack
            let mut cert_done = 0u64; // step7 user-token certs all Alice (cert sub-goal)
            let mut key_done = 0u64; // step7 user-token key all Alice (key sub-goal)
            for _ in 0..n {
                let mut m = legit.clone();
                let _ = mutator.mutate(&mut state, &mut m);
                if recipes_eq(&m, &d0) { exact += 1; }
                if cnt7(&m, "fn_oscar_cert") == 0 && cnt7(&m, "fn_alice_cert") > 0 { cert_done += 1; }
                if cnt7(&m, "fn_oscar_sk") == 0 && cnt7(&m, "fn_alice_sk") > 0 { key_done += 1; }
            }
            println!("[{label:18}] P(exact attack)={:.5}  P(cert sub-goal)={:.5}  P(key sub-goal)={:.5}",
                exact as f64/n as f64, cert_done as f64/n as f64, key_done as f64/n as f64);
        }
        println!();
    }

    /// Shows the exact sub-term that must be mutated and how, plus the duplication that makes it
    /// unreachable by a single scoped mutation.
    /// Run: `cargo test -p opcuapuffin badswitch_show_replacement_site -- --nocapture`
    #[test]
    fn test_badswitch_show_replacement_site() {
        use puffin::fuzzer::utils::{find_all_term_filtered, find_term};

        let a = AgentName::first();
        let d1 = seed_bad_switch_cfg(a, true, true, false, false); // uts key = Mallory
        let d0 = seed_bad_switch_cfg(a, true, true, true, false); // uts key = Alice (attack)
        let constraints = TermConstraints::default();

        // The `switch_certificate` sub-term (2nd/switch activation) -- the REAL thing being edited.
        // d0 (attack) form; the only d1->d0 delta is the last fn_sign's key: fn_mallory_sk -> fn_alice_sk.
        let switch_certificate_d0 = term! {
            fn_activate_request(
                (fn_request_header(
                    ((a, 3)[Some(OpcuaQueryMatcher::CreateSessionResponse)]/NodeId),
                    fn_seq_5
                )),
                fn_basic256sha256,
                (fn_sign(                                   // clientSignature (stays Mallory)
                    (fn_signature_data(fn_bob_cert,
                        ((a, 0)[Some(OpcuaQueryMatcher::ActivateSessionResponse)]/ByteString))),
                    fn_basic256sha256, fn_mallory_cert, fn_mallory_sk
                )),
                (fn_user_cert(                              // user identity token
                    ((a, 0)[Some(OpcuaQueryMatcher::PolicyIdCertificate)]/UAString),
                    fn_alice_cert
                )),
                (fn_sign(                                   // userTokenSignature (the OOB trigger)
                    (fn_signature_data(fn_bob_cert,
                        ((a, 0)[Some(OpcuaQueryMatcher::ActivateSessionResponse)]/ByteString))),
                    fn_basic256sha256, fn_alice_cert, fn_alice_sk   // <-- key: d1 has fn_mallory_sk here
                ))
            )
        };
        println!("\n================ switch_certificate sub-term (the real recipe fragment) ================");
        println!("{switch_certificate_d0}");

        // Every place the duplicated leaf actually lives in the full trace:
        let sk_sites = find_all_term_filtered(&d0, |t| t.name() == fn_alice_sk.name(), &constraints);
        println!("\n================ the {} duplicated replacement sites (fn_alice_sk in d0) ================", sk_sites.len());
        for (i, p) in sk_sites.iter().enumerate() {
            let in_d1 = find_term(&d1, p).map(|t| t.name().rsplit("::").next().unwrap().to_string());
            let in_d0 = find_term(&d0, p).map(|t| t.name().rsplit("::").next().unwrap().to_string());
            println!("  site #{i}: path={:?}\n           d1: {:?}  ->  d0: {:?}", p, in_d1, in_d0);
        }
        println!(
            "\nAll {} sites are the SAME leaf, duplicated by @switch_certificate splicing (size field,\n\
             body, and the MAC-input copies). A correct mutation must flip ALL of them at once, while\n\
             leaving the other fn_mallory_sk (channel/MAC keys) untouched -- which no scope can do.\n",
            sk_sites.len()
        );
    }

    /// Prints the FULL switch message recipe (step 7) as puffin Displays it, before (legit d3)
    /// and after (attack d0). Run: `cargo test -p opcuapuffin badswitch_full_term -- --nocapture`
    #[test]
    fn test_badswitch_full_term() {
        let a = AgentName::first();
        let d3 = seed_bad_switch_cfg(a, false, false, false, false); // legit switch (all Mallory)
        let d0 = seed_bad_switch_cfg(a, true, true, true, false); // the attack (Alice identity)

        let recipe = |t: &TestTrace, i: usize| -> String {
            match &t.steps[i].action {
                Action::Input(inp) => format!("{}", inp.recipe),
                _ => String::from("<output step>"),
            }
        };
        let sw = 7usize; // the switch message step

        println!("\n################## BEFORE  (legit seed_f / d3, all-Mallory switch) — step {sw} ##################");
        println!("{}", recipe(&d3, sw));
        println!("\n################## AFTER   (attack d0, Alice user identity) — step {sw} ##################");
        println!("{}", recipe(&d0, sw));
        println!("\n################## END ##################\n");
    }

    /// Full legit(seed_f / d3, all-Mallory switch) -> attack(d0) delta table, with the trace paths
    /// of every identity leaf. Shows which leaves change, which stay, and where they live.
    /// Run: `cargo test -p opcuapuffin badswitch_delta_table -- --nocapture`
    #[test]
    fn test_badswitch_delta_table() {
        use puffin::algebra::Term;
        use puffin::fuzzer::utils::{find_all_term_filtered, find_term};

        let a = AgentName::first();
        let d3 = seed_bad_switch_cfg(a, false, false, false, false); // legit switch (== seed_f identity)
        let d0 = seed_bad_switch_cfg(a, true, true, true, false); // the crashing attack
        let c = TermConstraints::default();

        // Role of an identity leaf inside switch_certificate = last two indices of its term path:
        //   [2,2]=clientSig cert  [2,3]=clientSig key  [3,1]=user-token cert
        //   [4,2]=userTokenSig cert  [4,3]=userTokenSig key
        fn role(suffix: &[usize]) -> Option<&'static str> {
            match suffix {
                [2, 2] => Some("clientSignature cert"),
                [2, 3] => Some("clientSignature key"),
                [3, 1] => Some("user-token cert"),
                [4, 2] => Some("userTokenSignature cert"),
                [4, 3] => Some("userTokenSignature key"),
                _ => None,
            }
        }
        let short = |t: &Term<OpcuaProtocolTypes>| t.name().rsplit("::").next().unwrap().to_string();

        // Switch message step index (where switch_certificate lives). All its fn_alice_* end up here.
        let switch_step = find_all_term_filtered(&d0, |t| t.name().ends_with("fn_alice_sk"), &c)
            .into_iter()
            .map(|p| format!("{:?}", p.0))
            .next()
            .unwrap_or_default();

        let is_id = |t: &Term<OpcuaProtocolTypes>| {
            let n = t.name();
            n.ends_with("fn_mallory_cert") || n.ends_with("fn_alice_cert")
                || n.ends_with("fn_mallory_sk") || n.ends_with("fn_alice_sk")
        };
        // role -> (legit value, attack value, list of term-paths)
        let mut rows: std::collections::BTreeMap<&str, (String, String, Vec<Vec<usize>>)> =
            std::collections::BTreeMap::new();
        for p in find_all_term_filtered(&d0, is_id, &c) {
            if format!("{:?}", p.0) != switch_step {
                continue; // only the switch activation (skip the 1st activation & channel crypto)
            }
            let tp = &p.1;
            if tp.len() < 2 { continue; }
            if let Some(r) = role(&tp[tp.len() - 2..]) {
                let d3v = find_term(&d3, &p).map(&short).unwrap_or_default();
                let d0v = find_term(&d0, &p).map(&short).unwrap_or_default();
                let e = rows.entry(r).or_insert((d3v, d0v, vec![]));
                e.2.push(tp.clone());
            }
        }

        println!("\n=========== legit seed_f (d3) -> attack (d0): identity leaves of switch_certificate (step {switch_step}) ===========");
        println!("{:<26} {:<16} {:<16} {:<8} {}", "role", "legit (d3)", "attack (d0)", "change?", "#copies / term-paths");
        for (r, (d3v, d0v, paths)) in &rows {
            let changed = if d3v != d0v { "CHANGE" } else { "keep" };
            println!("{:<26} {:<16} {:<16} {:<8} {}", r, d3v, d0v, changed, paths.len());
            for tp in paths {
                println!("        {tp:?}");
            }
        }
        println!();
    }

    /// Isolated probability experiment for the bad-switch attack: measure how often a SINGLE
    /// `ReplaceMatchMutator` application turns the d1 seed (one leaf short of the attack) into the
    /// exact crashing trace d0. Pure structural (no PUT/vendor needed): d1 and d0 differ only in
    /// the userTokenSignature signing key (`fn_mallory_sk` -> `fn_alice_sk`), so the "appropriate
    /// mutation" is exactly `mutant == d0`.
    ///
    /// Run: `cargo test -p opcuapuffin badswitch_mutation_probability -- --nocapture`
    #[test]
    fn test_badswitch_mutation_probability() {
        use puffin::fuzzer::utils::{find_all_term_filtered, find_term_mut};

        // Compare the RECIPE terms only (Term: PartialEq). NOT the whole Step/Trace: InputAction
        // also carries `precomputations` and the trace carries metadata, which mutate() vs a fresh
        // build populate differently -> those would spuriously differ even for an identical recipe.
        fn recipes_eq(a: &TestTrace, b: &TestTrace) -> bool {
            a.steps.len() == b.steps.len()
                && a.steps.iter().zip(&b.steps).all(|(x, y)| match (&x.action, &y.action) {
                    (Action::Input(xi), Action::Input(yi)) => xi.recipe == yi.recipe,
                    _ => false,
                })
        }

        let a = AgentName::first();
        let d1 = seed_bad_switch_cfg(a, true, true, false, false); // uts key still Mallory
        let d0 = seed_bad_switch_cfg(a, true, true, true, false); // the crashing attack
        assert!(!recipes_eq(&d1, &d0), "d1 must differ from d0 (only the uts signing-key leaf)");

        let constraints = TermConstraints::default();
        let n_mallory_sk =
            find_all_term_filtered(&d1, |t| t.name() == fn_mallory_sk.name(), &constraints).len();
        let total_nodes = d1.size();
        println!(
            "\n=== bad-switch d1->d0 single-mutation probability ===\n\
             d1 has {n_mallory_sk} fn_mallory_sk leaves (identical to the target) out of {total_nodes} nodes"
        );

        // REACHABILITY DIAGNOSTIC: does term-selection (the same collect_subterms the mutator uses)
        // even SEE the Alice identity leaves? d0 has 1 fn_alice_sk (uts key) + 2 fn_alice_cert
        // (user_cert + uts cert). If find_all reports fewer, those leaves are UNREACHABLE by the
        // mutator (non-symbolic / too-deep ancestor -> not selectable).
        let seen_alice_sk_d0 =
            find_all_term_filtered(&d0, |t| t.name() == fn_alice_sk.name(), &constraints).len();
        let seen_alice_cert_d0 =
            find_all_term_filtered(&d0, |t| t.name() == fn_alice_cert.name(), &constraints).len();
        let seen_mallory_sk_d0 =
            find_all_term_filtered(&d0, |t| t.name() == fn_mallory_sk.name(), &constraints).len();
        println!(
            "REACHABILITY (via find_all/collect_subterms, same selection the mutator uses):\n\
             d0 selectable fn_alice_sk = {seen_alice_sk_d0} (built-in: 1 at uts key)\n\
             d0 selectable fn_alice_cert = {seen_alice_cert_d0} (built-in: 2: user_cert + uts cert)\n\
             d0 selectable fn_mallory_sk = {seen_mallory_sk_d0}"
        );

        // Manual per-leaf swap over the SELECTABLE mallory_sk leaves: how many reproduce d0?
        let alice_sk_term = term! { fn_alice_sk };
        let paths = find_all_term_filtered(&d1, |t| t.name() == fn_mallory_sk.name(), &constraints);
        let mut manual_hits = 0usize;
        for p in &paths {
            let mut m = d1.clone();
            if let Some(tm) = find_term_mut(&mut m, p) {
                tm.mutate(alice_sk_term.clone());
            }
            if recipes_eq(&m, &d0) {
                manual_hits += 1;
            }
        }
        println!(
            "manual swap over {} SELECTABLE mallory_sk leaves: {manual_hits} reproduce d0",
            paths.len()
        );

        let n: u64 = 50_000;
        for (label, sw) in [
            ("default scope (1,1,1)", ScopeWeights::new(1, 1, 1)),
            ("individual only (0,0,1)", ScopeWeights::new(0, 0, 1)),
        ] {
            let mut state = create_state();
            let mut mutator =
                ReplaceMatchMutator::new(constraints, &OPCUA_SIGNATURE, true, false, sw);
            let mut exact = 0u64; // recipe == d0 (the appropriate mutation)
            let mut any_alice_sk = 0u64; // introduced >=1 fn_alice_sk anywhere
            for _ in 0..n {
                let mut m = d1.clone();
                let _ = mutator.mutate(&mut state, &mut m);
                if recipes_eq(&m, &d0) {
                    exact += 1;
                }
                if find_all_term_filtered(&m, |t| t.name() == fn_alice_sk.name(), &constraints).len() >= 1 {
                    any_alice_sk += 1;
                }
            }
            println!(
                "[{label:24}] P(exact d0) = {exact}/{n} = {:.6}   P(any fn_alice_sk introduced) = {any_alice_sk}/{n} = {:.6}",
                exact as f64 / n as f64,
                any_alice_sk as f64 / n as f64,
            );
        }
        println!("(ReplaceMatch is 1 of 7 fuzzer mutators; campaign probability further divided by scheduling + corpus size.)\n");
    }
}
