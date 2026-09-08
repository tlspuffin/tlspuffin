//! Implementation of special traces, used to start the fuzzing.
//! Each may represent a special execution of OPC UA, like a full handshake
//! or the execution of a known attack.
#![allow(dead_code)]

use opcua::puffin::messages::EncryptedBody;
use opcua::puffin::query::OpcuaQueryMatcher;
use opcua::puffin::signature::fn_impl::*;
use opcua::puffin::signature::{fn_acknowledge, fn_client_hello, fn_server_hello};
use opcua::puffin::types::{ApplicationConfig, OpcuaProtocolTypes};
use opcua::types::{ByteString, NodeId, UAString};
use puffin::agent::AgentName;
use puffin::trace::{Action, InputAction, Step, Trace};
use puffin::{input_action, term};

use crate::protocol::OpcuaProtocolBehavior;

/// Initial fuzzing corpus.
///
/// The corpus is intentionally made of **legitimate** OPC UA traces only — a spread of valid
/// handshake / session / channel exchanges. The fuzzer is meant to *discover* vulnerabilities by
/// mutating these benign starting points; seeding it with a trace that already triggers a known
/// bug would defeat that purpose (it would "find" the planted bug trivially and skew time-to-find
/// measurements).
///
/// The bug-targeting seeds below are therefore **commented out on purpose**. They reproduce
/// deliberately *planted* defects and only crash when the open62541 vendor is built with the
/// matching patch (see `puffin-build/vendors/open62541/builder.cmake`, where those patches are
/// disabled by default). Uncomment one only for a targeted reproduction against a vendor built
/// with its patch — never for a normal fuzzing campaign:
///   - `seed_bad_switch`        → `Bug-bad-switch.patch`   (OOB write in `Service_ActivateSession`)
///   - `seed_bug_dead_session`  → `Bug-dead-session.patch` (activation of a dead session)
pub fn create_corpus(
    _put: &dyn puffin::put_registry::Factory<OpcuaProtocolBehavior>,
) -> Vec<(Trace<OpcuaProtocolTypes>, &'static str)> {
    let a = AgentName::first();
    // --- Legitimate seeds (the actual fuzzing corpus) ---
    let mut corpus: Vec<(Trace<OpcuaProtocolTypes>, &'static str)> = vec![
        (seed_a_hello_bob(a), "seed_a_hello_bob"),
        (
            seed_ap_client_open_unsecure_channel(a),
            "seed_ap_client_open_unsecure_channel",
        ),
        (
            seed_b_client_open_secure_channel(a),
            "seed_b_client_open_secure_channel",
        ),
        (
            seed_c_server_open_unsecure_channel(a),
            "seed_c_server_open_unsecure_channel",
        ),
        (seed_d_client_simple_request(a), "seed_d_client_simple_request"),
        (
            seed_e_client_reopen_reactivate(a),
            "seed_e_client_reopen_reactivate",
        ),
        (
            seed_f_client_switch_secure_channels(a),
            "seed_f_client_switch_secure_channels",
        ),
    ];

    // Seed-distance (dichotomy) evaluation: LADDER_RUNG injects ONE pre-baked
    // intermediate switch-seed between seed_f (legit switch, all-Mallory) and the
    // TRIGGERING bad-switch attack. Empirically only the 3-Alice-leaf variant
    // (user_cert=Alice AND userTokenSignature=Alice) fires the OOB in
    // Service_ActivateSession; the Mallory-user_cert variant does NOT. So distances
    // are counted from that 3-leaf attack:
    //   d0  = attack        (uc=T, uts_cert=T, uts_key=T)  -> should crash at once
    //   d1  = needs uts key (uc=T, uts_cert=T, uts_key=F)
    //   d2  = needs uts c+k (uc=T, uts_cert=F, uts_key=F)
    //   d3  = seed_f-equiv  (uc=F, uts_cert=F, uts_key=F)  -> needs all 3
    //   allalice = over-replace clientSig too (uc=T, uts_cert=T, uts_key=T, csig=T)
    use crate::opcua::vulnerabilities::{make_user_oscar, seed_bad_switch_cfg};

    // DISTINCT_ALL: make EVERY legit seed use a user-token identity (Oscar) distinct from the
    // application/channel identity (Mallory). Realistic (app cert != user identity) AND it lets a
    // single per-step scoped mutation flip just the user token -- the shared-identity seeds cannot.
    if std::env::var("DISTINCT_ALL").is_ok() {
        for (t, _) in corpus.iter_mut() {
            make_user_oscar(t);
        }
    }

    match std::env::var("LADDER_RUNG").as_deref() {
        Ok("d0") => corpus.push((seed_bad_switch_cfg(a, true, true, true, false), "ladder_d0_attack")),
        Ok("d1") => corpus.push((seed_bad_switch_cfg(a, true, true, false, false), "ladder_d1")),
        Ok("d2") => corpus.push((seed_bad_switch_cfg(a, true, false, false, false), "ladder_d2")),
        Ok("d3") => corpus.push((seed_bad_switch_cfg(a, false, false, false, false), "ladder_d3_legitswitch")),
        Ok("allalice") => {
            corpus.push((seed_bad_switch_cfg(a, true, true, true, true), "ladder_allalice"))
        }
        // Distinct client (Oscar) vs user-token (Mallory) identity: mallory now marks ONLY the user
        // token, so a single per-step scoped mallory->alice should reach the bug.
        Ok("distinct_legit") => {
            let mut t = seed_bad_switch_cfg(a, false, false, false, false); // user token Mallory -> Oscar
            make_user_oscar(&mut t);
            corpus.push((t, "distinct_legit"));
        }
        Ok("distinct_d0") => {
            // switch user = Alice; activate#1 user Mallory -> Oscar. => stored=Oscar, switch=Alice => bug.
            let mut t = seed_bad_switch_cfg(a, true, true, true, false);
            make_user_oscar(&mut t);
            corpus.push((t, "distinct_d0_attack"));
        }
        // Intermediate distinct-identity rungs: with distinct identity the attack = 2 safe swaps
        // (user-token cert Oscar->Alice, user-token key Oscar->Alice). These pre-bake ONE swap so the
        // fuzzer needs only the other (isolates single-swap findability from the 2-swap combo).
        Ok("distinct_d1key") => {
            // certs already Alice; key still Oscar -> fuzzer needs only oscar_sk -> alice_sk.
            let mut t = seed_bad_switch_cfg(a, true, true, false, false);
            make_user_oscar(&mut t); // uts_key was Mallory -> Oscar
            corpus.push((t, "distinct_d1key"));
        }
        Ok("distinct_d1cert") => {
            // key already Alice; certs still Oscar -> fuzzer needs only oscar_cert -> alice_cert.
            let mut t = seed_bad_switch_cfg(a, false, false, true, false);
            make_user_oscar(&mut t); // uc + uts_cert were Mallory -> Oscar
            corpus.push((t, "distinct_d1cert"));
        }
        _ => {}
    }
    corpus
}

pub fn seed_a_hello_bob(server: AgentName) -> Trace<OpcuaProtocolTypes> {
    Trace {
        prior_traces: vec![],
        metadata_trace: Default::default(),
        descriptors: vec![ApplicationConfig::new_server(server)],
        steps: vec![Step {
            agent: server,
            action: Action::Input(input_action! { term! {
                fn_client_hello (
                    fn_tcp_1,
                    fn_bob_endpoint,
                    fn_default_size,
                    fn_default_size
                )}
            }),
        }],
    }
}

pub fn seed_ap_client_open_unsecure_channel(server: AgentName) -> Trace<OpcuaProtocolTypes> {
    let open_request = term! {
        fn_service(
            (fn_sequence_header(fn_seq_0, fn_seq_0)),
            (fn_client_open(
                (fn_request_header(fn_sa_token_zero, fn_seq_0)),
                fn_issue,
                fn_mode_none,
                fn_no_nonce
            ))
        )
    };
    let close_request = term! {
        fn_service(
            (fn_sequence_header(fn_seq_0, fn_seq_0)),
            (fn_client_close(
                (fn_request_header(fn_sa_token_zero, fn_seq_0))
            ))
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
                    fn_open_message(
                        fn_tcp_1,
                        (fn_open_header(
                            (fn_header(fn_open, fn_seq_0)),
                            fn_security_policy_none,
                            fn_null_cert,
                            fn_null_cert,
                            (@open_request)
                        )),
                        (fn_asym_header(
                            fn_security_policy_none,
                            fn_null_cert,
                            fn_null_cert
                        )),
                        (fn_asym_encrypt(
                            fn_security_policy_none,
                            fn_null_cert,
                            (fn_data_to_encrypt(
                                fn_security_policy_none,
                                fn_null_cert,
                                (@open_request),
                                fn_no_bytes
                            ))
                        ))
                    )
                }}),
            },
            Step {
                agent: server,
                action: Action::Input(input_action! { term! {
                    fn_message (
                        fn_tcp_1,
                        (fn_msg_header(
                            fn_security_policy_none,
                            (fn_header(
                                fn_close, // needs channel id:
                                ((server, 1)[Some(OpcuaQueryMatcher::OpenSecureChannelResponse)]/u32))))),
                        (fn_body(
                            (fn_get_channel_token(
                                (fn_decrypted_body(
                                    (fn_asym_decrypt(
                                        fn_security_policy_none,
                                        ((server, 1)[None]/EncryptedBody),
                                        fn_no_bytes)),
                                    fn_no_bytes
                                ))
                            )),
                            (fn_sequence_header(fn_seq_1, fn_seq_1)),
                            (fn_client_close(
                                (fn_request_header(fn_sa_token_zero, fn_seq_1))
                            )),
                            fn_no_bytes
                        ))
                    )
                    }
                }),
            },
        ],
    }
}

pub fn seed_b_client_open_secure_channel(server: AgentName) -> Trace<OpcuaProtocolTypes> {
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
    let close_request = term! {
        fn_service(
            (fn_sequence_header(fn_seq_1, fn_seq_1)),
            (fn_client_close(
                (fn_request_header(fn_sa_token_zero, fn_seq_1))
            ))
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
                            (fn_sequence_header(fn_seq_1, fn_seq_1)),
                            (fn_client_close(
                                (fn_request_header(fn_sa_token_zero, fn_seq_1))
                            )),
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
                                    (@close_request)
                                )),
                                fn_basic256sha256,
                                (fn_client_mac_key(
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
                                ))
                            ))
                        ))
                    )
                    }
                }),
            },
        ],
    }
}

pub fn seed_c_server_open_unsecure_channel(client: AgentName) -> Trace<OpcuaProtocolTypes> {
    let open_response = term! {
        fn_service(
            (fn_sequence_header(fn_seq_0, fn_seq_0)), // needs request id! (2)
            (fn_server_open(
                (fn_response_header(fn_seq_0)), // needs request id!
                fn_seq_1,  // channel id 1,
                fn_seq_1,  // channel token 1
                fn_no_nonce
            ))
        )
    };
    let get_endpoints_response = term! {
        fn_endpoints(
                (fn_response_header(fn_seq_2)) // request id
        )
    };
    let close_response = term! {
        fn_server_close(
                (fn_response_header(fn_seq_3)) // request id
        )
    };

    Trace {
        prior_traces: vec![],
        metadata_trace: Default::default(),
        descriptors: vec![ApplicationConfig::new_client(client)],
        steps: vec![
            Step {
                agent: client,
                action: Action::Input(input_action! { term! {
                    fn_server_hello (
                        fn_tcp_1,
                        fn_oscar_uri,
                        fn_oscar_endpoint
                    )}
                }),
            },
            // We expect here a "hello Oscar" from the client!
            Step {
                agent: client,
                action: Action::Input(input_action! { term! {
                    fn_acknowledge(
                        fn_tcp_1,
                        fn_default_size,
                        fn_default_size
                    )}
                }),
            },
            // We expect here an Open Secure Channel request from the client!
            Step {
                agent: client,
                action: Action::Input(input_action! { term! {
                    fn_open_message(
                        fn_tcp_1,
                        (fn_open_header(
                            (fn_header(fn_open, fn_seq_1)),  // channel id 1
                            fn_security_policy_none,
                            fn_null_cert,
                            fn_null_cert,
                            (@open_response)
                        )),
                        (fn_asym_header(
                            fn_security_policy_none,
                            fn_null_cert,
                            fn_null_cert
                        )),
                        (fn_asym_encrypt(
                            fn_security_policy_none,
                            fn_null_cert,
                            (fn_data_to_encrypt(
                                fn_security_policy_none,
                                fn_null_cert,
                                (@open_response),
                                fn_no_bytes
                            ))
                        ))
                    )
                }}),
            },
            // We expect here a Get Endpoints Request from the client!
            Step {
                agent: client,
                action: Action::Input(input_action! { term! {
                    fn_message(
                        fn_tcp_1,
                        (fn_msg_header(
                            fn_security_policy_none,
                            (fn_header(fn_final, fn_seq_1)))),
                        (fn_body(
                            (fn_channel_token(fn_seq_1)),
                            (fn_sequence_header(fn_seq_1, fn_seq_2)),
                            (@get_endpoints_response),
                            fn_no_bytes
                        ))
                    )
                }}),
            },
            // We expect a close secure channel from the client!
            Step {
                agent: client,
                action: Action::Input(input_action! { term! {
                    fn_message(
                        fn_tcp_1,
                        (fn_msg_header(
                            fn_security_policy_none,
                            (fn_header(fn_final, fn_seq_1)))),
                        (fn_body(
                            (fn_channel_token(fn_seq_1)),
                            (fn_sequence_header(fn_seq_1, fn_seq_3)),
                            (@close_response),
                            fn_no_bytes
                        ))
                    )
                }}),
            },
        ],
    }
}

pub fn seed_d_client_simple_request(server: AgentName) -> Trace<OpcuaProtocolTypes> {
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
    let _activate_anonymous = term! {
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
            (fn_anonymous(
                ((server, 0)[Some(OpcuaQueryMatcher::PolicyIdAnonymous)]/UAString) // PolicyId!
            )),
            fn_no_bytes
        )
    };
    let _activate_password = term! {
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
            (fn_legacy_user_pwd(
                ((server, 0)[Some(OpcuaQueryMatcher::PolicyIdPassword)]/UAString), // PolicyId!
                fn_basic256sha256,
                fn_username,
                fn_password,
                fn_bob_cert,
                ((server, 0)[None]/ByteString)
            )),
            fn_no_bytes
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
    let close_channel = term! {
        fn_client_close(
            (fn_request_header(
                ((server, 3)[Some(OpcuaQueryMatcher::CreateSessionResponse)]/NodeId), // SA_Token!
                fn_seq_5))
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
                            (fn_header(fn_close,
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
                            (@close_channel),
                            (fn_mac(
                                (fn_data_to_mac(
                            fn_basic256sha256,
                                    (fn_msg_header(
                                        fn_basic256sha256,
                                        (fn_header(fn_close,
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
                                        (fn_sequence_header(fn_seq_5, fn_seq_5)),
                                        (@close_channel)
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

pub fn seed_e_client_reopen_reactivate(server: AgentName) -> Trace<OpcuaProtocolTypes> {
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
    let activate_anonymous = term! {
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
            (fn_anonymous(
                ((server, 0)[Some(OpcuaQueryMatcher::PolicyIdAnonymous)]/UAString) // PolicyId!
            )),
            fn_no_bytes
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
    let reopen_request = term! {
        fn_service(
            (fn_sequence_header(fn_seq_4, fn_seq_4)),
            (fn_client_open(
                (fn_request_header(
                    ((server, 3)[Some(OpcuaQueryMatcher::CreateSessionResponse)]/NodeId), // SA_Token!
                    fn_seq_4
                )),
                fn_renew,
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
    let activate_certificate = term! {
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
              fn_oscar_cert
            )),
            (fn_sign(
                (fn_signature_data(
                    fn_bob_cert,
                    ((server, 0)[Some(OpcuaQueryMatcher::ActivateSessionResponse)]/ByteString) // S_nonce!
                )),
                fn_basic256sha256,
                fn_oscar_cert,
                fn_oscar_sk
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
    let close_channel = term! {
        fn_client_close(
            (fn_request_header(
                ((server, 3)[Some(OpcuaQueryMatcher::CreateSessionResponse)]/NodeId), // SA_Token!
                fn_seq_7))
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
                    fn_open_message(
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
                            (@activate_anonymous),
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
                                        (@activate_anonymous)
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
            /* reopen secure channel */
            Step {
                agent: server,
                action: Action::Input(input_action! { term! {
                    fn_open_message(
                        fn_tcp_1,
                        (fn_open_header(
                            (fn_header(fn_open,
                                ((server, 1)[Some(OpcuaQueryMatcher::OpenSecureChannelResponse)]/u32))),
                            fn_basic256sha256,
                            fn_mallory_cert,
                            fn_bob_cert,
                            (@reopen_request)
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
                                (@reopen_request),
                                (fn_sign(
                                    (fn_data_to_sign(
                                        (fn_open_header(
                                            (fn_header(fn_open,
                                                ((server, 1)[Some(OpcuaQueryMatcher::OpenSecureChannelResponse)]/u32))),
                                            fn_basic256sha256,
                                            fn_mallory_cert,
                                            fn_bob_cert,
                                            (@reopen_request)
                                        )),
                                        fn_basic256sha256,
                                        fn_mallory_cert,
                                        fn_bob_cert,
                                        (@reopen_request)
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
            /* Reactivate session */
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
                                        ((server, 2)[None]/EncryptedBody),
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
                                                ((server, 2)[None]/EncryptedBody),
                                                fn_mallory_sk)),
                                            fn_mallory_sk
                                        ))
                                    )),
                                    (fn_service(
                                        (fn_sequence_header(fn_seq_5, fn_seq_5)),
                                        (@activate_certificate)
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
                                            ((server, 1)[Some(OpcuaQueryMatcher::OpenSecureChannelResponse)]/u32))))),
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
                        fn_tcp_1,
                        (fn_msg_header(
                            fn_basic256sha256,
                            (fn_header(fn_close,
                                ((server, 1)[Some(OpcuaQueryMatcher::OpenSecureChannelResponse)]/u32))))),
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
                            (@close_channel),
                            (fn_mac(
                                (fn_data_to_mac(
                            fn_basic256sha256,
                                    (fn_msg_header(
                                        fn_basic256sha256,
                                        (fn_header(fn_close,
                                            ((server, 1)[Some(OpcuaQueryMatcher::OpenSecureChannelResponse)]/u32))))),
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
                                        (@close_channel)
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

pub fn seed_f_client_switch_secure_channels(server: AgentName) -> Trace<OpcuaProtocolTypes> {
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
              fn_oscar_cert
            )),
            (fn_sign(
                (fn_signature_data(
                    fn_bob_cert,
                    ((server, 0)[Some(OpcuaQueryMatcher::ActivateSessionResponse)]/ByteString) // S_nonce!
                )),
                fn_basic256sha256,
                fn_oscar_cert,
                fn_oscar_sk
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

#[cfg(test)]
pub mod tests {

    use puffin::trace_helper::TraceHelper;

    #[allow(unused_imports)]
    use super::*;

    fn test_postcard_serialization(trace: Trace<OpcuaProtocolTypes>) {
        let serialized1 = trace.serialize_postcard().unwrap();
        let deserialized_trace =
            Trace::<OpcuaProtocolTypes>::deserialize_postcard(&serialized1.as_ref()).unwrap();
        let serialized2 = deserialized_trace.serialize_postcard().unwrap();
        assert_eq!(serialized1, serialized2);
    }

    #[test]
    fn test_postcard_of_seed_a() {
        let trace = seed_a_hello_bob.build_trace();
        test_postcard_serialization(trace);
    }

    #[test]
    fn test_postcard_of_seed_ap() {
        let trace = seed_ap_client_open_unsecure_channel.build_trace();
        test_postcard_serialization(trace);
    }

    #[test]
    fn test_postcard_of_seed_b() {
        let trace = seed_b_client_open_secure_channel.build_trace();
        test_postcard_serialization(trace);
    }

    #[test]
    fn test_postcard_of_seed_c() {
        let trace = seed_c_server_open_unsecure_channel.build_trace();
        test_postcard_serialization(trace);
    }

    #[test]
    fn test_postcard_of_seed_d() {
        let trace = seed_d_client_simple_request.build_trace();
        test_postcard_serialization(trace);
    }

    #[test]
    fn test_postcard_of_seed_e() {
        let trace = seed_e_client_reopen_reactivate.build_trace();
        test_postcard_serialization(trace);
    }

    #[test]
    fn test_postcard_of_seed_f() {
        let trace = seed_f_client_switch_secure_channels.build_trace();
        test_postcard_serialization(trace);
    }
}
