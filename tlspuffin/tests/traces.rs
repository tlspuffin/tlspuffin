use puffin::agent::AgentName;
use puffin::trace::{Action, InputAction, OutputAction, Step, Trace};
use puffin::{input_action, term};
use tlspuffin::protocol::{MessageFlight, TLSDescriptorConfig, TLSProtocolTypes, TLSVersion};
use tlspuffin::query::TlsQueryMatcher;
use tlspuffin::tls::fn_impl::*;
use tlspuffin::tls::rustls::msgs::enums::HandshakeType;

fn seed_successful_12_both(client12: AgentName, server: AgentName) -> Trace<TLSProtocolTypes> {
    Trace {
        prior_traces: vec![],
        descriptors: vec![
            TLSDescriptorConfig::new_client(client12, TLSVersion::V1_2),
            TLSDescriptorConfig::new_server(server, TLSVersion::Both),
        ],
        steps: vec![
            // ── TLS 1.2 handshake: client12 ↔ server ──────────────────────────────
            OutputAction::new_step(client12),
            // ClientHello → Server
            Step {
                agent: server,
                action: Action::Input(input_action! { term! { (client12, 0)/MessageFlight } }),
            },
            // ServerHello + Certificate + ServerKeyExchange + ServerHelloDone → Client12
            Step {
                agent: client12,
                action: Action::Input(input_action! { term! { (server, 0)/MessageFlight } }),
            },
            // ClientKeyExchange + ChangeCipherSpec + Finished → Server
            Step {
                agent: server,
                action: Action::Input(input_action! { term! { (client12, 1)/MessageFlight } }),
            },
            // ChangeCipherSpec + Finished → Client12
            Step {
                agent: client12,
                action: Action::Input(input_action! { term! { (server, 1)/MessageFlight } }),
            },
        ],
        ..Default::default()
    }
}

fn seed_successful_13_both(client13: AgentName, server: AgentName) -> Trace<TLSProtocolTypes> {
    Trace {
        prior_traces: vec![],
        descriptors: vec![
            TLSDescriptorConfig::new_client(client13, TLSVersion::V1_3),
            TLSDescriptorConfig::new_server(server, TLSVersion::Both),
        ],
        steps: vec![
            // ── TLS 1.3 handshake: client13 ↔ server ──────────────────────────────
            OutputAction::new_step(client13),
            // ClientHello → Server
            Step {
                agent: server,
                action: Action::Input(input_action! { term! { (client13, 0)/MessageFlight } }),
            },
            // ServerHello + EncryptedExtensions + Certificate + CertificateVerify + Finished →
            // Client13
            Step {
                agent: client13,
                action: Action::Input(input_action! { term! { (server, 0)/MessageFlight } }),
            },
            // Finished → Server
            Step {
                agent: server,
                action: Action::Input(input_action! { term! { (client13, 1)/MessageFlight } }),
            },
        ],
        ..Default::default()
    }
}

fn seed_successful_both_13(client: AgentName, server13: AgentName) -> Trace<TLSProtocolTypes> {
    Trace {
        prior_traces: vec![],
        descriptors: vec![
            TLSDescriptorConfig::new_client(client, TLSVersion::Both),
            TLSDescriptorConfig::new_server(server13, TLSVersion::V1_3),
        ],
        steps: vec![
            // ── TLS 1.3 handshake: client ↔ server13 ──────────────────────────────
            OutputAction::new_step(client),
            // ClientHello → Server
            Step {
                agent: server13,
                action: Action::Input(input_action! { term! { (client, 0)/MessageFlight } }),
            },
            // ServerHello + EncryptedExtensions + Certificate + CertificateVerify + Finished →
            // Client13
            Step {
                agent: client,
                action: Action::Input(input_action! { term! { (server13, 0)/MessageFlight } }),
            },
            // Finished → Server
            Step {
                agent: server13,
                action: Action::Input(input_action! { term! { (client, 1)/MessageFlight } }),
            },
        ],
        ..Default::default()
    }
}

fn seed_successful_both_12(client: AgentName, server12: AgentName) -> Trace<TLSProtocolTypes> {
    Trace {
        prior_traces: vec![],
        descriptors: vec![
            TLSDescriptorConfig::new_client(client, TLSVersion::Both),
            TLSDescriptorConfig::new_server(server12, TLSVersion::V1_2),
        ],
        steps: vec![
            // ── TLS 1.2 handshake: client ↔ server12 ──────────────────────────────
            OutputAction::new_step(client),
            // ClientHello → Server
            Step {
                agent: server12,
                action: Action::Input(input_action! { term! { (client, 0)/MessageFlight } }),
            },
            // ServerHello + Certificate + ServerKeyExchange + ServerHelloDone → Client12
            Step {
                agent: client,
                action: Action::Input(input_action! { term! { (server12, 0)/MessageFlight } }),
            },
            // ClientKeyExchange + ChangeCipherSpec + Finished → Server
            Step {
                agent: server12,
                action: Action::Input(input_action! { term! { (client, 1)/MessageFlight } }),
            },
            // ChangeCipherSpec + Finished → Client12
            Step {
                agent: client,
                action: Action::Input(input_action! { term! { (server12, 1)/MessageFlight } }),
            },
        ],
        ..Default::default()
    }
}

fn seed_error_12_13(client12: AgentName, server13: AgentName) -> Trace<TLSProtocolTypes> {
    Trace {
        prior_traces: vec![],
        descriptors: vec![
            TLSDescriptorConfig::new_client(client12, TLSVersion::V1_2),
            TLSDescriptorConfig::new_server(server13, TLSVersion::V1_3),
        ],
        steps: vec![
            // ── TLS 1.2 handshake: client12 ↔ server13 ──────────────────────────────
            OutputAction::new_step(client12),
            // ClientHello → server13
            Step {
                agent: server13,
                action: Action::Input(input_action! { term! { (client12, 0)/MessageFlight } }),
            },
            // ServerHello + Certificate + ServerKeyExchange + ServerHelloDone → Client12
            Step {
                agent: client12,
                action: Action::Input(input_action! { term! { (server13, 0)/MessageFlight } }),
            },
        ],
        ..Default::default()
    }
}

fn seed_error_13_12(client13: AgentName, server12: AgentName) -> Trace<TLSProtocolTypes> {
    Trace {
        prior_traces: vec![],
        descriptors: vec![
            TLSDescriptorConfig::new_client(client13, TLSVersion::V1_3),
            TLSDescriptorConfig::new_server(server12, TLSVersion::V1_2),
        ],
        steps: vec![
            // ── TLS 1.2 handshake: client12 ↔ server13 ──────────────────────────────
            OutputAction::new_step(client13),
            // ClientHello → server13
            Step {
                agent: server12,
                action: Action::Input(input_action! { term! { (client13, 0)/MessageFlight } }),
            },
            // ServerHello + Certificate + ServerKeyExchange + ServerHelloDone → Client12
            Step {
                agent: client13,
                action: Action::Input(input_action! { term! { (server12, 0)/MessageFlight } }),
            },
            // ClientKeyExchange + ChangeCipherSpec + Finished → Server
            Step {
                agent: server12,
                action: Action::Input(input_action! { term! { (client13, 1)/MessageFlight } }),
            },
            // ChangeCipherSpec + Finished → Client12
            Step {
                agent: client13,
                action: Action::Input(input_action! { term! { (server12, 1)/MessageFlight } }),
            },
        ],
        ..Default::default()
    }
}

fn seed_successful_12_then_13(server: AgentName) -> Trace<TLSProtocolTypes> {
    // -- TLS 1.2 terms
    let client_hello12 = term! {
          fn_client_hello(
            fn_protocol_version12,
            fn_new_random,
            fn_new_session_id,
            (fn_cipher_suites_make(
                (fn_append_cipher_suite(
                  (fn_new_cipher_suites()),
                  // force TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
                  fn_cipher_suite12
            )))),
            fn_compressions,
            (fn_client_extensions_make(
            (fn_client_extensions_append(
                (fn_client_extensions_append(
                    (fn_client_extensions_append(
                        (fn_client_extensions_append(
                            (fn_client_extensions_append(
                                (fn_client_extensions_append(
                                    fn_client_extensions_new,
                                    (fn_support_group_extension_make(
                                        (fn_support_group_extension_append(
                                            fn_support_group_extension_new,
                                            fn_named_group_secp384r1
                                        ))
                                    ))
                                )),
                                fn_signature_algorithm_extension
                            )),
                            fn_ec_point_formats_extension
                        )),
                        fn_signed_certificate_timestamp_extension
                    )),
                     // Enable Renegotiation
                    (fn_renegotiation_info_extension((fn_payload_u8(fn_empty_bytes_vec))))
                )),
                // Add signature cert extension
                fn_signature_algorithm_cert_extension
            ))
        )))
    };

    let server_hello_transcript12 = term! {
        fn_append_transcript(
            (fn_append_transcript(
                fn_new_transcript12,
                (@client_hello12) // ClientHello
            )),
            ((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerHello)))]) // plaintext ServerHello
        )
    };

    let certificate_transcript12 = term! {
        fn_append_transcript(
            (@server_hello_transcript12),
            ((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::Certificate)))]) // Certificate
        )
    };

    let server_key_exchange_transcript12 = term! {
      fn_append_transcript(
            (@certificate_transcript12),
            ((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerKeyExchange)))]) // ServerKeyExchange
        )
    };

    let server_hello_done_transcript12 = term! {
      fn_append_transcript(
            (@server_key_exchange_transcript12),
            ((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerHelloDone)))]) // ServerHelloDone
        )
    };

    let client_key_exchange12 = term! {
        fn_client_key_exchange(
            (fn_encode_ec_pubkey12(
                (fn_payload_u8((fn_new_pubkey12(fn_named_group_secp384r1))))
            ))
        )
    };

    let client_key_exchange_transcript12 = term! {
      fn_append_transcript(
            (@server_hello_done_transcript12),
            (@client_key_exchange12)
        )
    };

    let client_verify_data12 = term! {
        fn_client_sign_transcript(
            ((server, 0)),
            (fn_decode_server_ecdh_pubkey(
                ((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerKeyExchange)))]/Vec<u8>) // ServerECDHParams
            )),
            (@client_key_exchange_transcript12),
            fn_named_group_secp384r1,
            fn_new_random,
            fn_cipher_suite12
        )
    };

    // --- TLS 1.3 terms
    let client_hello13 = term! {
          fn_client_hello(
            fn_protocol_version12,
            fn_new_random,
            fn_new_session_id,
            (fn_cipher_suites_make(
                 (fn_append_cipher_suite(
                  (fn_new_cipher_suites()),
                   fn_cipher_suite13_aes_128_gcm_sha256
            )))),
            fn_compressions,
            (fn_client_extensions_make(
                (fn_client_extensions_append(
                (fn_client_extensions_append(
                    (fn_client_extensions_append(
                        (fn_client_extensions_append(
                            fn_client_extensions_new,
                            (fn_support_group_extension_make(
                                (fn_support_group_extension_append(
                                    fn_support_group_extension_new,
                                    fn_named_group_secp384r1
                                ))
                            ))
                        )),
                        fn_signature_algorithm_extension
                    )),
                    (fn_key_share_deterministic_extension(fn_named_group_secp384r1))
                )),
                fn_supported_versions13_extension
            ))
        )))
    };

    let client_finished13 = term! {
        fn_finished(
            (fn_verify_data(
                (fn_server_finished_transcript(((server, 1)))),
                (fn_server_hello_transcript(((server, 1)))),
                (fn_get_server_key_share(((server, 1)))),
                fn_no_psk,
                fn_named_group_secp384r1,
                fn_new_random,
                fn_cipher_suite13_aes_128_gcm_sha256
            ))
        )
    };

    let trace12 = Trace {
        prior_traces: vec![],
        descriptors: vec![TLSDescriptorConfig::new_server(server, TLSVersion::Both)],
        steps: vec![
            Step {
                agent: server,
                action: Action::Input(input_action! { client_hello12
                }),
            },
            Step {
                agent: server,
                action: Action::Input(input_action! { client_key_exchange12
                }),
            },
            Step {
                agent: server,
                action: Action::Input(input_action! { term! { fn_change_cipher_spec }
                }),
            },
            Step {
                agent: server,
                action: Action::Input(input_action! { term! {
                        fn_encrypt12(
                            (fn_finished((@client_verify_data12))),
                            ((server, 0)),
                            (fn_decode_server_ecdh_pubkey(
                                ((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerKeyExchange)))]/Vec<u8>) // ServerECDHParams
                            )),
                            fn_named_group_secp384r1,
                            fn_true,
                            fn_seq_0,
                            fn_new_random,
                            fn_cipher_suite12
                        )
                    }
                }),
            },
            OutputAction::new_step(server),
        ],
        ..Default::default()
    };

    Trace {
        prior_traces: vec![trace12],
        descriptors: vec![TLSDescriptorConfig::new_server(server, TLSVersion::Both)],
        steps: vec![
            Step {
                agent: server,
                action: Action::Input(input_action! { term! {
                        @client_hello13
                    }
                }),
            },
            Step {
                agent: server,
                action: Action::Input(input_action! { term! {
                        fn_encrypt_handshake(
                            (@client_finished13),
                            (fn_server_hello_transcript(((server, 1)))),
                            (fn_get_server_key_share(((server, 1)))),
                            fn_no_psk,
                            fn_named_group_secp384r1,
                            fn_true,
                            fn_seq_0,  // sequence 0
                            fn_new_random,
                            fn_cipher_suite13_aes_128_gcm_sha256
                        )
                    }
                }),
            },
            OutputAction::new_step(server),
        ],
        ..Default::default()
    }
}

fn seed_successful_12_then_12(server: AgentName) -> Trace<TLSProtocolTypes> {
    // -- TLS 1.2 terms
    let client_hello12 = term! {
          fn_client_hello(
            fn_protocol_version12,
            fn_new_random,
            fn_new_session_id,
            (fn_cipher_suites_make(
                (fn_append_cipher_suite(
                  (fn_new_cipher_suites()),
                  // force TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
                  fn_cipher_suite12
            )))),
            fn_compressions,
            (fn_client_extensions_make(
            (fn_client_extensions_append(
                (fn_client_extensions_append(
                    (fn_client_extensions_append(
                        (fn_client_extensions_append(
                            (fn_client_extensions_append(
                                (fn_client_extensions_append(
                                    fn_client_extensions_new,
                                    (fn_support_group_extension_make(
                                        (fn_support_group_extension_append(
                                            fn_support_group_extension_new,
                                            fn_named_group_secp384r1
                                        ))
                                    ))
                                )),
                                fn_signature_algorithm_extension
                            )),
                            fn_ec_point_formats_extension
                        )),
                        fn_signed_certificate_timestamp_extension
                    )),
                     // Enable Renegotiation
                    (fn_renegotiation_info_extension((fn_payload_u8(fn_empty_bytes_vec))))
                )),
                // Add signature cert extension
                fn_signature_algorithm_cert_extension
            ))
        )))
    };

    let server_hello_transcript12 = term! {
        fn_append_transcript(
            (fn_append_transcript(
                fn_new_transcript12,
                (@client_hello12) // ClientHello
            )),
            ((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerHello)))]) // plaintext ServerHello
        )
    };

    let certificate_transcript12 = term! {
        fn_append_transcript(
            (@server_hello_transcript12),
            ((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::Certificate)))]) // Certificate
        )
    };

    let server_key_exchange_transcript12 = term! {
      fn_append_transcript(
            (@certificate_transcript12),
            ((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerKeyExchange)))]) // ServerKeyExchange
        )
    };

    let server_hello_done_transcript12 = term! {
      fn_append_transcript(
            (@server_key_exchange_transcript12),
            ((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerHelloDone)))]) // ServerHelloDone
        )
    };

    let client_key_exchange12 = term! {
        fn_client_key_exchange(
            (fn_encode_ec_pubkey12(
                (fn_payload_u8((fn_new_pubkey12(fn_named_group_secp384r1))))
            ))
        )
    };

    let client_key_exchange_transcript12 = term! {
      fn_append_transcript(
            (@server_hello_done_transcript12),
            (@client_key_exchange12)
        )
    };

    let client_verify_data12 = term! {
        fn_client_sign_transcript(
            ((server, 0)),
            (fn_decode_server_ecdh_pubkey(
                ((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerKeyExchange)))]/Vec<u8>) // ServerECDHParams
            )),
            (@client_key_exchange_transcript12),
            fn_named_group_secp384r1,
            fn_new_random,
            fn_cipher_suite12
        )
    };

    // -- TLS 1.2 terms for the SECOND connection (server output index = 1)
    let server_hello_transcript12_2 = term! {
        fn_append_transcript(
            (fn_append_transcript(
                fn_new_transcript12,
                (@client_hello12) // ClientHello
            )),
            ((server, 1)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerHello)))]) // plaintext ServerHello
        )
    };

    let certificate_transcript12_2 = term! {
        fn_append_transcript(
            (@server_hello_transcript12_2),
            ((server, 1)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::Certificate)))]) // Certificate
        )
    };

    let server_key_exchange_transcript12_2 = term! {
        fn_append_transcript(
            (@certificate_transcript12_2),
            ((server, 1)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerKeyExchange)))]) // ServerKeyExchange
        )
    };

    let server_hello_done_transcript12_2 = term! {
        fn_append_transcript(
            (@server_key_exchange_transcript12_2),
            ((server, 1)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerHelloDone)))]) // ServerHelloDone
        )
    };

    let client_key_exchange_transcript12_2 = term! {
        fn_append_transcript(
            (@server_hello_done_transcript12_2),
            (@client_key_exchange12)
        )
    };

    let client_verify_data12_2 = term! {
        fn_client_sign_transcript(
            ((server, 1)),
            (fn_decode_server_ecdh_pubkey(
                ((server, 1)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerKeyExchange)))]/Vec<u8>) // ServerECDHParams
            )),
            (@client_key_exchange_transcript12_2),
            fn_named_group_secp384r1,
            fn_new_random,
            fn_cipher_suite12
        )
    };

    let trace12 = Trace {
        prior_traces: vec![],
        descriptors: vec![TLSDescriptorConfig::new_server(server, TLSVersion::Both)],
        steps: vec![
            Step {
                agent: server,
                action: Action::Input(input_action! { client_hello12.clone()
                }),
            },
            Step {
                agent: server,
                action: Action::Input(input_action! { client_key_exchange12.clone()
                }),
            },
            Step {
                agent: server,
                action: Action::Input(input_action! { term! { fn_change_cipher_spec }
                }),
            },
            Step {
                agent: server,
                action: Action::Input(input_action! { term! {
                        fn_encrypt12(
                            (fn_finished((@client_verify_data12))),
                            ((server, 0)),
                            (fn_decode_server_ecdh_pubkey(
                                ((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerKeyExchange)))]/Vec<u8>) // ServerECDHParams
                            )),
                            fn_named_group_secp384r1,
                            fn_true,
                            fn_seq_0,
                            fn_new_random,
                            fn_cipher_suite12
                        )
                    }
                }),
            },
            OutputAction::new_step(server),
        ],
        ..Default::default()
    };

    Trace {
        prior_traces: vec![trace12],
        descriptors: vec![TLSDescriptorConfig::new_server(server, TLSVersion::Both)],
        steps: vec![
            Step {
                agent: server,
                action: Action::Input(input_action! { term! {
                        @client_hello12
                    }
                }),
            },
            Step {
                agent: server,
                action: Action::Input(input_action! { client_key_exchange12
                }),
            },
            Step {
                agent: server,
                action: Action::Input(input_action! { term! { fn_change_cipher_spec }
                }),
            },
            Step {
                agent: server,
                action: Action::Input(input_action! { term! {
                        fn_encrypt12(
                            (fn_finished((@client_verify_data12_2))),
                            ((server, 1)),
                            (fn_decode_server_ecdh_pubkey(
                                ((server, 1)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerKeyExchange)))]/Vec<u8>) // ServerECDHParams
                            )),
                            fn_named_group_secp384r1,
                            fn_true,
                            fn_seq_0,
                            fn_new_random,
                            fn_cipher_suite12
                        )
                    }
                }),
            },
            OutputAction::new_step(server),
        ],
        ..Default::default()
    }
}

#[cfg(test)]
pub mod tests {
    use puffin::put::PutDescriptor;
    use tlspuffin::test_utils::prelude::*;

    use super::*;

    #[apply(test_puts, filter = all(tls12, tls13, not(boringssl)))]
    fn test_seed_successful_12_both(put: &str) {
        let runner = default_runner_for(put);
        let trace = seed_successful_12_both.build_trace();
        let ctx = runner.execute(trace, &mut 0).unwrap();
        assert!(ctx.agents_successful());
    }

    #[apply(test_puts, filter = all(tls12, tls13, not(boringssl)))]
    fn test_seed_successful_13_both(put: &str) {
        let runner = default_runner_for(put);
        let trace = seed_successful_13_both.build_trace();
        let ctx = runner.execute(trace, &mut 0).unwrap();
        assert!(ctx.agents_successful());
    }

    #[apply(test_puts, filter = all(tls13, tls13, not(boringssl)))]
    fn test_seed_successful_both_13(put: &str) {
        let runner = default_runner_for(put);
        let trace = seed_successful_both_13.build_trace();
        let ctx = runner.execute(trace, &mut 0).unwrap();
        assert!(ctx.agents_successful());
    }

    #[apply(test_puts, filter = all(tls12, tls13, not(boringssl)))]
    fn test_seed_successful_both_12(put: &str) {
        let runner = default_runner_for(put);
        let trace = seed_successful_both_12.build_trace();
        let ctx = runner.execute(trace, &mut 0).unwrap();
        assert!(ctx.agents_successful());
    }

    #[apply(test_puts, filter = all(tls12, tls13, not(boringssl)))]
    fn test_seed_error_12_13(put: &str) {
        let runner = default_runner_for(put);
        let trace = seed_error_12_13.build_trace();
        let result = runner.execute(trace, &mut 0);
        assert!(result.is_err());
        let error = result.unwrap_err();
        assert!(matches!(error, puffin::error::Error::Put(_)));
        let error_string = error.to_string();
        // Respectively OpenSSL and WolfSSL error messages
        assert!(
            error_string.contains("unsupported protocol")
                || error_string.contains("record layer version error")
        );
    }

    #[apply(test_puts, filter = all(tls12, tls13, not(boringssl)))]
    fn test_seed_error_13_12(put: &str) {
        let runner = default_runner_for(put);
        let trace = seed_error_13_12.build_trace();
        let result = runner.execute(trace, &mut 0);
        assert!(result.is_err());
        let error = result.unwrap_err();
        assert!(matches!(error, puffin::error::Error::Put(_)));
        let error_string = error.to_string();
        // Respectively OpenSSL and WolfSSL error messages
        assert!(
            error_string.contains("unsupported protocol")
                || error_string.contains("record layer version error")
        );
    }

    #[apply(test_puts, filter = all(tls12, tls13, not(boringssl)))]
    fn test_seed_successful_12_then_13(put: &str) {
        let runner = default_runner_for_desc(PutDescriptor::new(put, vec![("use_clear", "true")]));
        let trace = seed_successful_12_then_13.build_trace();
        let ctx = runner.execute(trace, &mut 0).unwrap();
        assert!(ctx.agents_successful());
    }

    #[apply(test_puts, filter = all(tls12, tls13, not(boringssl)))]
    fn test_seed_successful_12_then_12(put: &str) {
        let runner = default_runner_for_desc(PutDescriptor::new(put, vec![("use_clear", "true")]));
        let trace = seed_successful_12_then_12.build_trace();
        let ctx = runner.execute(trace, &mut 0).unwrap();
        assert!(ctx.agents_successful());
    }
}
