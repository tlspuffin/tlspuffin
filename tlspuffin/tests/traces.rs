use puffin::agent::AgentName;
use puffin::trace::{Action, InputAction, OutputAction, Step, Trace};
use puffin::{input_action, term};
use tlspuffin::protocol::{MessageFlight, TLSDescriptorConfig, TLSProtocolTypes, TLSVersion};
use tlspuffin::query::TlsQueryMatcher;
use tlspuffin::tls::fn_impl::*;
use tlspuffin::tls::rustls::msgs::base::*;
use tlspuffin::tls::rustls::msgs::ccs::fn_changecipherspecpayload;
use tlspuffin::tls::rustls::msgs::enums::{HandshakeType, *};
use tlspuffin::tls::rustls::msgs::handshake::{fn_compressions, *};
use tlspuffin::tls::rustls::msgs::message::*;

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
                action: Action::Input(input_action! { term! {
                    (client12, 0)/MessageFlight
                } }),
            },
            // ServerHello + Certificate + ServerKeyExchange + ServerHelloDone → Client12
            Step {
                agent: client12,
                action: Action::Input(input_action! { term! {
                    (server, 0)/MessageFlight
                } }),
            },
            // ClientKeyExchange + ChangeCipherSpec + Finished → Server
            Step {
                agent: server,
                action: Action::Input(input_action! { term! {
                    (client12, 1)/MessageFlight
                } }),
            },
            // ChangeCipherSpec + Finished → Client12
            Step {
                agent: client12,
                action: Action::Input(input_action! { term! {
                    (server, 1)/MessageFlight
                } }),
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
                action: Action::Input(input_action! { term! {
                    (client13, 0)/MessageFlight
                } }),
            },
            // ServerHello + EncryptedExtensions + Certificate + CertificateVerify + Finished →
            // Client13
            Step {
                agent: client13,
                action: Action::Input(input_action! { term! {
                    (server, 0)/MessageFlight
                } }),
            },
            // Finished → Server
            Step {
                agent: server,
                action: Action::Input(input_action! { term! {
                    (client13, 1)/MessageFlight
                } }),
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
                action: Action::Input(input_action! { term! {
                    (client, 0)/MessageFlight
                } }),
            },
            // ServerHello + EncryptedExtensions + Certificate + CertificateVerify + Finished →
            // Client13
            Step {
                agent: client,
                action: Action::Input(input_action! { term! {
                    (server13, 0)/MessageFlight
                } }),
            },
            // Finished → Server
            Step {
                agent: server13,
                action: Action::Input(input_action! { term! {
                    (client, 1)/MessageFlight
                } }),
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
                action: Action::Input(input_action! { term! {
                    (client, 0)/MessageFlight
                } }),
            },
            // ServerHello + Certificate + ServerKeyExchange + ServerHelloDone → Client12
            Step {
                agent: client,
                action: Action::Input(input_action! { term! {
                    (server12, 0)/MessageFlight
                } }),
            },
            // ClientKeyExchange + ChangeCipherSpec + Finished → Server
            Step {
                agent: server12,
                action: Action::Input(input_action! { term! {
                    (client, 1)/MessageFlight
                } }),
            },
            // ChangeCipherSpec + Finished → Client12
            Step {
                agent: client,
                action: Action::Input(input_action! { term! {
                    (server12, 1)/MessageFlight
                } }),
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
                action: Action::Input(input_action! { term! {
                    (client12, 0)/MessageFlight
                } }),
            },
            // ServerHello + Certificate + ServerKeyExchange + ServerHelloDone → Client12
            Step {
                agent: client12,
                action: Action::Input(input_action! { term! {
                    (server13, 0)/MessageFlight
                } }),
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
                action: Action::Input(input_action! { term! {
                    (client13, 0)/MessageFlight
                } }),
            },
            // ServerHello + Certificate + ServerKeyExchange + ServerHelloDone → Client12
            Step {
                agent: client13,
                action: Action::Input(input_action! { term! {
                    (server12, 0)/MessageFlight
                } }),
            },
            // ClientKeyExchange + ChangeCipherSpec + Finished → Server
            Step {
                agent: server12,
                action: Action::Input(input_action! { term! {
                    (client13, 1)/MessageFlight
                } }),
            },
            // ChangeCipherSpec + Finished → Client12
            Step {
                agent: client13,
                action: Action::Input(input_action! { term! {
                    (server12, 1)/MessageFlight
                } }),
            },
        ],
        ..Default::default()
    }
}

fn seed_successful_12_then_13(server: AgentName) -> Trace<TLSProtocolTypes> {
    // -- TLS 1.2 terms
    let client_hello12 = term! {
        fn_message(
            fn_protocolversion_tlsv1_2,
            fn_messagepayload_handshake(
                fn_handshakemessagepayload(
                    fn_handshaketype_clienthello,
                    fn_handshakepayload_clienthello(
                        fn_clienthellopayload(
                            fn_protocolversion_tlsv1_2,
                            fn_random,
                            fn_sessionid,
                            (fn_ciphersuites(
                                (fn_list_ciphersuite_append(
                                    (fn_list_ciphersuite_empty()),
                                    // force TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
                                    fn_ciphersuite_tls_ecdhe_rsa_with_aes_128_gcm_sha256
                                ))
                            )),
                            fn_compressions(
                                fn_list_compression_append(
                                    fn_list_compression_empty,
                                    fn_compression_null
                                )
                            ),
                            (fn_clientextensions(
                                (fn_list_clientextension_append(
                                    (fn_list_clientextension_append(
                                        (fn_list_clientextension_append(
                                            (fn_list_clientextension_append(
                                                (fn_list_clientextension_append(
                                                    (fn_list_clientextension_append(
                                                        fn_list_clientextension_empty,
                                                        (fn_clientextension_namedgroups(
                                                            fn_namedgroups(
                                                                (fn_list_namedgroup_append(
                                                                    fn_list_namedgroup_empty,
                                                                    fn_namedgroup_secp384r1
                                                                ))
                                                            )
                                                        ))
                                                    )),
                                                    (fn_clientextension_signaturealgorithms(
                                                        fn_supportedsignatureschemes(
                                                            (fn_list_signaturescheme_append(
                                                                (fn_list_signaturescheme_append(
                                                                    fn_list_signaturescheme_empty,
                                                                    fn_signaturescheme_rsa_pkcs1_sha256
                                                                )),
                                                                fn_signaturescheme_rsa_pss_sha256
                                                            ))
                                                        )
                                                    ))
                                                )),
                                                fn_clientextension_ecpointformats(
                                                    fn_ecpointformatlist(
                                                        fn_list_ecpointformat_append(
                                                            fn_list_ecpointformat_empty,
                                                            fn_ecpointformat_uncompressed
                                                        )
                                                    )
                                                )
                                            )),
                                            fn_clientextension_signedcertificatetimestamprequest
                                        )),
                                        // Enable Renegotiation
                                        (fn_clientextension_renegotiationinfo(
                                            (fn_payloadu8(fn_empty_bytes_vec))
                                        ))
                                    )),
                                    // Add signature cert extension
                                    fn_signature_algorithm_cert_extension
                                ))
                            ))
                        )
                    )
                )
            )
        )
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
        fn_message(
            fn_protocolversion_tlsv1_2,
            fn_messagepayload_handshake(
                fn_handshakemessagepayload(
                    fn_handshaketype_clientkeyexchange,
                    fn_handshakepayload_clientkeyexchange(
                        fn_payload(
                            (fn_encode_ec_pubkey12(
                                (fn_payloadu8((fn_new_pubkey12(fn_namedgroup_secp384r1))))
                            ))
                        )
                    )
                )
            )
        )
    };

    let client_key_exchange_transcript12 = term! {
        fn_append_transcript((@server_hello_done_transcript12), (@client_key_exchange12))
    };

    let client_verify_data12 = term! {
        fn_client_sign_transcript(
            ((server, 0)),
            (fn_decode_server_ecdh_pubkey(
                ((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerKeyExchange)))]/Vec<u8>) // ServerECDHParams
            )),
            (@client_key_exchange_transcript12),
            fn_namedgroup_secp384r1,
            fn_random,
            fn_ciphersuite_tls_ecdhe_rsa_with_aes_128_gcm_sha256
        )
    };

    // --- TLS 1.3 terms
    let client_hello13 = term! {
        fn_message(
            fn_protocolversion_tlsv1_2,
            fn_messagepayload_handshake(
                fn_handshakemessagepayload(
                    fn_handshaketype_clienthello,
                    fn_handshakepayload_clienthello(
                        fn_clienthellopayload(
                            fn_protocolversion_tlsv1_2,
                            fn_random,
                            fn_sessionid,
                            (fn_ciphersuites(
                                (fn_list_ciphersuite_append(
                                    (fn_list_ciphersuite_empty()),
                                    fn_ciphersuite_tls13_aes_128_gcm_sha256
                                ))
                            )),
                            fn_compressions(
                                fn_list_compression_append(
                                    fn_list_compression_empty,
                                    fn_compression_null
                                )
                            ),
                            (fn_clientextensions(
                                (fn_list_clientextension_append(
                                    (fn_list_clientextension_append(
                                        (fn_list_clientextension_append(
                                            (fn_list_clientextension_append(
                                                fn_list_clientextension_empty,
                                                (fn_clientextension_namedgroups(
                                                    fn_namedgroups(
                                                        (fn_list_namedgroup_append(
                                                            fn_list_namedgroup_empty,
                                                            fn_namedgroup_secp384r1
                                                        ))
                                                    )
                                                ))
                                            )),
                                            (fn_clientextension_signaturealgorithms(
                                                fn_supportedsignatureschemes(
                                                    (fn_list_signaturescheme_append(
                                                        (fn_list_signaturescheme_append(
                                                            fn_list_signaturescheme_empty,
                                                            fn_signaturescheme_rsa_pkcs1_sha256
                                                        )),
                                                        fn_signaturescheme_rsa_pss_sha256
                                                    ))
                                                )
                                            ))
                                        )),
                                        (fn_clientextension_keyshare(
                                            fn_keyshareentries(
                                                (fn_list_keyshareentry_append(
                                                    fn_list_keyshareentry_empty,
                                                    (fn_key_share_deterministic(
                                                        fn_namedgroup_secp384r1
                                                    ))
                                                ))
                                            )
                                        ))
                                    )),
                                    fn_clientextension_supportedversions(
                                        fn_protocolversions(
                                            fn_list_protocolversion_append(
                                                fn_list_protocolversion_empty,
                                                fn_protocolversion_tlsv1_3
                                            )
                                        )
                                    )
                                ))
                            ))
                        )
                    )
                )
            )
        )
    };

    let client_finished13 = term! {
        fn_message(
            fn_protocolversion_tlsv1_2,
            fn_messagepayload_handshake(
                fn_handshakemessagepayload(
                    fn_handshaketype_finished,
                    fn_handshakepayload_finished(
                        fn_payload(
                            (fn_verify_data(
                                (fn_server_finished_transcript(((server, 1)))),
                                (fn_server_hello_transcript(((server, 1)))),
                                (fn_psk(D(((server, 0) / KeyShareEntry), Vec<u8>))),
                                fn_no_psk,
                                fn_namedgroup_secp384r1,
                                fn_random,
                                fn_ciphersuite_tls13_aes_128_gcm_sha256
                            ))
                        )
                    )
                )
            )
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
                action: Action::Input(input_action! { term! {
                    fn_message(
                        fn_protocolversion_tlsv1_2,
                        fn_messagepayload_changecipherspec(fn_changecipherspecpayload)
                    )
                }
                }),
            },
            Step {
                agent: server,
                action: Action::Input(input_action! { term! {
                    fn_encrypt12(
                        (fn_message(
                            fn_protocolversion_tlsv1_2,
                            fn_messagepayload_handshake(
                                fn_handshakemessagepayload(
                                    fn_handshaketype_finished,
                                    fn_handshakepayload_finished(
                                        fn_payload((@client_verify_data12))
                                    )
                                )
                            )
                        )),
                        ((server, 0)),
                        (fn_decode_server_ecdh_pubkey(
                            ((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerKeyExchange)))]/Vec<u8>) // ServerECDHParams
                        )),
                        fn_namedgroup_secp384r1,
                        fn_true,
                        fn_seq_0,
                        fn_random,
                        fn_ciphersuite_tls_ecdhe_rsa_with_aes_128_gcm_sha256
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
                        (fn_psk(D(((server, 0) / KeyShareEntry), Vec<u8>))),
                        fn_no_psk,
                        fn_namedgroup_secp384r1,
                        fn_true,
                        fn_seq_0,
                        // sequence 0
                        fn_random,
                        fn_ciphersuite_tls13_aes_128_gcm_sha256
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
        fn_message(
            fn_protocolversion_tlsv1_2,
            fn_messagepayload_handshake(
                fn_handshakemessagepayload(
                    fn_handshaketype_clienthello,
                    fn_handshakepayload_clienthello(
                        fn_clienthellopayload(
                            fn_protocolversion_tlsv1_2,
                            fn_random,
                            fn_sessionid,
                            (fn_ciphersuites(
                                (fn_list_ciphersuite_append(
                                    (fn_list_ciphersuite_empty()),
                                    // force TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
                                    fn_ciphersuite_tls_ecdhe_rsa_with_aes_128_gcm_sha256
                                ))
                            )),
                            fn_compressions(
                                fn_list_compression_append(
                                    fn_list_compression_empty,
                                    fn_compression_null
                                )
                            ),
                            (fn_clientextensions(
                                (fn_list_clientextension_append(
                                    (fn_list_clientextension_append(
                                        (fn_list_clientextension_append(
                                            (fn_list_clientextension_append(
                                                (fn_list_clientextension_append(
                                                    (fn_list_clientextension_append(
                                                        fn_list_clientextension_empty,
                                                        (fn_clientextension_namedgroups(
                                                            fn_namedgroups(
                                                                (fn_list_namedgroup_append(
                                                                    fn_list_namedgroup_empty,
                                                                    fn_namedgroup_secp384r1
                                                                ))
                                                            )
                                                        ))
                                                    )),
                                                    (fn_clientextension_signaturealgorithms(
                                                        fn_supportedsignatureschemes(
                                                            (fn_list_signaturescheme_append(
                                                                (fn_list_signaturescheme_append(
                                                                    fn_list_signaturescheme_empty,
                                                                    fn_signaturescheme_rsa_pkcs1_sha256
                                                                )),
                                                                fn_signaturescheme_rsa_pss_sha256
                                                            ))
                                                        )
                                                    ))
                                                )),
                                                fn_clientextension_ecpointformats(
                                                    fn_ecpointformatlist(
                                                        fn_list_ecpointformat_append(
                                                            fn_list_ecpointformat_empty,
                                                            fn_ecpointformat_uncompressed
                                                        )
                                                    )
                                                )
                                            )),
                                            fn_clientextension_signedcertificatetimestamprequest
                                        )),
                                        // Enable Renegotiation
                                        (fn_clientextension_renegotiationinfo(
                                            (fn_payloadu8(fn_empty_bytes_vec))
                                        ))
                                    )),
                                    // Add signature cert extension
                                    fn_signature_algorithm_cert_extension
                                ))
                            ))
                        )
                    )
                )
            )
        )
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
        fn_message(
            fn_protocolversion_tlsv1_2,
            fn_messagepayload_handshake(
                fn_handshakemessagepayload(
                    fn_handshaketype_clientkeyexchange,
                    fn_handshakepayload_clientkeyexchange(
                        fn_payload(
                            (fn_encode_ec_pubkey12(
                                (fn_payloadu8((fn_new_pubkey12(fn_namedgroup_secp384r1))))
                            ))
                        )
                    )
                )
            )
        )
    };

    let client_key_exchange_transcript12 = term! {
        fn_append_transcript((@server_hello_done_transcript12), (@client_key_exchange12))
    };

    let client_verify_data12 = term! {
        fn_client_sign_transcript(
            ((server, 0)),
            (fn_decode_server_ecdh_pubkey(
                ((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerKeyExchange)))]/Vec<u8>) // ServerECDHParams
            )),
            (@client_key_exchange_transcript12),
            fn_namedgroup_secp384r1,
            fn_random,
            fn_ciphersuite_tls_ecdhe_rsa_with_aes_128_gcm_sha256
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
        fn_append_transcript((@server_hello_done_transcript12_2), (@client_key_exchange12))
    };

    let client_verify_data12_2 = term! {
        fn_client_sign_transcript(
            ((server, 1)),
            (fn_decode_server_ecdh_pubkey(
                ((server, 1)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerKeyExchange)))]/Vec<u8>) // ServerECDHParams
            )),
            (@client_key_exchange_transcript12_2),
            fn_namedgroup_secp384r1,
            fn_random,
            fn_ciphersuite_tls_ecdhe_rsa_with_aes_128_gcm_sha256
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
                action: Action::Input(input_action! { term! {
                    fn_message(
                        fn_protocolversion_tlsv1_2,
                        fn_messagepayload_changecipherspec(fn_changecipherspecpayload)
                    )
                }
                }),
            },
            Step {
                agent: server,
                action: Action::Input(input_action! { term! {
                    fn_encrypt12(
                        (fn_message(
                            fn_protocolversion_tlsv1_2,
                            fn_messagepayload_handshake(
                                fn_handshakemessagepayload(
                                    fn_handshaketype_finished,
                                    fn_handshakepayload_finished(
                                        fn_payload((@client_verify_data12))
                                    )
                                )
                            )
                        )),
                        ((server, 0)),
                        (fn_decode_server_ecdh_pubkey(
                            ((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerKeyExchange)))]/Vec<u8>) // ServerECDHParams
                        )),
                        fn_namedgroup_secp384r1,
                        fn_true,
                        fn_seq_0,
                        fn_random,
                        fn_ciphersuite_tls_ecdhe_rsa_with_aes_128_gcm_sha256
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
                action: Action::Input(input_action! { term! {
                    fn_message(
                        fn_protocolversion_tlsv1_2,
                        fn_messagepayload_changecipherspec(fn_changecipherspecpayload)
                    )
                }
                }),
            },
            Step {
                agent: server,
                action: Action::Input(input_action! { term! {
                    fn_encrypt12(
                        (fn_message(
                            fn_protocolversion_tlsv1_2,
                            fn_messagepayload_handshake(
                                fn_handshakemessagepayload(
                                    fn_handshaketype_finished,
                                    fn_handshakepayload_finished(
                                        fn_payload((@client_verify_data12_2))
                                    )
                                )
                            )
                        )),
                        ((server, 1)),
                        (fn_decode_server_ecdh_pubkey(
                            ((server, 1)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerKeyExchange)))]/Vec<u8>) // ServerECDHParams
                        )),
                        fn_namedgroup_secp384r1,
                        fn_true,
                        fn_seq_0,
                        fn_random,
                        fn_ciphersuite_tls_ecdhe_rsa_with_aes_128_gcm_sha256
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

    // LibreSSL333 supports TLS1.3 but not the 1.3 API, therefore we cannot set an agent only on 1.3
    // There is no error raised if the agent can communicate in 1.2
    #[apply(test_puts, filter = all(tls12, tls13, not(feature="libressl333")))]
    fn test_seed_error_12_13(put: &str) {
        let runner = default_runner_for(put);
        let trace = seed_error_12_13.build_trace();
        let result = runner.execute(trace, &mut 0);
        assert!(result.is_err());
        let error = result.unwrap_err();
        assert!(matches!(error, puffin::error::Error::Put(_)));
        let error_string = error.to_string();
        log::debug!("Error: {}", error_string);
        // Respectively OpenSSL, BoringSSL and WolfSSL error messages
        // If it crashes, you might have added a new PUT version or vendor
        // You might need to add another condition
        assert!(
            error_string.contains("unsupported protocol")               // OpenSSL
                || error_string.contains("UNSUPPORTED_PROTOCOL")        // BoringSSL
                || error_string.contains("record layer version error")  // WolfSSL
                || error_string.contains("unknown error number")        // WolfSSL_430
                || error_string.contains("wrong version number")        // LibreSSL
                || error_string.contains("parse tlsext") // LibreSSL
        );
    }

    // LibreSSL333 supports TLS1.3 but not the 1.3 API, therefore we cannot set an agent only on 1.3
    // There is no error raised if the agent can communicate in 1.2
    #[apply(test_puts, filter = all(tls12, tls13, not(feature="libressl333")))]
    fn test_seed_error_13_12(put: &str) {
        let runner = default_runner_for(put);
        let trace = seed_error_13_12.build_trace();
        let result = runner.execute(trace, &mut 0);
        assert!(result.is_err());
        let error = result.unwrap_err();
        assert!(matches!(error, puffin::error::Error::Put(_)));
        let error_string = error.to_string();
        log::debug!("Error: {}", error_string);
        // Respectively OpenSSL, BoringSSL and WolfSSL error messages
        // If it crashes, you might have added a new PUT version or vendor
        // You might need to add another condition
        assert!(
            error_string.contains("unsupported protocol")               // OpenSSL
                || error_string.contains("UNSUPPORTED_PROTOCOL")        // BoringSSL
                || error_string.contains("record layer version error")  // WolfSSL
                || error_string.contains("unknown error number")        // WolfSSL_430
                || error_string.contains("wrong version number")        // LibreSSL
                || error_string.contains("parse tlsext") // LibreSSL
        );
    }

    // the standard for ssl_clear only specifies that it should work with exactly the same agent
    // Most implementations outside openssl seems to implement the strict minimum and therefore
    // won't work with those tests
    #[apply(test_puts, filter = all(tls12, tls13, not(boringssl), not(wolfssl), not(libressl)))]
    fn test_seed_successful_12_then_13(put: &str) {
        let runner = default_runner_for_desc(PutDescriptor::new(put, vec![("use_clear", "true")]));
        let trace = seed_successful_12_then_13.build_trace();
        let ctx = runner.execute(trace, &mut 0).unwrap();
        assert!(ctx.agents_successful());
    }

    #[apply(test_puts, filter = all(tls12, tls13, not(boringssl), not(wolfssl), not(libressl)))]
    fn test_seed_successful_12_then_12(put: &str) {
        let runner = default_runner_for_desc(PutDescriptor::new(put, vec![("use_clear", "true")]));
        let trace = seed_successful_12_then_12.build_trace();
        let ctx = runner.execute(trace, &mut 0).unwrap();
        assert!(ctx.agents_successful());
    }
}
