#![allow(dead_code)]
/// This modules contains reproducer for RFC violations found with differential fuzzing
use puffin::agent::{AgentDescriptor, AgentName};
use puffin::trace::{Action, InputAction, OutputAction, Step, Trace};
use puffin::{input_action, term};

use crate::protocol::{
    AgentType, MessageFlight, TLSDescriptorConfig, TLSProtocolTypes, TLSVersion,
};
use crate::query::TlsQueryMatcher;
use crate::tls::fn_impl::*;
use crate::tls::rustls::msgs::enums::HandshakeType;

/// RFC violation triggering bad wolfSSL alert when SH contains unsupported cipher (HandshakeFailure
/// instead of IllegalParameter)
/// <https://github.com/wolfSSL/wolfssl/issues/9639>
pub fn rfc_violation_alert_unsupported_cipher_suite(
    client: AgentName,
    _server: AgentName,
) -> Trace<TLSProtocolTypes> {
    let curve = term! {
        fn_get_any_client_curve(
            ((client, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ClientHello)))])
        )
    };

    let server_hello = term! {
          fn_server_hello(
            fn_protocol_version12,
            fn_new_random,
            ((client, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ClientHello)))]),
            fn_cipher_suite13_aes_128_ccm_sha256,
            fn_compression,
            (fn_server_extensions_make(
              (fn_server_extensions_append(
                  (fn_server_extensions_append(
                      fn_server_extensions_new,
                      (fn_key_share_deterministic_server_extension((@curve)))
                  )),
                  fn_supported_versions13_server_extension
            ))))
        )
    };

    let server_hello_transcript = term! {
        fn_append_transcript(
            (fn_append_transcript(
                fn_new_transcript,
                ((client, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ClientHello)))]) // ClientHello
            )),
            (@server_hello) // plaintext ServerHello
        )
    };

    let encrypted_extensions = term! {
        fn_encrypted_extensions(
            fn_server_extensions_new
        )
    };

    let certificate = term! {
        fn_certificate13(
            (fn_payload_u8((fn_empty_bytes_vec))),
            (fn_certificate_entries_make(
                (fn_chain_append_certificate_entry(
                  fn_empty_certificate_chain,
                  (fn_certificate_entry_extensions(
                    fn_alice_cert,
                    (fn_cert_extensions_make(
                        fn_cert_extensions_new
                    ))
            ))))
            ))
        )
    };

    let encrypted_extensions_transcript = term! {
        fn_append_transcript(
            (@server_hello_transcript),
            (@encrypted_extensions) // plaintext EncryptedExtensions
        )
    };

    let certificate_transcript = term! {
        fn_append_transcript(
            (@encrypted_extensions_transcript),
            (@certificate) // plaintext Certificate
        )
    };

    let certificate_verify = term! {
        fn_certificate_verify(
            fn_rsa_pss_signature_algorithm,
            (fn_payload_u16(
                (fn_rsa_sign_server(
                    (@certificate_transcript),
                    fn_alice_key,
                    fn_rsa_pss_signature_algorithm
                ))
            ))
        )
    };

    let certificate_verify_transcript = term! {
        fn_append_transcript(
            (@certificate_transcript),
            (@certificate_verify) // plaintext CertificateVerify
        )
    };

    let server_finished = term! {
        fn_finished(
            (fn_verify_data_server(
                (@certificate_verify_transcript),
                //(fn_server_finished_transcript(((client, 0)))),
                (@server_hello_transcript),
                (fn_get_client_key_share(((client, 0)), (@curve))),
                (@curve),
                fn_no_psk,
                fn_new_random,
                fn_cipher_suite13_aes_128_gcm_sha256
            ))
        )
    };

    Trace {
        prior_traces: vec![],
        descriptors: vec![AgentDescriptor::from_config(
            client,
            TLSDescriptorConfig {
                tls_version: TLSVersion::V1_3,
                typ: AgentType::Client,
                cipher_string_tls13: String::from(
                    "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256",
                ),
                ..TLSDescriptorConfig::default()
            },
        )],
        steps: vec![
            OutputAction::new_step(client),
            Step {
                agent: client,
                action: Action::Input(input_action! { server_hello
                }),
            },
            Step {
                agent: client,
                action: Action::Input(input_action! { term! {
                        fn_encrypt_handshake(
                            (@encrypted_extensions),
                            (@server_hello_transcript),
                            (fn_get_client_key_share(((client, 0)), (@curve))),
                            fn_no_psk,
                            (@curve),
                            fn_false,
                            fn_seq_0,  // sequence 0
                            fn_new_random,
                            fn_cipher_suite13_aes_128_gcm_sha256
                        )
                    }
                }),
            },
            Step {
                agent: client,
                action: Action::Input(input_action! { term! {
                        fn_encrypt_handshake(
                            (@certificate),
                            (@server_hello_transcript),
                            (fn_get_client_key_share(((client, 0)), (@curve))),
                            fn_no_psk,
                            (@curve),
                            fn_false,
                            fn_seq_1,  // sequence 1
                            fn_new_random,
                            fn_cipher_suite13_aes_128_gcm_sha256
                        )
                    }
                }),
            },
            Step {
                agent: client,
                action: Action::Input(input_action! { term! {
                        fn_encrypt_handshake(
                            (@certificate_verify),
                            (@server_hello_transcript),
                            (fn_get_client_key_share(((client, 0)), (@curve))),
                            fn_no_psk,
                            (@curve),
                            fn_false,
                            fn_seq_2,  // sequence 2
                            fn_new_random,
                            fn_cipher_suite13_aes_128_gcm_sha256
                        )
                    }
                }),
            },
            Step {
                agent: client,
                action: Action::Input(input_action! { term! {
                        fn_encrypt_handshake(
                            (@server_finished),
                            (@server_hello_transcript),
                            (fn_get_client_key_share(((client, 0)), (@curve))),
                            fn_no_psk,
                            (@curve),
                            fn_false,
                            fn_seq_3,  // sequence 3
                            fn_new_random,
                            fn_cipher_suite13_aes_128_gcm_sha256
                        )
                    }
                }),
            },
        ],
        ..Default::default()
    }
}

/// A wolfSSL TLS 1.3 Server receiving a ClientHello with a malformed KeyShare extension (e.g. with
/// no key inside) returns a IllegalParameter alert instead of a DecodeError alert.
/// <https://github.com/wolfSSL/wolfssl/issues/9640>
pub fn rfc_violation_alert_bad_key_share(
    _client: AgentName,
    server: AgentName,
) -> Trace<TLSProtocolTypes> {
    let client_hello = term! {
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
                    (fn_key_share_extension(
                        fn_named_group_secp384r1,
                        (fn_payload_u16(fn_empty_bytes_vec))
                    ))
                )),
                fn_supported_versions13_extension
            ))
        )))
    };

    let server_hello_transcript = term! {
        fn_append_transcript(
            (fn_append_transcript(
                fn_new_transcript,
                (@client_hello) // ClientHello
            )),
            ((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerHello)))]) // plaintext ServerHello
        )
    };

    // ((0, 1)) could be a CCS the server sends one

    let extensions = term! {
        fn_decrypt_handshake_flight(
            ((server, 0)/MessageFlight), // The first flight of messages sent by the server
            (@server_hello_transcript),
            (fn_get_server_key_share(((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerHello)))]))),
            fn_no_psk,
            fn_named_group_secp384r1,
            fn_true,
            fn_seq_0,  // sequence 0
            fn_new_random,
            fn_cipher_suite13_aes_128_gcm_sha256
        )
    };

    let encrypted_extensions = term! {
        fn_find_encrypted_extensions((@extensions))
    };

    let encrypted_extension_transcript = term! {
        fn_append_transcript(
            (@server_hello_transcript),
            (@encrypted_extensions) // plaintext Encrypted Extensions
        )
    };

    let server_certificate = term! {
        fn_find_server_certificate((@extensions))
    };

    let server_certificate_transcript = term! {
        fn_append_transcript(
            (@encrypted_extension_transcript),
            (@server_certificate) // plaintext Server Certificate
        )
    };

    let server_certificate_verify = term! {
        fn_find_server_certificate_verify((@extensions))
    };

    let server_certificate_verify_transcript = term! {
        fn_append_transcript(
            (@server_certificate_transcript),
            (@server_certificate_verify) // plaintext Server Certificate Verify
        )
    };

    let server_finished = term! {
        fn_find_server_finished((@extensions))
    };

    let server_finished_transcript = term! {
        fn_append_transcript(
            (@server_certificate_verify_transcript),
            (@server_finished) // plaintext Server Handshake Finished
        )
    };

    let client_finished = term! {
        fn_finished(
            (fn_verify_data(
                (@server_finished_transcript),
                (@server_hello_transcript),
                (fn_get_server_key_share(((server, 0)))),
                fn_no_psk,
                fn_named_group_secp384r1,
                fn_new_random,
                fn_cipher_suite13_aes_128_gcm_sha256
             ))
        )
    };

    Trace {
        prior_traces: vec![],
        descriptors: vec![TLSDescriptorConfig::new_server(server, TLSVersion::V1_3)],
        steps: vec![
            Step {
                agent: server,
                action: Action::Input(input_action! { term! {
                        @client_hello
                    }
                }),
            },
            OutputAction::new_step(server),
            Step {
                agent: server,
                action: Action::Input(input_action! { term! {
                        fn_encrypt_handshake(
                            (@client_finished),
                            (@server_hello_transcript),
                            (fn_get_server_key_share(((server, 0)))),
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

/// A WolfSSL TLS 1.3 client receiving encrypted out of order messages will detect the error and log
/// "Out of order message, fatal" without sending an alert.
/// <https://github.com/wolfSSL/wolfssl/issues/9531>
pub fn rfc_violation_missing_alert_out_of_order_encrypted(
    client: AgentName,
    _server: AgentName,
) -> Trace<TLSProtocolTypes> {
    let curve = term! {
        fn_get_any_client_curve(
            ((client, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ClientHello)))])
        )
    };

    let server_hello = term! {
          fn_server_hello(
            fn_protocol_version12,
            fn_new_random,
            ((client, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ClientHello)))]),
            fn_cipher_suite13_aes_128_gcm_sha256,
            fn_compression,
            (fn_server_extensions_make(
              (fn_server_extensions_append(
                  (fn_server_extensions_append(
                      fn_server_extensions_new,
                      (fn_key_share_deterministic_server_extension((@curve)))
                  )),
                  fn_supported_versions13_server_extension
            ))))
        )
    };

    let server_hello_transcript = term! {
        fn_append_transcript(
            (fn_append_transcript(
                fn_new_transcript,
                ((client, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ClientHello)))]) // ClientHello
            )),
            (@server_hello) // plaintext ServerHello
        )
    };

    let encrypted_extensions = term! {
        fn_encrypted_extensions(
            fn_server_extensions_new
        )
    };

    let certificate = term! {
        fn_certificate13(
            (fn_payload_u8((fn_empty_bytes_vec))),
            (fn_certificate_entries_make(
                (fn_chain_append_certificate_entry(
                  fn_empty_certificate_chain,
                  (fn_certificate_entry_extensions(
                    fn_alice_cert,
                    (fn_cert_extensions_make(
                        fn_cert_extensions_new
                    ))
            ))))
            ))
        )
    };

    let encrypted_extensions_transcript = term! {
        fn_append_transcript(
            (@server_hello_transcript),
            (@encrypted_extensions) // plaintext EncryptedExtensions
        )
    };

    let certificate_transcript = term! {
        fn_append_transcript(
            (@encrypted_extensions_transcript),
            (@certificate) // plaintext Certificate
        )
    };

    let certificate_verify = term! {
        fn_certificate_verify(
            fn_rsa_pss_signature_algorithm,
            (fn_payload_u16(
                (fn_rsa_sign_server(
                    (@certificate_transcript),
                    fn_alice_key,
                    fn_rsa_pss_signature_algorithm
                ))
            ))
        )
    };

    let certificate_verify_transcript = term! {
        fn_append_transcript(
            (@certificate_transcript),
            (@certificate_verify) // plaintext CertificateVerify
        )
    };

    let server_finished = term! {
        fn_finished(
            (fn_verify_data_server(
                (@certificate_verify_transcript),
                //(fn_server_finished_transcript(((client, 0)))),
                (@server_hello_transcript),
                (fn_get_client_key_share(((client, 0)), (@curve))),
                (@curve),
                fn_no_psk,
                fn_new_random,
                fn_cipher_suite13_aes_128_gcm_sha256
            ))
        )
    };

    Trace {
        prior_traces: vec![],
        descriptors: vec![AgentDescriptor::from_config(
            client,
            TLSDescriptorConfig {
                tls_version: TLSVersion::V1_3,
                typ: AgentType::Client,
                ..TLSDescriptorConfig::default()
            },
        )],
        steps: vec![
            OutputAction::new_step(client),
            Step {
                agent: client,
                action: Action::Input(input_action! { term! { @server_hello }
                }),
            },
            Step {
                agent: client,
                action: Action::Input(input_action! { term! {
                        fn_encrypt_handshake(
                            (@server_hello),
                            (@server_hello_transcript),
                            (fn_get_client_key_share(((client, 0)), (@curve))),
                            fn_no_psk,
                            (@curve),
                            fn_false,
                            fn_seq_0,  // sequence 0
                            fn_new_random,
                            fn_cipher_suite13_aes_128_gcm_sha256
                        )
                    }
                }),
            },
            Step {
                agent: client,
                action: Action::Input(input_action! { term! {
                        fn_encrypt_handshake(
                            (@certificate),
                            (@server_hello_transcript),
                            (fn_get_client_key_share(((client, 0)), (@curve))),
                            fn_no_psk,
                            (@curve),
                            fn_false,
                            fn_seq_1,  // sequence 1
                            fn_new_random,
                            fn_cipher_suite13_aes_128_gcm_sha256
                        )
                    }
                }),
            },
            Step {
                agent: client,
                action: Action::Input(input_action! { term! {
                        fn_encrypt_handshake(
                            (@certificate_verify),
                            (@server_hello_transcript),
                            (fn_get_client_key_share(((client, 0)), (@curve))),
                            fn_no_psk,
                            (@curve),
                            fn_false,
                            fn_seq_2,  // sequence 2
                            fn_new_random,
                            fn_cipher_suite13_aes_128_gcm_sha256
                        )
                    }
                }),
            },
            Step {
                agent: client,
                action: Action::Input(input_action! { term! {
                        fn_encrypt_handshake(
                            (@server_finished),
                            (@server_hello_transcript),
                            (fn_get_client_key_share(((client, 0)), (@curve))),
                            fn_no_psk,
                            (@curve),
                            fn_false,
                            fn_seq_3,  // sequence 3
                            fn_new_random,
                            fn_cipher_suite13_aes_128_gcm_sha256
                        )
                    }
                }),
            },
        ],
        ..Default::default()
    }
}

/// A WolfSSL TLS 1.3 client receiving a ServerHello with a PresharedKey extension when the client
/// hasn't requested the use of a preshared key, returns an IllegalParameter Alert instead of
/// UnsupportedExtension
/// <https://github.com/wolfSSL/wolfssl/issues/9503>
pub fn rfc_violation_bad_alert_non_requested_psk(
    client: AgentName,
    _server: AgentName,
) -> Trace<TLSProtocolTypes> {
    let curve = term! {
        fn_get_any_client_curve(
            ((client, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ClientHello)))])
        )
    };

    let server_hello = term! {
          fn_server_hello(
            fn_protocol_version12,
            fn_new_random,
            ((client, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ClientHello)))]),
            fn_cipher_suite13_aes_128_gcm_sha256,
            fn_compression,
            (fn_server_extensions_make(
              (fn_server_extensions_append(
                  (fn_server_extensions_append(
                      (fn_server_extensions_append(
                          fn_server_extensions_new,
                          (fn_key_share_deterministic_server_extension((@curve)))
                      )),
                      (fn_preshared_keys_server_extension((fn_u32_to_u16((fn_u64_to_u32(fn_seq_5))))))
                  )),
                  fn_supported_versions13_server_extension
            ))))
        )
    };

    Trace {
        prior_traces: vec![],
        descriptors: vec![AgentDescriptor::from_config(
            client,
            TLSDescriptorConfig {
                tls_version: TLSVersion::V1_3,
                typ: AgentType::Client,
                ..TLSDescriptorConfig::default()
            },
        )],
        steps: vec![
            OutputAction::new_step(client),
            Step {
                agent: client,
                action: Action::Input(input_action! { server_hello
                }),
            },
        ],
        ..Default::default()
    }
}

/// A WolfSSL TLS 1.3 server sending a HelloRetryRequest requesting a specific KeyShare can accept a
/// second ClientHello with a KeyShare not present in the HelloRetryRequest.
/// <https://github.com/wolfSSL/wolfssl/issues/9362>
pub fn rfc_violation_incorrect_keyshare_after_hrr(server: AgentName) -> Trace<TLSProtocolTypes> {
    let client_hello_1 = term! {
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
                                    (fn_support_group_extension_append(
                                        fn_support_group_extension_new,
                                        fn_named_group_x25519
                                    )),
                                    fn_named_group_secp256r1
                                ))
                            ))
                        )),
                        fn_signature_algorithm_extension
                    )),
                    (fn_key_share_deterministic_extension(fn_named_group_x25519))
                )),
                fn_supported_versions13_extension
            ))
        )))
    };

    let client_hello_2 = term! {
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

    Trace {
        prior_traces: vec![],
        descriptors: vec![AgentDescriptor::from_config(
            server,
            TLSDescriptorConfig {
                tls_version: TLSVersion::V1_3,
                typ: AgentType::Server,
                groups: Some(String::from("P-256:P-384")),
                ..TLSDescriptorConfig::default()
            },
        )],
        steps: vec![
            Step {
                agent: server,
                action: Action::Input(input_action! { term! {
                        @client_hello_1
                    }
                }),
            },
            OutputAction::new_step(server),
            Step {
                agent: server,
                action: Action::Input(input_action! { term! {
                        @client_hello_2
                    }
                }),
            },
            OutputAction::new_step(server),
        ],
        ..Default::default()
    }
}

/// A WolfSSL TLS 1.3 client receiving a ServerHello containing a duplicated extension (e.g. two
/// SupportedVersions) abort the connection but doesn't send an Alert.
/// <https://github.com/wolfSSL/wolfssl/issues/9520>
pub fn rfc_violation_no_alert_duplicate_extension(
    client: AgentName,
    _server: AgentName,
) -> Trace<TLSProtocolTypes> {
    let curve = term! {
        fn_get_any_client_curve(
            ((client, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ClientHello)))])
        )
    };

    let server_hello = term! {
          fn_server_hello(
            fn_protocol_version12,
            fn_new_random,
            ((client, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ClientHello)))]),
            fn_cipher_suite13_aes_128_gcm_sha256,
            fn_compression,
            (fn_server_extensions_make(
              (fn_server_extensions_append(
                  (fn_server_extensions_append(
                      (fn_server_extensions_append(
                          fn_server_extensions_new,
                          (fn_key_share_deterministic_server_extension((@curve)))
                      )),
                      fn_supported_versions13_server_extension
                  )),
                  fn_supported_versions13_server_extension
            ))))
        )
    };

    Trace {
        prior_traces: vec![],
        descriptors: vec![AgentDescriptor::from_config(
            client,
            TLSDescriptorConfig {
                tls_version: TLSVersion::V1_3,
                typ: AgentType::Client,
                ..TLSDescriptorConfig::default()
            },
        )],
        steps: vec![
            OutputAction::new_step(client),
            Step {
                agent: client,
                action: Action::Input(input_action! { server_hello
                }),
            },
        ],
        ..Default::default()
    }
}

/// WolfSSL can respond to a ClientHello without a SupportedGroup extension if the CH contains a
/// keyshare. This behavior happens only when setting the list of supported groups on the server
/// using wolfSSL_set_groups or wolfSSL_CTX_set1_groups_list or using --force-curve in the example
/// CLI. <https://github.com/wolfSSL/wolfssl/issues/9521>
/// <https://github.com/wolfSSL/wolfssl/issues/9247>
pub fn rfc_violation_missing_supported_group(server: AgentName) -> Trace<TLSProtocolTypes> {
    let client_hello = term! {
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
                            fn_client_extensions_new,
                        fn_signature_algorithm_extension
                    )),
                    (fn_key_share_deterministic_extension(fn_named_group_secp384r1))
                )),
                fn_supported_versions13_extension
            ))
        )))
    };

    Trace {
        prior_traces: vec![],
        descriptors: vec![AgentDescriptor::from_config(
            server,
            TLSDescriptorConfig {
                tls_version: TLSVersion::V1_3,
                typ: AgentType::Server,
                groups: Some(String::from("P-256:P-384")),
                ..TLSDescriptorConfig::default()
            },
        )],
        steps: vec![Step {
            agent: server,
            action: Action::Input(input_action! { term! {
                    @client_hello
                }
            }),
        }],
        ..Default::default()
    }
}

/// A WolfSSL TLS 1.3 client receiving a HelloRetryRequest followed by a ServerHello with another
/// cipher (eg. using TLS_AES_256_GCM_SHA384 in HRR and TLS_AES_128_GCM_SHA256 in ServerHello), will
/// continue the handshake while it should reject the ServerHello with an appropriate error.
/// <https://github.com/wolfSSL/wolfssl/issues/9331>
pub fn rfc_violation_changing_cipher_after_hrr(client: AgentName) -> Trace<TLSProtocolTypes> {
    let curve = term! {
        fn_get_any_client_curve(
            ((client, 1)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ClientHello)))])
        )
    };

    let server_hrr = term! {
        fn_hello_retry_request(
            fn_protocol_version12,
            fn_hello_retry_request_random,
            ((client, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ClientHello)))]),
            fn_cipher_suite13_aes_128_gcm_sha256,
            fn_compressions,
            (fn_hello_retry_extensions_make(
                (fn_hello_retry_extensions_append(
                    (fn_hello_retry_extensions_append(
                        fn_hello_retry_extensions_new,
                    fn_supported_versions13_hello_retry_extension
                    )),
                    // ask the client to use P384 curve for the second client hello
                    (fn_key_share_hello_retry_extension(fn_named_group_secp384r1))
                ))
            ))
        )
    };

    let server_hello = term! {
          fn_server_hello(
            fn_protocol_version12,
            fn_new_random,
            ((client, 1)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ClientHello)))]),
            fn_cipher_suite13_aes_256_gcm_sha384,
            fn_compression,
            (fn_server_extensions_make(
              (fn_server_extensions_append(
                  (fn_server_extensions_append(
                      fn_server_extensions_new,
                      (fn_key_share_deterministic_server_extension((@curve)))
                  )),
                  fn_supported_versions13_server_extension
            ))))
        )
    };

    Trace {
        prior_traces: vec![],
        descriptors: vec![AgentDescriptor::from_config(
            client,
            TLSDescriptorConfig {
                tls_version: TLSVersion::V1_3,
                typ: AgentType::Client,
                ..TLSDescriptorConfig::default()
            },
        )],
        steps: vec![
            OutputAction::new_step(client),
            Step {
                agent: client,
                action: Action::Input(input_action! { server_hrr }),
            },
            Step {
                agent: client,
                action: Action::Input(input_action! { server_hello }),
            },
        ],
        ..Default::default()
    }
}

/// When receiving a HelloRetryRequest (ServerHello with magic random value) which should trigger no
/// change in the ClientHello (the HRR only contains a SupportedVersion extension), WolfSSL TLS 1.3
/// client sends a ClientHello that is identical to its first ClientHello.
/// <https://github.com/wolfSSL/wolfssl/issues/9247>
pub fn rfc_violation_no_change_after_hrr(client: AgentName) -> Trace<TLSProtocolTypes> {
    let server_hrr = term! {
        fn_hello_retry_request(
            fn_protocol_version12,
            fn_hello_retry_request_random,
            ((client, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ClientHello)))]),
            fn_cipher_suite13_aes_128_gcm_sha256,
            fn_compressions,
            (fn_hello_retry_extensions_make(
                    (fn_hello_retry_extensions_append(
                        fn_hello_retry_extensions_new,
                    fn_supported_versions13_hello_retry_extension
                    ))
                ))
        )
    };

    Trace {
        prior_traces: vec![],
        descriptors: vec![AgentDescriptor::from_config(
            client,
            TLSDescriptorConfig {
                tls_version: TLSVersion::V1_3,
                typ: AgentType::Client,
                ..TLSDescriptorConfig::default()
            },
        )],
        steps: vec![
            OutputAction::new_step(client),
            Step {
                agent: client,
                action: Action::Input(input_action! { server_hrr }),
            },
        ],
        ..Default::default()
    }
}

/// An OpenSSL TLS 1.3 client receiving a ServerHello with a StatusRequest extension returns an
/// UnsupportedExtension Alert instead of an IllegalParameter alert
/// <https://github.com/openssl/openssl/issues/29353>
pub fn rfc_violation_incorrect_extension_in_sh(
    client: AgentName,
    _server: AgentName,
) -> Trace<TLSProtocolTypes> {
    let curve = term! {
        fn_get_any_client_curve(
            ((client, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ClientHello)))])
        )
    };

    let server_hello = term! {
          fn_server_hello(
            fn_protocol_version12,
            fn_new_random,
            ((client, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ClientHello)))]),
            fn_cipher_suite13_aes_128_gcm_sha256,
            fn_compression,
            (fn_server_extensions_make(
              (fn_server_extensions_append(
                  (fn_server_extensions_append(
                      (fn_server_extensions_append(
                          fn_server_extensions_new,
                          (fn_key_share_deterministic_server_extension((@curve)))
                      )),
                    fn_status_request_server_extension
                  )),
                  fn_supported_versions13_server_extension
            ))))
        )
    };

    Trace {
        prior_traces: vec![],
        descriptors: vec![AgentDescriptor::from_config(
            client,
            TLSDescriptorConfig {
                tls_version: TLSVersion::V1_3,
                typ: AgentType::Client,
                ..TLSDescriptorConfig::default()
            },
        )],
        steps: vec![
            OutputAction::new_step(client),
            Step {
                agent: client,
                action: Action::Input(input_action! { server_hello
                }),
            },
        ],
        ..Default::default()
    }
}
