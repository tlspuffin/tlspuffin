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
use crate::tls::rustls::key::fn_certificate;
use crate::tls::rustls::msgs::base::*;
use crate::tls::rustls::msgs::enums::{HandshakeType, *};
use crate::tls::rustls::msgs::handshake::{fn_compressions, *};
use crate::tls::rustls::msgs::message::*;

/// RFC violation triggering bad wolfSSL alert when SH contains unsupported cipher (HandshakeFailure
/// instead of IllegalParameter)
/// <https://github.com/wolfSSL/wolfssl/issues/9639>
pub fn rfc_violation_alert_unsupported_cipher_suite(
    client: AgentName,
    _server: AgentName,
) -> Trace<TLSProtocolTypes> {
    let curve = term! {
        D(K((client, 0) / KeyShareEntry), NamedGroup)
    };

    let server_hello = term! {
        fn_message(
            fn_protocolversion_tlsv1_2,
            fn_messagepayload_handshake(
                fn_handshakemessagepayload(
                    fn_handshaketype_serverhello,
                    fn_handshakepayload_serverhello(
                        fn_serverhellopayload(
                            fn_protocolversion_tlsv1_2,
                            fn_random,
                            K((client, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ClientHello)))]),
                            fn_ciphersuite_tls13_aes_128_ccm_sha256,
                            fn_compression_null,
                            (fn_serverextensions(
                                (fn_list_serverextension_append(
                                    (fn_list_serverextension_append(
                                        fn_list_serverextension_empty,
                                        (fn_serverextension_keyshare(
                                            (fn_key_share_deterministic((@curve)))
                                        ))
                                    )),
                                    fn_serverextension_supportedversions(fn_protocolversion_tlsv1_3)
                                ))
                            ))
                        )
                    )
                )
            )
        )
    };

    let server_hello_transcript = term! {
        fn_append_transcript(
            (fn_append_transcript(
                fn_new_transcript,
                K((client, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ClientHello)))]) // ClientHello
            )),
            (@server_hello) // plaintext ServerHello
        )
    };

    let encrypted_extensions = term! {
        fn_message(
            fn_protocolversion_tlsv1_2,
            fn_messagepayload_handshake(
                fn_handshakemessagepayload(
                    fn_handshaketype_encryptedextensions,
                    fn_handshakepayload_encryptedextensions(
                        fn_encryptedextensions(fn_list_serverextension_empty)
                    )
                )
            )
        )
    };

    let certificate = term! {
        fn_message(
            fn_protocolversion_tlsv1_2,
            fn_messagepayload_handshake(
                fn_handshakemessagepayload(
                    fn_handshaketype_certificate,
                    fn_handshakepayload_certificatetls13(
                        fn_certificatepayloadtls13(
                            (fn_payloadu8((fn_empty_bytes_vec))),
                            (fn_certificateentries(
                                (fn_list_certificateentry_append(
                                    fn_list_certificateentry_empty,
                                    (fn_certificateentry(
                                        fn_certificate(fn_alice_cert),
                                        (fn_certificateextensions(fn_list_certificateextension_empty))
                                    ))
                                ))
                            ))
                        )
                    )
                )
            )
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
        fn_message(
            fn_protocolversion_tlsv1_2,
            fn_messagepayload_handshake(
                fn_handshakemessagepayload(
                    fn_handshaketype_certificateverify,
                    fn_handshakepayload_certificateverify(
                        fn_digitallysignedstruct(
                            fn_signaturescheme_rsa_pss_sha256,
                            (fn_payloadu16(
                                (fn_rsa_sign_server(
                                    (@certificate_transcript),
                                    fn_alice_key,
                                    fn_signaturescheme_rsa_pss_sha256
                                ))
                            ))
                        )
                    )
                )
            )
        )
    };

    let certificate_verify_transcript = term! {
        fn_append_transcript(
            (@certificate_transcript),
            (@certificate_verify) // plaintext CertificateVerify
        )
    };

    let server_finished = term! {
        fn_message(
            fn_protocolversion_tlsv1_2,
            fn_messagepayload_handshake(
                fn_handshakemessagepayload(
                    fn_handshaketype_finished,
                    fn_handshakepayload_finished(
                        fn_payload(
                            (fn_verify_data_server(
                                (@certificate_verify_transcript),
                                //(fn_server_finished_transcript(((client, 0)))),
                                (@server_hello_transcript),
                                (fn_get_client_key_share(K((client, 0)), (@curve))),
                                (@curve),
                                fn_no_psk,
                                fn_random,
                                fn_ciphersuite_tls13_aes_128_gcm_sha256
                            ))
                        )
                    )
                )
            )
        )
    };

    let mut descriptor_config = TLSDescriptorConfig {
        tls_version: TLSVersion::V1_3,
        typ: AgentType::Client,
        ..TLSDescriptorConfig::default()
    };

    descriptor_config.set_cipher_string(String::from(
        "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256",
    ));

    Trace {
        prior_traces: vec![],
        descriptors: vec![AgentDescriptor::from_config(client, descriptor_config)],
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
                        (fn_get_client_key_share(K((client, 0)), (@curve))),
                        fn_no_psk,
                        (@curve),
                        fn_false,
                        fn_seq_0,
                        // sequence 0
                        fn_random,
                        fn_ciphersuite_tls13_aes_128_gcm_sha256
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
                        (fn_get_client_key_share(K((client, 0)), (@curve))),
                        fn_no_psk,
                        (@curve),
                        fn_false,
                        fn_seq_1,
                        // sequence 1
                        fn_random,
                        fn_ciphersuite_tls13_aes_128_gcm_sha256
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
                        (fn_get_client_key_share(K((client, 0)), (@curve))),
                        fn_no_psk,
                        (@curve),
                        fn_false,
                        fn_seq_2,
                        // sequence 2
                        fn_random,
                        fn_ciphersuite_tls13_aes_128_gcm_sha256
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
                        (fn_get_client_key_share(K((client, 0)), (@curve))),
                        fn_no_psk,
                        (@curve),
                        fn_false,
                        fn_seq_3,
                        // sequence 3
                        fn_random,
                        fn_ciphersuite_tls13_aes_128_gcm_sha256
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
                                        (fn_keyshareentry(
                                            fn_namedgroup_secp384r1,
                                            (fn_payloadu16(fn_empty_bytes_vec))
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

    let server_hello_transcript = term! {
        fn_append_transcript(
            (fn_append_transcript(
                fn_new_transcript,
                (@client_hello) // ClientHello
            )),
            K((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerHello)))]) // plaintext ServerHello
        )
    };

    // ((0, 1)) could be a CCS the server sends one

    let extensions = term! {
        fn_decrypt_handshake_flight(
            K((server, 0)/MessageFlight),
            // The first flight of messages sent by the server
            (@server_hello_transcript),
            (fn_psk(D(K((server, 0) / KeyShareEntry), Vec<u8>))),
            fn_no_psk,
            fn_namedgroup_secp384r1,
            fn_true,
            fn_seq_0,
            // sequence 0
            fn_random,
            fn_ciphersuite_tls13_aes_128_gcm_sha256
        )
    };

    let encrypted_extensions = term! {
        D(
            (@extensions),
            [Some(TlsQueryMatcher::Handshake(Some(HandshakeType::EncryptedExtensions)))] / Message
        )
    };

    let encrypted_extension_transcript = term! {
        fn_append_transcript(
            (@server_hello_transcript),
            (@encrypted_extensions) // plaintext Encrypted Extensions
        )
    };

    let server_certificate = term! {
        D(
            (@extensions),
            [Some(TlsQueryMatcher::Handshake(Some(HandshakeType::Certificate)))] / Message
        )
    };

    let server_certificate_transcript = term! {
        fn_append_transcript(
            (@encrypted_extension_transcript),
            (@server_certificate) // plaintext Server Certificate
        )
    };

    let server_certificate_verify = term! {
        D(
            (@extensions),
            [Some(TlsQueryMatcher::Handshake(Some(HandshakeType::CertificateVerify)))] / Message
        )
    };

    let server_certificate_verify_transcript = term! {
        fn_append_transcript(
            (@server_certificate_transcript),
            (@server_certificate_verify) // plaintext Server Certificate Verify
        )
    };

    let server_finished = term! {
        D(
            (@extensions),
            [Some(TlsQueryMatcher::Handshake(Some(HandshakeType::Finished)))] / Message
        )
    };

    let server_finished_transcript = term! {
        fn_append_transcript(
            (@server_certificate_verify_transcript),
            (@server_finished) // plaintext Server Handshake Finished
        )
    };

    let client_finished = term! {
        fn_message(
            fn_protocolversion_tlsv1_2,
            fn_messagepayload_handshake(
                fn_handshakemessagepayload(
                    fn_handshaketype_finished,
                    fn_handshakepayload_finished(
                        fn_payload(
                            (fn_verify_data(
                                (@server_finished_transcript),
                                (@server_hello_transcript),
                                (fn_psk(D(K((server, 0) / KeyShareEntry), Vec<u8>))),
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
                        (fn_psk(D(K((server, 0) / KeyShareEntry), Vec<u8>))),
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

/// A WolfSSL TLS 1.3 client receiving encrypted out of order messages will detect the error and log
/// "Out of order message, fatal" without sending an alert.
/// <https://github.com/wolfSSL/wolfssl/issues/9531>
pub fn rfc_violation_missing_alert_out_of_order_encrypted(
    client: AgentName,
    _server: AgentName,
) -> Trace<TLSProtocolTypes> {
    let curve = term! {
        D(K((client, 0) / KeyShareEntry), NamedGroup)
    };

    let server_hello = term! {
        fn_message(
            fn_protocolversion_tlsv1_2,
            fn_messagepayload_handshake(
                fn_handshakemessagepayload(
                    fn_handshaketype_serverhello,
                    fn_handshakepayload_serverhello(
                        fn_serverhellopayload(
                            fn_protocolversion_tlsv1_2,
                            fn_random,
                            K((client, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ClientHello)))]),
                            fn_ciphersuite_tls13_aes_128_gcm_sha256,
                            fn_compression_null,
                            (fn_serverextensions(
                                (fn_list_serverextension_append(
                                    (fn_list_serverextension_append(
                                        fn_list_serverextension_empty,
                                        (fn_serverextension_keyshare(
                                            (fn_key_share_deterministic((@curve)))
                                        ))
                                    )),
                                    fn_serverextension_supportedversions(fn_protocolversion_tlsv1_3)
                                ))
                            ))
                        )
                    )
                )
            )
        )
    };

    let server_hello_transcript = term! {
        fn_append_transcript(
            (fn_append_transcript(
                fn_new_transcript,
                K((client, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ClientHello)))]) // ClientHello
            )),
            (@server_hello) // plaintext ServerHello
        )
    };

    let encrypted_extensions = term! {
        fn_message(
            fn_protocolversion_tlsv1_2,
            fn_messagepayload_handshake(
                fn_handshakemessagepayload(
                    fn_handshaketype_encryptedextensions,
                    fn_handshakepayload_encryptedextensions(
                        fn_encryptedextensions(fn_list_serverextension_empty)
                    )
                )
            )
        )
    };

    let certificate = term! {
        fn_message(
            fn_protocolversion_tlsv1_2,
            fn_messagepayload_handshake(
                fn_handshakemessagepayload(
                    fn_handshaketype_certificate,
                    fn_handshakepayload_certificatetls13(
                        fn_certificatepayloadtls13(
                            (fn_payloadu8((fn_empty_bytes_vec))),
                            (fn_certificateentries(
                                (fn_list_certificateentry_append(
                                    fn_list_certificateentry_empty,
                                    (fn_certificateentry(
                                        fn_certificate(fn_alice_cert),
                                        (fn_certificateextensions(fn_list_certificateextension_empty))
                                    ))
                                ))
                            ))
                        )
                    )
                )
            )
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
        fn_message(
            fn_protocolversion_tlsv1_2,
            fn_messagepayload_handshake(
                fn_handshakemessagepayload(
                    fn_handshaketype_certificateverify,
                    fn_handshakepayload_certificateverify(
                        fn_digitallysignedstruct(
                            fn_signaturescheme_rsa_pss_sha256,
                            (fn_payloadu16(
                                (fn_rsa_sign_server(
                                    (@certificate_transcript),
                                    fn_alice_key,
                                    fn_signaturescheme_rsa_pss_sha256
                                ))
                            ))
                        )
                    )
                )
            )
        )
    };

    let certificate_verify_transcript = term! {
        fn_append_transcript(
            (@certificate_transcript),
            (@certificate_verify) // plaintext CertificateVerify
        )
    };

    let server_finished = term! {
        fn_message(
            fn_protocolversion_tlsv1_2,
            fn_messagepayload_handshake(
                fn_handshakemessagepayload(
                    fn_handshaketype_finished,
                    fn_handshakepayload_finished(
                        fn_payload(
                            (fn_verify_data_server(
                                (@certificate_verify_transcript),
                                //(fn_server_finished_transcript(((client, 0)))),
                                (@server_hello_transcript),
                                (fn_get_client_key_share(K((client, 0)), (@curve))),
                                (@curve),
                                fn_no_psk,
                                fn_random,
                                fn_ciphersuite_tls13_aes_128_gcm_sha256
                            ))
                        )
                    )
                )
            )
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
                action: Action::Input(input_action! { term! {
                    @server_hello
                }
                }),
            },
            Step {
                agent: client,
                action: Action::Input(input_action! { term! {
                    fn_encrypt_handshake(
                        (@server_hello),
                        (@server_hello_transcript),
                        (fn_get_client_key_share(K((client, 0)), (@curve))),
                        fn_no_psk,
                        (@curve),
                        fn_false,
                        fn_seq_0,
                        // sequence 0
                        fn_random,
                        fn_ciphersuite_tls13_aes_128_gcm_sha256
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
                        (fn_get_client_key_share(K((client, 0)), (@curve))),
                        fn_no_psk,
                        (@curve),
                        fn_false,
                        fn_seq_1,
                        // sequence 1
                        fn_random,
                        fn_ciphersuite_tls13_aes_128_gcm_sha256
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
                        (fn_get_client_key_share(K((client, 0)), (@curve))),
                        fn_no_psk,
                        (@curve),
                        fn_false,
                        fn_seq_2,
                        // sequence 2
                        fn_random,
                        fn_ciphersuite_tls13_aes_128_gcm_sha256
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
                        (fn_get_client_key_share(K((client, 0)), (@curve))),
                        fn_no_psk,
                        (@curve),
                        fn_false,
                        fn_seq_3,
                        // sequence 3
                        fn_random,
                        fn_ciphersuite_tls13_aes_128_gcm_sha256
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
        D(K((client, 0) / KeyShareEntry), NamedGroup)
    };

    let server_hello = term! {
        fn_message(
            fn_protocolversion_tlsv1_2,
            fn_messagepayload_handshake(
                fn_handshakemessagepayload(
                    fn_handshaketype_serverhello,
                    fn_handshakepayload_serverhello(
                        fn_serverhellopayload(
                            fn_protocolversion_tlsv1_2,
                            fn_random,
                            K((client, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ClientHello)))]),
                            fn_ciphersuite_tls13_aes_128_gcm_sha256,
                            fn_compression_null,
                            (fn_serverextensions(
                                (fn_list_serverextension_append(
                                    (fn_list_serverextension_append(
                                        (fn_list_serverextension_append(
                                            fn_list_serverextension_empty,
                                            (fn_serverextension_keyshare(
                                                (fn_key_share_deterministic((@curve)))
                                            ))
                                        )),
                                        (fn_serverextension_presharedkey(
                                            (fn_u32_to_u16((fn_u64_to_u32(fn_seq_5))))
                                        ))
                                    )),
                                    fn_serverextension_supportedversions(fn_protocolversion_tlsv1_3)
                                ))
                            ))
                        )
                    )
                )
            )
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
                                                            (fn_list_namedgroup_append(
                                                                fn_list_namedgroup_empty,
                                                                fn_namedgroup_x25519
                                                            )),
                                                            fn_namedgroup_secp256r1
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
                                                    (fn_key_share_deterministic(fn_namedgroup_x25519))
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

    let client_hello_2 = term! {
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
        D(K((client, 0) / KeyShareEntry), NamedGroup)
    };

    let server_hello = term! {
        fn_message(
            fn_protocolversion_tlsv1_2,
            fn_messagepayload_handshake(
                fn_handshakemessagepayload(
                    fn_handshaketype_serverhello,
                    fn_handshakepayload_serverhello(
                        fn_serverhellopayload(
                            fn_protocolversion_tlsv1_2,
                            fn_random,
                            K((client, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ClientHello)))]),
                            fn_ciphersuite_tls13_aes_128_gcm_sha256,
                            fn_compression_null,
                            (fn_serverextensions(
                                (fn_list_serverextension_append(
                                    (fn_list_serverextension_append(
                                        (fn_list_serverextension_append(
                                            fn_list_serverextension_empty,
                                            (fn_serverextension_keyshare(
                                                (fn_key_share_deterministic((@curve)))
                                            ))
                                        )),
                                        fn_serverextension_supportedversions(
                                            fn_protocolversion_tlsv1_3
                                        )
                                    )),
                                    fn_serverextension_supportedversions(fn_protocolversion_tlsv1_3)
                                ))
                            ))
                        )
                    )
                )
            )
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
                                            fn_list_clientextension_empty,
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
        D(K((client, 1) / KeyShareEntry), NamedGroup)
    };

    let server_hrr = term! {
        fn_hello_retry_request(
            fn_protocolversion_tlsv1_2,
            fn_hello_retry_request_random,
            K((client, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ClientHello)))]),
            fn_ciphersuite_tls13_aes_128_gcm_sha256,
            fn_compressions(
                fn_list_compression_append(fn_list_compression_empty, fn_compression_null)
            ),
            (fn_helloretryextensions(
                (fn_list_helloretryextension_append(
                    (fn_list_helloretryextension_append(
                        fn_list_helloretryextension_empty,
                        fn_helloretryextension_supportedversions(fn_protocolversion_tlsv1_3)
                    )),
                    // ask the client to use P384 curve for the second client hello
                    (fn_helloretryextension_keyshare(fn_namedgroup_secp384r1))
                ))
            ))
        )
    };

    let server_hello = term! {
        fn_message(
            fn_protocolversion_tlsv1_2,
            fn_messagepayload_handshake(
                fn_handshakemessagepayload(
                    fn_handshaketype_serverhello,
                    fn_handshakepayload_serverhello(
                        fn_serverhellopayload(
                            fn_protocolversion_tlsv1_2,
                            fn_random,
                            K((client, 1)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ClientHello)))]),
                            fn_ciphersuite_tls13_aes_256_gcm_sha384,
                            fn_compression_null,
                            (fn_serverextensions(
                                (fn_list_serverextension_append(
                                    (fn_list_serverextension_append(
                                        fn_list_serverextension_empty,
                                        (fn_serverextension_keyshare(
                                            (fn_key_share_deterministic((@curve)))
                                        ))
                                    )),
                                    fn_serverextension_supportedversions(fn_protocolversion_tlsv1_3)
                                ))
                            ))
                        )
                    )
                )
            )
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
            fn_protocolversion_tlsv1_2,
            fn_hello_retry_request_random,
            K((client, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ClientHello)))]),
            fn_ciphersuite_tls13_aes_128_gcm_sha256,
            fn_compressions(
                fn_list_compression_append(fn_list_compression_empty, fn_compression_null)
            ),
            (fn_helloretryextensions(
                (fn_list_helloretryextension_append(
                    fn_list_helloretryextension_empty,
                    fn_helloretryextension_supportedversions(fn_protocolversion_tlsv1_3)
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
        D(K((client, 0) / KeyShareEntry), NamedGroup)
    };

    let server_hello = term! {
        fn_message(
            fn_protocolversion_tlsv1_2,
            fn_messagepayload_handshake(
                fn_handshakemessagepayload(
                    fn_handshaketype_serverhello,
                    fn_handshakepayload_serverhello(
                        fn_serverhellopayload(
                            fn_protocolversion_tlsv1_2,
                            fn_random,
                            K((client, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ClientHello)))]),
                            fn_ciphersuite_tls13_aes_128_gcm_sha256,
                            fn_compression_null,
                            (fn_serverextensions(
                                (fn_list_serverextension_append(
                                    (fn_list_serverextension_append(
                                        (fn_list_serverextension_append(
                                            fn_list_serverextension_empty,
                                            (fn_serverextension_keyshare(
                                                (fn_key_share_deterministic((@curve)))
                                            ))
                                        )),
                                        fn_serverextension_certificatestatusack
                                    )),
                                    fn_serverextension_supportedversions(fn_protocolversion_tlsv1_3)
                                ))
                            ))
                        )
                    )
                )
            )
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

/// A WolfSSL TLS 1.3 server receiving a second ClientHello after a HelloRetryRequest with another
/// cipher, after the Server has selected a cipher (eg. using `TLS_AES_256_GCM_SHA384` in first CH
/// and `TLS_AES_128_GCM_SHA256` in the second), will continue the handshake while it should
/// reject the second ClientHello with an appropriate error.
pub fn rfc_violation_client_changing_cipher_hrr(server: AgentName) -> Trace<TLSProtocolTypes> {
    let client_hello_1 = term! {
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
                                                            (fn_list_namedgroup_append(
                                                                fn_list_namedgroup_empty,
                                                                fn_namedgroup_x25519
                                                            )),
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
                                                    (fn_key_share_deterministic(fn_namedgroup_x25519))
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

    let client_hello_2 = term! {
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
                                    fn_ciphersuite_tls13_aes_256_gcm_sha384
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
