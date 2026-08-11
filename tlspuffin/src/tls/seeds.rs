//! Implementation of  special traces. Each may represent a special TLS execution like a full
//! handshake or an execution which crashes OpenSSL.
//!
//! # Function symbols used here
//!
//! The recipes are built from the constructors *generated* by `#[derive(Constructor)]` on the
//! rustls message types rather than from hand-written ones, so that the term algebra sees the
//! same structure as the Rust types:
//!
//! * a message is `fn_message(version, fn_messagepayload_<kind>(..))`, and a handshake message
//!   additionally goes through `fn_handshakemessagepayload(fn_handshaketype_<kind>, ..)` and
//!   `fn_handshakepayload_<kind>(..)`;
//! * lists are `fn_list_<element>_empty` / `fn_list_<element>_append`, wrapped into their newtype
//!   by that type's own constructor (`fn_ciphersuites`, `fn_clientextensions`, ...);
//! * sub-values are extracted with the `D(source, [matcher] / Type)` deconstructor terms instead of
//!   hand-written `fn_find_*` / `fn_get_*` accessors;
//! * what an agent learned during the execution is read with the knowledge query `K((agent,
//!   counter) [matcher] / Type)` (the source may also be a `!"label"` precomputation), and what it
//!   claimed with the claim query `C((agent, counter) [matcher] / Type)` — the latter being the
//!   only way to reach the transcripts and the `Finished` claim.
//!
//! Hand-written symbols remain only where no generated constructor can replace them:
//!
//! * value corpora — a constant of a type whose constructor takes data the term algebra cannot
//!   produce, or a specific interesting value: `fn_random`, `fn_sessionid`,
//!   `fn_hello_retry_request_random`, `fn_alice_cert` and friends, `fn_invalid_signature_algorithm`
//!   (a `SignatureScheme::Unknown` with a specific ordinal), `fn_empty_bytes_vec`, `fn_seq_*`;
//! * constructors whose type has a *non-compositional* encoding, i.e. whose fields do not appear in
//!   the parent's encoding as their own encoding: `fn_hello_retry_request` and
//!   `fn_certificate_request13` (see the comments on `HelloRetryRequest` and
//!   `CertificateRequestPayloadTLS13`);
//! * constructors whose type only has a dummy codec, so a term of that type has no meaningful
//!   encoding: `fn_unknown_*_extension` (`UnknownExtension`), `fn_session_ticket_request_extension`
//!   / `fn_session_ticket_offer_extension` (`ClientSessionTicket`);
//! * everything that computes rather than constructs (transcripts, key shares, signatures,
//!   en/decryption);
//! * `fn_get_client_key_share`, the one accessor a deconstructor cannot express: it selects the key
//!   share *matching a named group*, while a deconstructor selects by position. Everything else is
//!   extracted structurally — the server key share is `fn_psk(D((..)[ServerHello] / KeyShareEntry),
//!   Vec<u8>))` (`fn_psk` being the `Some` constructor of `Option<Vec<u8>>`), the
//!   CertificateRequest context and the NewSessionTicket nonce are `D((..), Vec<u8>)`.
#![allow(dead_code)]

use puffin::agent::{AgentDescriptor, AgentName};
use puffin::algebra::dynamic_function::TypeShape;
use puffin::algebra::Term;
use puffin::trace::{Action, InputAction, OutputAction, Precomputation, Step, Trace};
use puffin::{input_action, term};

use crate::protocol::{
    fn_messageflight, AgentType, MessageFlight, TLSDescriptorConfig, TLSProtocolBehavior,
    TLSProtocolTypes, TLSVersion,
};
use crate::query::TlsQueryMatcher;
use crate::tls::fn_impl::*;
// `fn_certificate` is generated for `key::Certificate`; it shadows the (now unregistered)
// hand-written `fn_impl::fn_certificate` message constructor glob-imported above.
use crate::tls::rustls::key::{
    fn_certificate, fn_list_certificate_append, fn_list_certificate_empty,
};
use crate::tls::rustls::msgs::base::*;
use crate::tls::rustls::msgs::ccs::fn_changecipherspecpayload;
use crate::tls::rustls::msgs::enums::*;
// The `Compressions` constructor generated in `handshake` shadows the hand-written
// `fn_impl::fn_compressions` glob-imported above (both are named `fn_compressions`).
use crate::tls::rustls::msgs::handshake::fn_compressions;
use crate::tls::rustls::msgs::handshake::*;
use crate::tls::rustls::msgs::message::*;

pub fn seed_successful_client_auth(
    client: AgentName,
    server: AgentName,
) -> Trace<TLSProtocolTypes> {
    Trace {
        prior_traces: vec![],
        descriptors: vec![
            AgentDescriptor::from_config(
                client,
                TLSDescriptorConfig {
                    tls_version: TLSVersion::V1_3,
                    typ: AgentType::Client,
                    client_authentication: true,
                    ..TLSDescriptorConfig::default()
                },
            ),
            AgentDescriptor::from_config(
                server,
                TLSDescriptorConfig {
                    tls_version: TLSVersion::V1_3,
                    typ: AgentType::Server,
                    client_authentication: true,
                    ..TLSDescriptorConfig::default()
                },
            ),
        ],
        steps: vec![
            OutputAction::new_step(client),
            // Client Hello Client -> Server
            Step {
                agent: server,
                action: Action::Input(input_action! { term! {
                    fn_message(
                        fn_protocolversion_tlsv1_2,
                        fn_messagepayload_handshake(
                            fn_handshakemessagepayload(
                                fn_handshaketype_clienthello,
                                fn_handshakepayload_clienthello(
                                    fn_clienthellopayload(
                                        K((client, 0)),
                                        K((client, 0)),
                                        K((client, 0)),
                                        K((client, 0)),
                                        K((client, 0)),
                                        K((client, 0))
                                    )
                                )
                            )
                        )
                    )
                }
                }),
            },
            // Server Hello Server -> Client
            Step {
                agent: client,
                action: Action::Input(input_action! { term! {
                    fn_message(
                        fn_protocolversion_tlsv1_2,
                        fn_messagepayload_handshake(
                            fn_handshakemessagepayload(
                                fn_handshaketype_serverhello,
                                fn_handshakepayload_serverhello(
                                    fn_serverhellopayload(
                                        K((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerHello)))]/ProtocolVersion),
                                        K((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerHello)))]/Random),
                                        K((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerHello)))]/SessionID),
                                        K((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerHello)))]/CipherSuite),
                                        K((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerHello)))]/Compression),
                                        K((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerHello)))]/ServerExtensions)
                                    )
                                )
                            )
                        )
                    )
                }
                }),
            },
            // Encrypted Extensions Server -> Client
            Step {
                agent: client,
                action: Action::Input(input_action! { term! {
                    fn_message(
                        fn_protocolversion_tlsv1_2,
                        fn_messagepayload_applicationdata(
                            fn_payload(
                                K((server, 0)[Some(TlsQueryMatcher::ApplicationData)]/Vec<u8>)
                            )
                        )
                    )
                }
                }),
            },
            // Certificate Request Server -> Client
            Step {
                agent: client,
                action: Action::Input(input_action! {term! {
                    fn_message(
                        fn_protocolversion_tlsv1_2,
                        fn_messagepayload_applicationdata(
                            fn_payload(
                                K((server, 1)[Some(TlsQueryMatcher::ApplicationData)]/Vec<u8>)
                            )
                        )
                    )
                }
                }),
            },
            // Certificate Server -> Client
            Step {
                agent: client,
                action: Action::Input(input_action! {term! {
                    fn_message(
                        fn_protocolversion_tlsv1_2,
                        fn_messagepayload_applicationdata(
                            fn_payload(
                                K((server, 2)[Some(TlsQueryMatcher::ApplicationData)]/Vec<u8>)
                            )
                        )
                    )
                }
                }),
            },
            // Certificate Verify Server -> Client
            Step {
                agent: client,
                action: Action::Input(input_action! {term! {
                    fn_message(
                        fn_protocolversion_tlsv1_2,
                        fn_messagepayload_applicationdata(
                            fn_payload(
                                K((server, 3)[Some(TlsQueryMatcher::ApplicationData)]/Vec<u8>)
                            )
                        )
                    )
                }
                }),
            },
            // Finish Server -> Client
            Step {
                agent: client,
                action: Action::Input(input_action! { term! {
                    fn_message(
                        fn_protocolversion_tlsv1_2,
                        fn_messagepayload_applicationdata(
                            fn_payload(
                                K((server, 4)[Some(TlsQueryMatcher::ApplicationData)]/Vec<u8>)
                            )
                        )
                    )
                }
                }),
            },
            // Certificate Client -> Server
            Step {
                agent: server,
                action: Action::Input(input_action! { term! {
                    fn_message(
                        fn_protocolversion_tlsv1_2,
                        fn_messagepayload_applicationdata(
                            fn_payload(
                                K((client, 0)[Some(TlsQueryMatcher::ApplicationData)]/Vec<u8>)
                            )
                        )
                    )
                }
                }),
            },
            // CertificateVerify Client -> Server
            Step {
                agent: server,
                action: Action::Input(input_action! { term! {
                    fn_message(
                        fn_protocolversion_tlsv1_2,
                        fn_messagepayload_applicationdata(
                            fn_payload(
                                K((client, 1)[Some(TlsQueryMatcher::ApplicationData)]/Vec<u8>)
                            )
                        )
                    )
                }
                }),
            },
            // Finished Client -> Server
            Step {
                agent: server,
                action: Action::Input(input_action! { term! {
                    fn_message(
                        fn_protocolversion_tlsv1_2,
                        fn_messagepayload_applicationdata(
                            fn_payload(
                                K((client, 2)[Some(TlsQueryMatcher::ApplicationData)]/Vec<u8>)
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

// TODO: `[BAD_DECRYPT] [DECRYPTION_FAILED_OR_BAD_RECORD_MAC]` error with BoringSSL
pub fn seed_successful(client: AgentName, server: AgentName) -> Trace<TLSProtocolTypes> {
    Trace {
        prior_traces: vec![],
        descriptors: vec![
            TLSDescriptorConfig::new_client(client, TLSVersion::V1_3),
            TLSDescriptorConfig::new_server(server, TLSVersion::V1_3),
        ],
        steps: vec![
            OutputAction::new_step(client),
            // Client Hello Client -> Server
            Step {
                agent: server,
                action: Action::Input(input_action! { term! {
                    K((client, 0)/MessageFlight)
                }
                }),
            },
            // ServerHello/EncryptedExtensions/Certificate/CertificateVerify/ServerFinished ->
            // Client
            Step {
                agent: client,
                action: Action::Input(input_action! { term! {
                    K((server, 0)/MessageFlight)
                }
                }),
            },
            // Client Finished -> server
            Step {
                agent: server,
                action: Action::Input(input_action! { term! {
                    K((client, 1)/MessageFlight)
                }
                }),
            },
        ],
        ..Default::default()
    }
}

/// Seed which triggers a MITM attack. It changes the cipher suite. This should fail.
pub fn seed_successful_mitm(client: AgentName, server: AgentName) -> Trace<TLSProtocolTypes> {
    Trace {
        prior_traces: vec![],
        descriptors: vec![
            TLSDescriptorConfig::new_client(client, TLSVersion::V1_3),
            TLSDescriptorConfig::new_server(server, TLSVersion::V1_3),
        ],
        steps: vec![
            OutputAction::new_step(client),
            // Client Hello Client -> Server
            Step {
                agent: server,
                action: Action::Input(input_action! { term! {
                    fn_message(
                        fn_protocolversion_tlsv1_2,
                        fn_messagepayload_handshake(
                            fn_handshakemessagepayload(
                                fn_handshaketype_clienthello,
                                fn_handshakepayload_clienthello(
                                    fn_clienthellopayload(
                                        K((client, 0)),
                                        K((client, 0)),
                                        K((client, 0)),
                                        (fn_ciphersuites(
                                            (fn_list_ciphersuite_append(
                                                fn_list_ciphersuite_empty,
                                                fn_ciphersuite_tls13_aes_128_gcm_sha256
                                            ))
                                        )),
                                        K((client, 0)),
                                        K((client, 0))
                                    )
                                )
                            )
                        )
                    )
                }
                }),
            },
            // ServerHello/EncryptedExtensions/Certificate/CertificateVerify/ServerFinished ->
            // Client
            Step {
                agent: client,
                action: Action::Input(input_action! { term! {
                    K((server, 0)/MessageFlight)
                }
                }),
            },
            // Client Finished -> server
            Step {
                agent: server,
                action: Action::Input(input_action! { term! {
                    K((client, 1)/MessageFlight)
                }
                }),
            },
        ],
        ..Default::default()
    }
}

// TODO: `[RENEGOTIATION_MISMATCH] [ERROR_PARSING_EXTENSION] [PARSE_TLSEXT]` error with BoringSSL
pub fn seed_successful12_with_tickets(
    client: AgentName,
    server: AgentName,
) -> Trace<TLSProtocolTypes> {
    let mut trace = seed_successful12(client, server);
    // NewSessionTicket, Server -> Client
    // wolfSSL 4.4.0 does not support tickets in TLS 1.2
    trace.steps.insert(
        9,
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
                                    K((server, 0)/u32),
                                    (fn_payloadu16(
                                        K((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::NewSessionTicket)))]/Vec<u8>)
                                    ))
                                )
                            )
                        )
                    )
                )
            }
            }),
        },
    );

    trace.steps[11] = Step {
        agent: client,
        action: Action::Input(input_action! { term! {
            K((server, 6)[None])> TypeShape::of::<OpaqueMessage>()
        }
        }),
    };

    trace
}

pub fn seed_successful12(client: AgentName, server: AgentName) -> Trace<TLSProtocolTypes> {
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
                                        K((client, 0)),
                                        K((client, 0)),
                                        K((client, 0)),
                                        K((client, 0)),
                                        K((client, 0)),
                                        K((client, 0))
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
                                        K((server, 0)),
                                        K((server, 0)),
                                        K((server, 0)),
                                        K((server, 0)),
                                        K((server, 0)),
                                        K((server, 0))
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
                                    fn_certificatepayload(K((server, 0)))
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
                                            K((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerKeyExchange)))]/Vec<u8>)
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
                                        K((client, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ClientKeyExchange)))]/Vec<u8>)
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
                    K((client, 3)[None]) > TypeShape::of::<OpaqueMessage>()
                }
                }),
            },
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
            // Server Handshake Finished, Server -> Client
            Step {
                agent: client,
                action: Action::Input(input_action! { term! {
                    K((server, 5)[None]) > TypeShape::of::<OpaqueMessage>()
                }
                }),
            },
        ],
        ..Default::default()
    }
}

/// This seed performs a TLS 1.2 handshake between a client and a server by only
/// forwarding messages between the agents
pub fn seed_successful12_forward(client: AgentName, server: AgentName) -> Trace<TLSProtocolTypes> {
    Trace {
        prior_traces: vec![],
        descriptors: vec![
            TLSDescriptorConfig::new_client(client, TLSVersion::V1_2),
            TLSDescriptorConfig::new_server(server, TLSVersion::V1_2),
        ],
        steps: vec![
            OutputAction::new_step(client),
            // Client Hello Client -> Server
            Step {
                agent: server,
                action: Action::Input(input_action! { term! {
                    K((client, 0)/MessageFlight)
                }
                }),
            },
            // ServerHello/EncryptedExtensions/Certificate/CertificateVerify/ServerFinished ->
            // Client
            Step {
                agent: client,
                action: Action::Input(input_action! { term! {
                    K((server, 0)/MessageFlight)
                }
                }),
            },
            // Client Finished -> server
            Step {
                agent: server,
                action: Action::Input(input_action! { term! {
                    K((client, 1)/MessageFlight)
                }
                }),
            },
            Step {
                agent: client,
                action: Action::Input(input_action! { term! {
                    K((server, 1)/MessageFlight)
                }
                }),
            },
        ],
        ..Default::default()
    }
}

// TODO: `[BAD_DECRYPT] [DECRYPTION_FAILED_OR_BAD_RECORD_MAC]` error with BoringSSL
pub fn seed_successful_with_ccs(client: AgentName, server: AgentName) -> Trace<TLSProtocolTypes> {
    Trace {
        prior_traces: vec![],
        descriptors: vec![
            TLSDescriptorConfig::new_client(client, TLSVersion::V1_3),
            TLSDescriptorConfig::new_server(server, TLSVersion::V1_3),
        ],
        steps: vec![
            OutputAction::new_step(client),
            // Client Hello Client -> Server
            Step {
                agent: server,
                action: Action::Input(input_action! { term! {
                    fn_message(
                        fn_protocolversion_tlsv1_2,
                        fn_messagepayload_handshake(
                            fn_handshakemessagepayload(
                                fn_handshaketype_clienthello,
                                fn_handshakepayload_clienthello(
                                    fn_clienthellopayload(
                                        K((client, 0)),
                                        K((client, 0)),
                                        K((client, 0)),
                                        K((client, 0)),
                                        K((client, 0)),
                                        K((client, 0))
                                    )
                                )
                            )
                        )
                    )
                }
                }),
            },
            // Server Hello Server -> Client
            Step {
                agent: client,
                action: Action::Input(input_action! { term! {
                    fn_message(
                        fn_protocolversion_tlsv1_2,
                        fn_messagepayload_handshake(
                            fn_handshakemessagepayload(
                                fn_handshaketype_serverhello,
                                fn_handshakepayload_serverhello(
                                    fn_serverhellopayload(
                                        K((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerHello)))]/ProtocolVersion),
                                        K((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerHello)))]/Random),
                                        K((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerHello)))]/SessionID),
                                        K((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerHello)))]/CipherSuite),
                                        K((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerHello)))]/Compression),
                                        K((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerHello)))]/ServerExtensions)
                                    )
                                )
                            )
                        )
                    )
                }
                }),
            },
            // CCS Server -> Client
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
            // Encrypted Extensions Server -> Client
            Step {
                agent: client,
                action: Action::Input(input_action! { term! {
                    fn_message(
                        fn_protocolversion_tlsv1_2,
                        fn_messagepayload_applicationdata(
                            fn_payload(
                                K((server, 0)[Some(TlsQueryMatcher::ApplicationData)]/Vec<u8>)
                            )
                        )
                    )
                }
                }),
            },
            // Certificate Server -> Client
            Step {
                agent: client,
                action: Action::Input(input_action! { term! {
                    fn_message(
                        fn_protocolversion_tlsv1_2,
                        fn_messagepayload_applicationdata(
                            fn_payload(
                                K((server, 1)[Some(TlsQueryMatcher::ApplicationData)]/Vec<u8>)
                            )
                        )
                    )
                }
                }),
            },
            // Certificate Verify Server -> Client
            Step {
                agent: client,
                action: Action::Input(input_action! { term! {
                    fn_message(
                        fn_protocolversion_tlsv1_2,
                        fn_messagepayload_applicationdata(
                            fn_payload(
                                K((server, 2)[Some(TlsQueryMatcher::ApplicationData)]/Vec<u8>)
                            )
                        )
                    )
                }
                }),
            },
            // Finish Server -> Client
            Step {
                agent: client,
                action: Action::Input(input_action! { term! {
                    fn_message(
                        fn_protocolversion_tlsv1_2,
                        fn_messagepayload_applicationdata(
                            fn_payload(
                                K((server, 3)[Some(TlsQueryMatcher::ApplicationData)]/Vec<u8>)
                            )
                        )
                    )
                }
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
            // Finished Client -> Server
            Step {
                agent: server,
                action: Action::Input(input_action! { term! {
                    fn_message(
                        fn_protocolversion_tlsv1_2,
                        fn_messagepayload_applicationdata(
                            fn_payload(
                                K((client, 0)[Some(TlsQueryMatcher::ApplicationData)]/Vec<u8>)
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

// TODO: `[BAD_DECRYPT] [DECRYPTION_FAILED_OR_BAD_RECORD_MAC]` error with BoringSSL
pub fn seed_successful_with_tickets(
    client: AgentName,
    server: AgentName,
) -> Trace<TLSProtocolTypes> {
    let mut trace = seed_successful_with_ccs(client, server);

    trace.steps.push(OutputAction::new_step(server));
    // Ticket
    trace.steps.push(Step {
        agent: client,
        action: Action::Input(input_action! { term! {
            fn_message(
                fn_protocolversion_tlsv1_2,
                fn_messagepayload_applicationdata(
                    fn_payload(K((server, 4)[Some(TlsQueryMatcher::ApplicationData)]/Vec<u8>))
                )
            )
        }
        }),
    });

    // FIXME: don't rely on cargo feature to set the number of session tickets
    // Ticket (wolfSSL 4.4.0 only sends a single ticket)
    #[cfg(not(feature = "wolfssl430"))]
    trace.steps.push(Step {
        agent: client,
        action: Action::Input(input_action! { term! {
            fn_message(
                fn_protocolversion_tlsv1_2,
                fn_messagepayload_applicationdata(
                    fn_payload(K((server, 5)[Some(TlsQueryMatcher::ApplicationData)]/Vec<u8>))
                )
            )
        }
        }),
    });

    trace
}

// TODO: `[BAD_DECRYPT] [DECRYPTION_FAILED_OR_BAD_RECORD_MAC]` error with BoringSSL
pub fn seed_server_attacker_full(client: AgentName) -> Trace<TLSProtocolTypes> {
    let curve = term! {
        D(
            K((client, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ClientHello)))] / KeyShareEntry),
            NamedGroup
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

pub fn seed_server_attacker_full_coalesced(client: AgentName) -> Trace<TLSProtocolTypes> {
    let curve = term! {
        D(
            K((client, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ClientHello)))] / KeyShareEntry),
            NamedGroup
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
                    fn_encrypt_handshake_opaque(
                        (fn_coalesced_flight(
                            fn_messageflight(
                                (fn_list_message_append(
                                    (fn_list_message_append(
                                        (fn_list_message_append(
                                            (fn_list_message_append(
                                                fn_list_message_empty,
                                                (@encrypted_extensions)
                                            )),
                                            (@certificate)
                                        )),
                                        (@certificate_verify)
                                    )),
                                    (@server_finished)
                                ))
                            )
                        )),
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
        ],
        ..Default::default()
    }
}

/// This seed sends a HelloRetryRequest message asking the TLS client to use P384 curves as keyshare
/// and compute a correct transcript for the whole handshake
/// The differences with seed_server_attacker_full are the addition of a round trip (server sends
/// HRR to the client and the client sends second client hello) and the computation of the
/// transcript following the HRR according to RFC 8446 section 4.4.1
pub fn seed_server_attacker_with_hello_retry_request(client: AgentName) -> Trace<TLSProtocolTypes> {
    let curve = term! {
        D(
            K((client, 1)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ClientHello)))] / KeyShareEntry),
            NamedGroup
        )
    };

    // The HelloRetryRequest keeps its hand-written constructor: `HelloRetryRequest::encode` is
    // not compositional (it writes a single compression byte instead of the `Compressions`
    // vector), so no constructor is generated for it.
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
                (fn_append_transcript(
                    // Compute the hash of the first Client Hello and add the hash in a new transcript buffer
                    // see RFC 8446 section 4.4.1
                    (fn_new_hrr_transcript(
                        K((client, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ClientHello)))])
                    )),
                    (@server_hrr)
                )),
                K((client, 1)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ClientHello)))])
            )),
            (@server_hello)
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
                                (fn_get_client_key_share(K((client, 1)), (@curve))),
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
                action: Action::Input(input_action! { server_hrr }),
            },
            Step {
                agent: client,
                action: Action::Input(input_action! { server_hello }),
            },
            Step {
                agent: client,
                action: Action::Input(input_action! { term! {
                    fn_encrypt_handshake(
                        (@encrypted_extensions),
                        (@server_hello_transcript),
                        (fn_get_client_key_share(K((client, 1)), (@curve))),
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
                        (fn_get_client_key_share(K((client, 1)), (@curve))),
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
                        (fn_get_client_key_share(K((client, 1)), (@curve))),
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
                        (fn_get_client_key_share(K((client, 1)), (@curve))),
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

// TODO: `BAD_SIGNATURE` error with BoringSSL
pub fn seed_client_attacker_auth(server: AgentName) -> Trace<TLSProtocolTypes> {
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

    let extensions = term! {
        fn_decrypt_handshake_flight(
            K((server, 0)/MessageFlight),
            // The first flight of messages sent by the server
            (fn_server_hello_transcript(C((server, 0)))),
            (fn_psk(
                D(
                    K((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerHello)))] / KeyShareEntry),
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
            (@extensions),
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
                                        fn_certificate(fn_bob_cert),
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
                                (fn_rsa_sign_client(
                                    (fn_certificate_transcript(C((server, 0)))),
                                    fn_bob_key,
                                    fn_signaturescheme_rsa_pss_sha256
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
                                (fn_server_finished_transcript(C((server, 0)))),
                                (fn_server_hello_transcript(C((server, 0)))),
                                (fn_psk(
                                    D(
                                        K((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerHello)))] / KeyShareEntry),
                                        Vec<u8>
                                    )
                                )),
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
                        (fn_server_hello_transcript(C((server, 0)))),
                        (fn_psk(
                            D(
                                K((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerHello)))] / KeyShareEntry),
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
                }
                }),
            },
            Step {
                agent: server,
                action: Action::Input(input_action! { term! {
                    fn_encrypt_handshake(
                        (@certificate_verify),
                        (fn_server_hello_transcript(C((server, 0)))),
                        (fn_psk(
                            D(
                                K((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerHello)))] / KeyShareEntry),
                                Vec<u8>
                            )
                        )),
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
                        (fn_server_hello_transcript(C((server, 0)))),
                        (fn_psk(
                            D(
                                K((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerHello)))] / KeyShareEntry),
                                Vec<u8>
                            )
                        )),
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

pub fn seed_client_attacker(server: AgentName) -> Trace<TLSProtocolTypes> {
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
                                    )),
                                    fn_clientextension_presharedkeymodes(
                                        fn_pskkeyexchangemodes(
                                            fn_list_pskkeyexchangemode_append(
                                                fn_list_pskkeyexchangemode_empty,
                                                fn_pskkeyexchangemode_psk_dhe_ke
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
                                (fn_server_finished_transcript(C((server, 0)))),
                                (fn_server_hello_transcript(C((server, 0)))),
                                (fn_psk(
                                    D(
                                        K((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerHello)))] / KeyShareEntry),
                                        Vec<u8>
                                    )
                                )),
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
            Step {
                agent: server,
                action: Action::Input(input_action! { term! {
                    fn_encrypt_handshake(
                        (@client_finished),
                        (fn_server_hello_transcript(C((server, 0)))),
                        (fn_psk(
                            D(
                                K((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerHello)))] / KeyShareEntry),
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
                }
                }),
            },
            OutputAction::new_step(server),
        ],
        ..Default::default()
    }
}

pub fn seed_client_attacker12(server: AgentName) -> Trace<TLSProtocolTypes> {
    _seed_client_attacker12(server).0
}

pub fn _seed_client_attacker12(
    server: AgentName,
) -> (Trace<TLSProtocolTypes>, Term<TLSProtocolTypes>) {
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

    let server_hello_transcript = term! {
        fn_append_transcript(
            (fn_append_transcript(
                fn_new_transcript12,
                (@client_hello) // ClientHello
            )),
            K((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerHello)))]) // plaintext ServerHello
        )
    };

    let certificate_transcript = term! {
        fn_append_transcript(
            (@server_hello_transcript),
            K((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::Certificate)))]) // Certificate
        )
    };

    let server_key_exchange_transcript = term! {
        fn_append_transcript(
            (@certificate_transcript),
            K((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerKeyExchange)))]) // ServerKeyExchange
        )
    };

    let server_hello_done_transcript = term! {
        fn_append_transcript(
            (@server_key_exchange_transcript),
            K((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerHelloDone)))]) // ServerHelloDone
        )
    };

    let client_key_exchange = term! {
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

    let client_key_exchange_transcript = term! {
        fn_append_transcript((@server_hello_done_transcript), (@client_key_exchange))
    };

    let client_verify_data = term! {
        fn_client_sign_transcript(
            K((server, 0)),
            (fn_decode_server_ecdh_pubkey(
                K((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerKeyExchange)))]/Vec<u8>) // ServerECDHParams
            )),
            (@client_key_exchange_transcript),
            fn_namedgroup_secp384r1,
            fn_random,
            fn_ciphersuite_tls_ecdhe_rsa_with_aes_128_gcm_sha256
        )
    };

    let trace = Trace {
        prior_traces: vec![],
        descriptors: vec![TLSDescriptorConfig::new_server(server, TLSVersion::V1_2)],
        steps: vec![
            Step {
                agent: server,
                action: Action::Input(input_action! { client_hello
                }),
            },
            Step {
                agent: server,
                action: Action::Input(input_action! { client_key_exchange
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
                                    fn_handshakepayload_finished(fn_payload((@client_verify_data)))
                                )
                            )
                        )),
                        K((server, 0)),
                        (fn_decode_server_ecdh_pubkey(
                            K((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerKeyExchange)))]/Vec<u8>) // ServerECDHParams
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
        ],
        ..Default::default()
    };

    (trace, client_verify_data)
}

pub fn seed_server_attacker12(client: AgentName) -> Trace<TLSProtocolTypes> {
    _seed_server_attacker12(client).0
}
pub fn _seed_server_attacker12(
    client: AgentName,
) -> (Trace<TLSProtocolTypes>, Term<TLSProtocolTypes>) {
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
                            fn_ciphersuite_tls_ecdhe_rsa_with_aes_128_gcm_sha256,
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
                K((client, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ClientHello)))]) // ClientHello
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
                                    K((client, 0)),
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
            K((client, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ClientKeyExchange)))])
        )
    };

    let client_ecdh_pubkey = term! {
        fn_decode_client_ecdh_pubkey(
            K((client, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ClientKeyExchange)))]/Vec<u8>) // ClientECDHParams
        )
    };

    let client_finished_transcript = term! {
        fn_append_transcript(
            (@client_key_exchange_transcript),
            (fn_decrypt12(
                // Decrypt client finished
                K((client, 0)[Some(TlsQueryMatcher::Handshake(None))]),
                //EncryptedHandshake
                fn_random,
                (@client_ecdh_pubkey),
                fn_namedgroup_secp384r1,
                fn_false,
                fn_seq_0,
                K((client, 0)),
                fn_ciphersuite_tls_ecdhe_rsa_with_aes_128_gcm_sha256
            ))
        )
    };

    let server_verify_data = term! {
        fn_server_sign_transcript(
            fn_random,
            (@client_ecdh_pubkey),
            (@client_finished_transcript),
            fn_namedgroup_secp384r1,
            K((client, 0)),
            fn_ciphersuite_tls_ecdhe_rsa_with_aes_128_gcm_sha256
        )
    };

    let trace = Trace {
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
                        K((client, 0)),
                        fn_ciphersuite_tls_ecdhe_rsa_with_aes_128_gcm_sha256
                    )
                }
                }),
            },
        ],
        ..Default::default()
    };

    (trace, server_verify_data)
}

// TODO: `"Unable to find variable (Some(Agent(AgentName(0))), 1)[None]/MessageFlight!"` error with
// BoringSSL
pub fn seed_session_resumption_dhe(
    initial_server: AgentName,
    server: AgentName,
) -> Trace<TLSProtocolTypes> {
    let initial_handshake = seed_client_attacker(initial_server);

    let extensions = term! {
        fn_decrypt_application_flight(
            K((initial_server, 1)/MessageFlight),
            // The first flight of messages sent by the server
            (fn_server_hello_transcript(C((initial_server, 0)))),
            (fn_server_finished_transcript(C((initial_server, 0)))),
            (fn_psk(
                D(
                    K((initial_server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerHello)))] / KeyShareEntry),
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

    let new_ticket_message = term! {
        D(
            (@extensions),
            [Some(TlsQueryMatcher::Handshake(Some(HandshakeType::NewSessionTicket)))] / Message
        )
    };

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
            (fn_server_hello_transcript(C((initial_server, 0)))),
            (fn_server_finished_transcript(C((initial_server, 0)))),
            (fn_client_finished_transcript(C((initial_server, 0)))),
            (fn_psk(
                D(
                    K((initial_server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerHello)))] / KeyShareEntry),
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

    let resumption_client_finished = term! {
        fn_message(
            fn_protocolversion_tlsv1_2,
            fn_messagepayload_handshake(
                fn_handshakemessagepayload(
                    fn_handshaketype_finished,
                    fn_handshakepayload_finished(
                        fn_payload(
                            (fn_verify_data(
                                (fn_server_finished_transcript(C((server, 0)))),
                                (fn_server_hello_transcript(C((server, 0)))),
                                (fn_psk(
                                    D(
                                        K((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerHello)))] / KeyShareEntry),
                                        Vec<u8>
                                    )
                                )),
                                (fn_psk((@psk))),
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
                    fn_encrypt_handshake(
                        (@resumption_client_finished),
                        (fn_server_hello_transcript(C((server, 0)))),
                        (fn_psk(
                            D(
                                K((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerHello)))] / KeyShareEntry),
                                Vec<u8>
                            )
                        )),
                        (fn_psk((@psk))),
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

// TODO: `Unable to find variable (Some(Agent(AgentName(0))), 1)[None]/MessageFlight!` error with
// BoringSSL
pub fn seed_session_resumption_ke(
    initial_server: AgentName,
    server: AgentName,
) -> Trace<TLSProtocolTypes> {
    let initial_handshake = seed_client_attacker(initial_server);

    let extensions = term! {
        fn_decrypt_application_flight(
            K((initial_server, 1)/MessageFlight),
            // The first flight of messages sent by the server
            (fn_server_hello_transcript(C((initial_server, 0)))),
            (fn_server_finished_transcript(C((initial_server, 0)))),
            (fn_psk(
                D(
                    K((initial_server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerHello)))] / KeyShareEntry),
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

    let new_ticket_message = term! {
        D(
            (@extensions),
            [Some(TlsQueryMatcher::Handshake(Some(HandshakeType::NewSessionTicket)))] / Message
        )
    };

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
                                                    fn_pskkeyexchangemode_psk_ke
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
            (fn_server_hello_transcript(C((initial_server, 0)))),
            (fn_server_finished_transcript(C((initial_server, 0)))),
            (fn_client_finished_transcript(C((initial_server, 0)))),
            (fn_psk(
                D(
                    K((initial_server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerHello)))] / KeyShareEntry),
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

    let resumption_client_finished = term! {
        fn_message(
            fn_protocolversion_tlsv1_2,
            fn_messagepayload_handshake(
                fn_handshakemessagepayload(
                    fn_handshaketype_finished,
                    fn_handshakepayload_finished(
                        fn_payload(
                            (fn_verify_data(
                                (fn_server_finished_transcript(C((server, 0)))),
                                (fn_server_hello_transcript(C((server, 0)))),
                                fn_no_key_share,
                                (fn_psk((@psk))),
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
                    fn_encrypt_handshake(
                        (@resumption_client_finished),
                        (fn_server_hello_transcript(C((server, 0)))),
                        fn_no_key_share,
                        (fn_psk((@psk))),
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

pub fn seed_client_attacker_full(server: AgentName) -> Trace<TLSProtocolTypes> {
    _seed_client_attacker_full(server).0
}

/// Seed which contains the whole transcript in the tree. This is rather huge >300 symbols
pub fn _seed_client_attacker_full(
    server: AgentName,
) -> (
    Trace<TLSProtocolTypes>,
    Term<TLSProtocolTypes>,
    Term<TLSProtocolTypes>,
    Term<TLSProtocolTypes>,
) {
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
                                    )),
                                    fn_clientextension_presharedkeymodes(
                                        fn_pskkeyexchangemodes(
                                            fn_list_pskkeyexchangemode_append(
                                                fn_list_pskkeyexchangemode_empty,
                                                fn_pskkeyexchangemode_psk_dhe_ke
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
            (fn_psk(
                D(
                    K((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerHello)))] / KeyShareEntry),
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
                                (fn_psk(
                                    D(
                                        K((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerHello)))] / KeyShareEntry),
                                        Vec<u8>
                                    )
                                )),
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

    let client_finished_transcript = term! {
        fn_append_transcript((@server_finished_transcript), (@client_finished))
    };

    let trace = Trace {
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
                        (fn_psk(
                            D(
                                K((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerHello)))] / KeyShareEntry),
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
                }
                }),
            },
            OutputAction::new_step(server),
            // Step {
            //     agent: server,
            //     action: Action::Input(InputAction {
            //         recipe: term! {
            //              fn_encrypt_application(
            //                 fn_message(
            //                     fn_protocolversion_tlsv1_2,
            //                     fn_messagepayload_alert(fn_alertmessagepayload(
            //                         fn_alertlevel_warning,
            //                         fn_alertdescription_closenotify
            //                     ))
            //                 ),
            //                 (@server_hello_transcript),
            //                 (@server_finished_transcript),
            //                 (fn_psk(D(
            //                     ((server, 0)[Some(TlsQueryMatcher::Handshake(Some(
            //                         HandshakeType::ServerHello
            //                     )))] / KeyShareEntry),
            //                     Vec<u8>
            //                 ))),
            //                 fn_no_psk,
            //                 fn_namedgroup_secp384r1,
            //                 fn_seq_0  // sequence 0
            //             )
            //         }
            //     }),
            // },
            // OutputAction::new_step(server),
        ],
        ..Default::default()
    };

    (
        trace,
        server_hello_transcript,
        server_finished_transcript,
        client_finished_transcript,
    )
}

pub fn seed_client_attacker_full_precomputation(server: AgentName) -> Trace<TLSProtocolTypes> {
    _seed_client_attacker_full_precomputation(server).0
}
pub fn _seed_client_attacker_full_precomputation(
    server: AgentName,
) -> (
    Trace<TLSProtocolTypes>,
    Term<TLSProtocolTypes>,
    Term<TLSProtocolTypes>,
    Term<TLSProtocolTypes>,
) {
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
            (fn_psk(
                D(
                    K((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerHello)))] / KeyShareEntry),
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

    // We are using a query on a precomputation with label decrypted_extensions
    let encrypted_extensions = term! {
        K((!"decrypted_extensions", 0)[Some(TlsQueryMatcher::Handshake(Some(
        HandshakeType::EncryptedExtensions
        )))] / Message)
    };

    let encrypted_extension_transcript = term! {
        fn_append_transcript(
            (@server_hello_transcript),
            (@encrypted_extensions) // plaintext Encrypted Extensions
        )
    };

    let server_certificate = term! {
        K((!"decrypted_extensions", 0)[Some(TlsQueryMatcher::Handshake(Some(
        HandshakeType::Certificate
        )))] / Message)
    };

    let server_certificate_transcript = term! {
        fn_append_transcript(
            (@encrypted_extension_transcript),
            (@server_certificate) // plaintext Server Certificate
        )
    };

    let server_certificate_verify = term! {
        K((!"decrypted_extensions", 0)[Some(TlsQueryMatcher::Handshake(Some(
        HandshakeType::CertificateVerify
        )))] / Message)
    };

    let server_certificate_verify_transcript = term! {
        fn_append_transcript(
            (@server_certificate_transcript),
            (@server_certificate_verify) // plaintext Server Certificate Verify
        )
    };

    let server_finished = term! {
        K((!"decrypted_extensions", 0)[Some(TlsQueryMatcher::Handshake(Some(
        HandshakeType::Finished
        )))] / Message)
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
                                (fn_psk(
                                    D(
                                        K((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerHello)))] / KeyShareEntry),
                                        Vec<u8>
                                    )
                                )),
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

    let client_finished_transcript = term! {
        fn_append_transcript((@server_finished_transcript), (@client_finished))
    };

    let trace = Trace {
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
                action: Action::Input(input_action! {
                    "decrypted_extensions" = term! {
                        @extensions
                    }
                    =>
                    term! {
                        fn_encrypt_handshake(
                            (@client_finished),
                            (@server_hello_transcript),
                            (fn_psk(
                                D(
                                    K((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerHello)))] / KeyShareEntry),
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
                    }
                }),
            },
            OutputAction::new_step(server),
        ],
        ..Default::default()
    };

    (
        trace,
        server_hello_transcript,
        server_finished_transcript,
        client_finished_transcript,
    )
}

/// Seed which contains the whole transcript in the tree. This is rather huge 10k symbols. It grows
/// exponentially.
pub fn seed_session_resumption_dhe_full(
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
            K((initial_server, 4)[Some(TlsQueryMatcher::ApplicationData)]),
            // Ticket?
            (@server_hello_transcript),
            (@server_finished_transcript),
            (fn_psk(
                D(
                    K((initial_server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerHello)))] / KeyShareEntry),
                    Vec<u8>
                )
            )),
            fn_no_psk,
            fn_namedgroup_secp384r1,
            fn_true,
            fn_seq_0,
            // sequence restarts at 0 because we are decrypting now traffic
            fn_random,
            fn_ciphersuite_tls13_aes_128_gcm_sha256
        )
    };

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
                    K((initial_server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerHello)))] / KeyShareEntry),
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

    let resumption_server_hello_transcript = term! {
        fn_append_transcript(
            (fn_append_transcript(
                fn_new_transcript,
                (@full_client_hello) // ClientHello
            )),
            K((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerHello)))]) // plaintext ServerHello
        )
    };

    let resumption_decrypted_handshake = term! {
        fn_decrypt_handshake_flight(
            K((server, 0)/MessageFlight),
            // The first flight of messages sent by the server
            (@resumption_server_hello_transcript),
            (fn_psk(
                D(
                    K((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerHello)))] / KeyShareEntry),
                    Vec<u8>
                )
            )),
            (fn_psk((@psk))),
            fn_namedgroup_secp384r1,
            fn_true,
            fn_seq_0,
            // sequence 0
            fn_random,
            fn_ciphersuite_tls13_aes_128_gcm_sha256
        )
    };

    let resumption_encrypted_extensions = term! {
        D(
            (@resumption_decrypted_handshake),
            [Some(TlsQueryMatcher::Handshake(Some(HandshakeType::EncryptedExtensions)))] / Message
        )
    };

    let resumption_encrypted_extension_transcript = term! {
        fn_append_transcript(
            (@resumption_server_hello_transcript),
            (@resumption_encrypted_extensions) // plaintext Encrypted Extensions
        )
    };

    let resumption_server_finished = term! {
        D(
            (@resumption_decrypted_handshake),
            [Some(TlsQueryMatcher::Handshake(Some(HandshakeType::Finished)))] / Message
        )
    };

    let resumption_server_finished_transcript = term! {
        fn_append_transcript(
            (@resumption_encrypted_extension_transcript),
            (@resumption_server_finished) // plaintext Server Handshake Finished
        )
    };

    let resumption_client_finished = term! {
        fn_message(
            fn_protocolversion_tlsv1_2,
            fn_messagepayload_handshake(
                fn_handshakemessagepayload(
                    fn_handshaketype_finished,
                    fn_handshakepayload_finished(
                        fn_payload(
                            (fn_verify_data(
                                (@resumption_server_finished_transcript),
                                (@resumption_server_hello_transcript),
                                (fn_psk(
                                    D(
                                        K((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerHello)))] / KeyShareEntry),
                                        Vec<u8>
                                    )
                                )),
                                (fn_psk((@psk))),
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
                    fn_encrypt_handshake(
                        (@resumption_client_finished),
                        (@resumption_server_hello_transcript),
                        (fn_psk(
                            D(
                                K((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerHello)))] / KeyShareEntry),
                                Vec<u8>
                            )
                        )),
                        (fn_psk((@psk))),
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
            /*Step {
                agent: server,
                action: Action::Input(input_action! { term! {
                    fn_encrypt_application(
                        fn_message(
                            fn_protocolversion_tlsv1_2,
                            fn_messagepayload_alert(
                                fn_alertmessagepayload(
                                    fn_alertlevel_warning,
                                    fn_alertdescription_closenotify
                                )
                            )
                        ),
                        (@resumption_server_hello_transcript),
                        (@resumption_server_finished_transcript),
                        (fn_psk(
                            D(
                                ((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerHello)))] / KeyShareEntry),
                                Vec<u8>
                            )
                        )),
                        (fn_psk((@psk))),
                        fn_seq_0 // sequence 0
                    )
                }
                }),
            },*/
        ],
        ..Default::default()
    }
}

fn decrypt_handshake_from_claims() -> Term<TLSProtocolTypes> {
    let server = AgentName::first();
    term! {
        fn_decrypt_handshake_flight(
            K((server, 0)/MessageFlight),
            (fn_server_hello_transcript(C((server,0)))),
            (fn_psk(
                D(
                    K((server, 0)[Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ServerHello)))] / KeyShareEntry),
                    Vec<u8>
                )
            )),
            fn_no_psk,
            fn_namedgroup_secp384r1,
            fn_true,
            fn_seq_0 // sequence 0
        )
    }
}

macro_rules! corpus {
    () => {
        vec![]
    };

    ( $( $func:ident : $cond:expr ),* $(,)? ) => {
        {
            use puffin::trace_helper::TraceHelper;
            let mut corpus = vec![];

            $(
                if $cond {
                    corpus.push(($func.build_trace(), $func.fn_name()));
                }
            )*

            corpus
        }
    };
}

pub fn create_corpus(
    put: &dyn puffin::put_registry::Factory<TLSProtocolBehavior>,
) -> Vec<(Trace<TLSProtocolTypes>, &'static str)> {
    corpus!(
        // Full Handshakes
        seed_successful: put.supports("tls13"),
        seed_successful_with_ccs: put.supports("tls13"),
        seed_successful_with_tickets: put.supports("tls13") && put.supports("tls13_session_resumption"),
        seed_successful12: put.supports("tls12") && !put.supports("tls12_session_resumption"),
        seed_successful12_with_tickets: put.supports("tls12") && put.supports("tls12_session_resumption"),
        // Client Attackers
        seed_client_attacker: put.supports("tls13"),
        seed_client_attacker_full: put.supports("tls13"),
        seed_client_attacker_auth: put.supports("tls13") && put.supports("client_authentication_transcript_extraction"),
        seed_client_attacker12: put.supports("tls12"),
        // Session resumption
        seed_session_resumption_dhe: put.supports("tls13") && put.supports("tls13_session_resumption"),
        seed_session_resumption_ke: put.supports("tls13") && put.supports("tls13_session_resumption") && put.supports("psk_ke_support"),
        // Server Attackers
        seed_server_attacker_full: put.supports("tls13"),
        seed_server_attacker_full_coalesced: put.supports("tls13"),
        seed_server_attacker_with_hello_retry_request : put.supports("tls13"),
        seed_server_attacker12: put.supports("tls12"),
    )
}

#[cfg(test)]
pub mod tests {
    use puffin::algebra::TermType;
    use puffin::fuzzer::utils::TermConstraints;
    use puffin::protocol::ProtocolTypes;
    use puffin::put::{PutDescriptor, PutOptions};
    use puffin::trace::Query;

    use super::*;
    #[allow(unused_imports)]
    use crate::{test_utils::prelude::*, tls::seeds::*};

    #[test_log::test]
    fn test_version() {
        for (id, put) in tls_registry().puts() {
            println!("{}:", id);
            for (component, version) in put.versions().into_iter() {
                println!("    {}: {}", component, version);
            }
        }
    }

    #[apply(test_puts, filter = tls12)]
    fn test_seed_client_attacker12(put: &str) {
        let runner = default_runner_for(put);
        let trace = seed_client_attacker12.build_trace();

        let ctx = runner.execute(trace, &mut 0).unwrap();

        assert!(ctx.agents_successful());
    }

    #[apply(test_puts, filter = all(tls13, transcript_extraction))]
    fn test_seed_client_attacker(put: &str) {
        let runner = default_runner_for(put);
        let trace = seed_client_attacker.build_trace();

        let ctx = runner.execute(trace, &mut 0).unwrap();

        assert!(ctx.agents_successful());
    }

    #[apply(test_puts, filter = all(tls13, client_authentication_transcript_extraction))]
    fn test_seed_client_attacker_auth(put: &str) {
        let runner = default_runner_for(put);
        let trace = seed_client_attacker_auth.build_trace();

        let ctx = runner.execute(trace, &mut 0).unwrap();

        assert!(ctx.agents_successful());
    }

    #[apply(test_puts, filter = tls13)]
    fn test_seed_client_attacker_full(put: &str) {
        let runner = default_runner_for(put);
        let trace = seed_client_attacker_full.build_trace();

        let ctx = runner.execute(trace, &mut 0).unwrap();

        assert!(ctx.agents_successful());
    }

    /// Run seed_client_attacker_full_precomputation to test precomputations
    #[apply(test_puts, filter = tls13)]
    fn test_precomputations(put: &str) {
        let runner = default_runner_for(put);
        let trace = seed_client_attacker_full_precomputation.build_trace();

        let ctx = runner.execute(trace, &mut 0).unwrap();

        assert!(ctx.agents_successful());
    }

    #[apply(test_puts, filter = all(tls12))]
    fn test_seed_server_attacker12(put: &str) {
        let runner = default_runner_for(put);
        let trace = seed_server_attacker12.build_trace();

        let ctx = runner.execute(trace, &mut 0).unwrap();

        assert!(ctx.agents_successful());
    }

    #[apply(test_puts, filter = all(tls13))]
    fn test_seed_server_attacker_full(put: &str) {
        let runner = default_runner_for(put);
        let trace = seed_server_attacker_full.build_trace();

        let ctx = runner.execute(trace, &mut 0).unwrap();

        assert!(ctx.agents_successful());
    }

    // TODO: find a better solution to filter out Wolfssl430 (too old) and wolfssl540-sdos2
    // (incompatible patch applied) than using client_authentication_transcript_extraction and
    // not(disable_postauth) in the next 3 tests
    // Exclude wolfssl430 (too old, no client_authentication_transcript_extraction) and
    // wolfssl540-sdos2 (incompatible patch, has disable_postauth) from differential decryption
    // tests.
    #[apply(test_puts, filter = all(tls13, transcript_extraction, client_authentication_transcript_extraction, not(boringssl), not(disable_postauth)))]
    fn test_seeds_differential_decryption(put: &str) {
        let traces = vec![
            seed_client_attacker.build_trace(),
            seed_client_attacker_full.build_trace(),
            seed_server_attacker_full.build_trace(),
            seed_successful.build_trace(),
        ];

        for trace in traces {
            let runner = default_runner_for(put);
            let descriptors = trace.descriptors.clone();
            let ctx = runner.execute(trace, &mut 0).unwrap();

            let terms = <TLSProtocolTypes as ProtocolTypes>::differential_fuzzing_terms_to_eval(
                &descriptors,
            );
            assert!(
                !terms.is_empty(),
                "no differential terms produced for {put}"
            );

            let any_ok = terms.iter().any(|t| t.evaluate_dy(&ctx).is_ok());
            assert!(
                any_ok,
                "no post-computation decryption term evaluated successfully for {put}"
            );
        }
    }

    #[apply(test_puts, filter = all(tls13, not(boringssl)))]
    fn test_seed_server_attacker_full_coalesced(put: &str) {
        let runner = default_runner_for(put);
        let trace = seed_server_attacker_full_coalesced.build_trace();

        let ctx = runner.execute(trace, &mut 0).unwrap();

        assert!(ctx.agents_successful());
    }

    #[apply(test_puts, filter = all(tls13))]
    fn test_seed_server_attacker_with_hello_retry_request(put: &str) {
        let runner = default_runner_for(put);
        let trace = seed_server_attacker_with_hello_retry_request.build_trace();

        let ctx = runner.execute(trace, &mut 0).unwrap();

        assert!(ctx.agents_successful());
    }

    #[apply(test_puts, filter = all(tls13, tls13_session_resumption, not(disable_postauth)))]
    fn test_seed_session_resumption_dhe(put: &str) {
        let runner = default_runner_for(put);
        let trace = seed_session_resumption_dhe.build_trace();

        let ctx = runner.execute(trace, &mut 0).unwrap();

        assert!(ctx.agents_successful());
    }

    #[apply(test_puts, filter = all(tls13, tls13_session_resumption, not(disable_postauth)))]
    fn test_seed_session_resumption_dhe_full(put: &str) {
        let runner = default_runner_for(put);
        let trace = seed_session_resumption_dhe_full.build_trace();

        let ctx = runner.execute(trace, &mut 0).unwrap();

        assert!(ctx.agents_successful());
    }

    #[apply(test_puts, filter = all(tls13, tls13_session_resumption, psk_ke_support, not(disable_postauth))
    )]
    fn test_seed_session_resumption_ke(put: &str) {
        let runner = default_runner_for(put);
        let trace = seed_session_resumption_ke.build_trace();

        let ctx = runner.execute(trace, &mut 0).unwrap();

        assert!(ctx.agents_successful());
    }

    #[apply(test_puts, filter = all(tls13))]
    fn test_seed_successful(put: &str) {
        let runner = default_runner_for(put);
        let trace = seed_successful.build_trace();

        let ctx = runner.execute(trace, &mut 0).unwrap();

        assert!(ctx.agents_successful());
    }

    #[apply(test_puts, filter = all(tls13))]
    fn test_seed_successful_client_auth(put: &str) {
        let runner = default_runner_for(put);
        let trace = seed_successful_client_auth.build_trace();

        let ctx = runner.execute(trace, &mut 0).unwrap();

        assert!(ctx.agents_successful());
    }

    #[apply(test_puts, attrs = [should_panic], filter = tls13)]
    // Cases:
    // expected = "Not the best cipher choosen", // in case MITM attack succeeded because transcript
    // is ignored -> We detect the MITM and error expected = "decryption failed or bad record
    // mac"  // in case MITM attack did fail
    fn test_seed_successful_mitm(put: &str) {
        let runner = default_runner_for(put);
        let trace = seed_successful_mitm.build_trace();

        let ctx = runner.execute(trace, &mut 0).unwrap();

        assert!(ctx.agents_successful());
    }

    #[apply(test_puts, filter = all(tls13))]
    fn test_seed_successful_with_ccs(put: &str) {
        let runner = default_runner_for(put);
        let trace = seed_successful_with_ccs.build_trace();

        let ctx = runner.execute(trace, &mut 0).unwrap();

        assert!(ctx.agents_successful());
    }

    // require version which supports TLS 1.3 and session resumption (else no tickets are sent)
    // LibreSSL does not yet support PSK
    #[apply(test_puts, filter = all(tls13, tls13_session_resumption))]
    fn test_seed_successful_with_tickets(put: &str) {
        let runner = default_runner_for(put);
        let trace = seed_successful_with_tickets.build_trace();

        let ctx = runner.execute(trace, &mut 0).unwrap();

        assert!(ctx.agents_successful());
    }

    #[apply(test_puts, filter = all(tls12))]
    fn test_seed_successful12(put: &str) {
        let runner = default_runner_for(put);

        let trace = if supports!(put, "tls12_session_resumption") {
            seed_successful12_with_tickets.build_trace()
        } else {
            seed_successful12.build_trace()
        };

        let ctx = runner.execute(trace, &mut 0).unwrap();

        assert!(ctx.agents_successful());
    }

    /// Verify that cipher and sigalgs configuration actually takes effect.
    /// This catches silent failures like BoringSSL ignoring unrecognised IANA cipher names.
    /// For openssl we only test version 3.4.0 as it is the only one that has the right claims added
    /// in our openssl github fork. Wolfssl430 does not have a C harness
    #[cfg(not(feature = "wolfssl430"))]
    #[apply(test_puts, filter = all(tls13, any(not(openssl), openssl340), not(libressl))
    )]
    fn test_cipher_config_takes_effect(put: &str) {
        use crate::claims::Finished;

        let client = AgentName::first();
        let server = client.next();
        let mut trace = seed_successful(client, server);
        trace =
            <TLSProtocolTypes as ProtocolTypes>::differential_fuzzing_uniformise_put_config(trace);

        let runner = default_runner_for(put);
        let ctx = runner.execute(trace, &mut 0).unwrap();
        assert!(ctx.agents_successful());

        // The uniformised TLS 1.3 config allows: AES-256-GCM, AES-128-GCM, CHACHA20
        let allowed_ciphers: &[u16] = &[0x1301, 0x1302, 0x1303];

        let claim = ctx
            .find_claim(server, TypeShape::of::<Finished>())
            .expect(&format!("no Finished claim for server agent in {put}"));
        let finished = claim.as_ref().as_any().downcast_ref::<Finished>().unwrap();
        assert!(
            allowed_ciphers.contains(&finished.chosen_cipher),
            "{put}: server chosen_cipher 0x{:04x} not in configured set {allowed_ciphers:?}",
            finished.chosen_cipher,
        );

        // Verify sigalgs config took effect: the negotiated signature algorithm must be
        // one of the configured RSA-PSS or RSA schemes.
        // RSA-PSS+SHA256=0x0804, RSA-PSS+SHA384=0x0805, RSA-PSS+SHA512=0x0806,
        // RSA+SHA256=0x0401, RSA+SHA384=0x0501, RSA+SHA512=0x0601
        let allowed_sigalgs: &[i32] = &[0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601];
        assert!(
            finished.signature_algorithm != 0,
            "{put}: server signature_algorithm not reported (== 0)",
        );
        assert!(
            allowed_sigalgs.contains(&finished.signature_algorithm),
            "{put}: server signature_algorithm 0x{:04x} not in configured set {allowed_sigalgs:?}",
            finished.signature_algorithm,
        );
    }

    /// Verify that TLS 1.2 cipher configuration takes effect.
    /// Uses the same seed selection logic as test_seed_successful12.
    /// Checks that the negotiated cipher is an ECDHE cipher as configured.
    /// OpenSSL101f and OpenSSL102u are not instrumented for claims.
    #[cfg(all(not(feature = "openssl101f"), not(feature = "openssl102u")))]
    #[apply(test_puts, filter = all(tls12, not(libressl)))]
    fn test_cipher_config_tls12_takes_effect(put: &str) {
        use crate::claims::Finished;

        let trace = if supports!(put, "tls12_session_resumption") {
            seed_successful12_with_tickets.build_trace()
        } else {
            seed_successful12.build_trace()
        };
        let server = AgentName::first().next();

        let runner = default_runner_for(put);
        let ctx = runner.execute(trace, &mut 0).unwrap();
        assert!(ctx.agents_successful());

        let claim = ctx
            .find_claim(server, TypeShape::of::<Finished>())
            .expect(&format!("no Finished claim for server agent in {put}"));
        let finished = claim.as_ref().as_any().downcast_ref::<Finished>().unwrap();
        // The chosen cipher must be non-zero (i.e., actually reported)
        assert!(
            finished.chosen_cipher != 0,
            "{put}: server Finished claim has chosen_cipher == 0 (cipher config not reported)",
        );
        // The chosen cipher must be an ECDHE cipher (0xC0xx range) since the seed uses
        // ServerKeyExchange which only applies to ephemeral key exchange
        assert!(
            (finished.chosen_cipher >> 8) == 0xC0,
            "{put}: server chosen_cipher 0x{:04x} is not an ECDHE cipher — \
             cipher config may not have taken effect",
            finished.chosen_cipher,
        );
    }

    #[test_log::test]
    fn test_corpus_file_sizes() {
        use puffin::trace::Action;

        let registry = tls_registry();
        let factory = registry.default();

        for (trace, name) in create_corpus(factory) {
            for step in &trace.steps {
                match &step.action {
                    Action::Input(input) => {
                        // should be below a certain threshold, else we should increase
                        // max_term_size_explore in fuzzer setup
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

    #[test_log::test]
    fn test_term_sizes() {
        use puffin::trace::Action;

        let client = puffin::agent::AgentName::first();
        let _server = client.next();

        for (name, trace) in [
            seed_successful_client_auth.build_named_trace(),
            seed_successful.build_named_trace(),
            seed_successful_mitm.build_named_trace(),
            seed_successful12_with_tickets.build_named_trace(),
            seed_successful12.build_named_trace(),
            seed_successful_with_ccs.build_named_trace(),
            seed_successful_with_tickets.build_named_trace(),
            seed_server_attacker_full.build_named_trace(),
            seed_client_attacker_auth.build_named_trace(),
            seed_client_attacker.build_named_trace(),
            seed_client_attacker12.build_named_trace(),
            seed_session_resumption_dhe.build_named_trace(),
            seed_session_resumption_ke.build_named_trace(),
            seed_client_attacker_full.build_named_trace(),
            seed_server_attacker12.build_named_trace(),
            // _full can be large: seed_session_resumption_dhe_full.build_named_trace(),
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

    pub mod serialization {
        use puffin::protocol::ProtocolTypes;
        use puffin::trace::Trace;

        use crate::test_utils::prelude::*;
        use crate::tls::seeds::*;

        fn test_postcard_serialization<PT: ProtocolTypes>(trace: Trace<PT>) {
            let serialized1 = trace.serialize_postcard().unwrap();
            let deserialized_trace =
                Trace::<TLSProtocolTypes>::deserialize_postcard(serialized1.as_ref()).unwrap();
            let serialized2 = deserialized_trace.serialize_postcard().unwrap();

            assert_eq!(serialized1, serialized2);
        }

        fn test_json_serialization<PT: ProtocolTypes>(trace: Trace<PT>) {
            let serialized1 = serde_json::to_string_pretty(&trace).unwrap();
            let deserialized_trace =
                serde_json::from_str::<Trace<TLSProtocolTypes>>(serialized1.as_str()).unwrap();
            let serialized2 = serde_json::to_string_pretty(&deserialized_trace).unwrap();

            assert_eq!(serialized1, serialized2);
        }

        #[test_log::test]
        fn test_serialisation_seed_seed_session_resumption_dhe_json() {
            let trace = seed_session_resumption_dhe.build_trace();
            test_json_serialization(trace);
        }

        #[test_log::test]
        fn test_serialisation_seed_seed_session_resumption_ke_json() {
            let trace = seed_session_resumption_ke.build_trace();
            test_json_serialization(trace);
        }

        #[test_log::test]
        fn test_serialisation_seed_client_attacker12_json() {
            let trace = seed_client_attacker12.build_trace();
            test_json_serialization(trace);
        }

        #[test_log::test]
        fn test_serialisation_seed_server_attacker12_json() {
            let trace = seed_server_attacker12.build_trace();
            test_json_serialization(trace);
        }

        #[test_log::test]
        fn test_serialisation_seed_successful_json() {
            let trace = seed_successful.build_trace();
            test_json_serialization(trace);
        }

        #[test_log::test]
        fn test_serialisation_seed_successful_postcard() {
            let trace = seed_successful.build_trace();
            test_postcard_serialization(trace);
        }

        #[test_log::test]
        fn test_serialisation_seed_successful12_json() {
            let trace = seed_successful12.build_trace();
            test_json_serialization(trace);
        }

        #[test_log::test]
        fn test_serialisation_seed_client_attacker_auth_json() {
            let trace = seed_client_attacker_auth.build_trace();
            test_json_serialization(trace);
        }

        #[test_log::test]
        fn test_serialisation_seed_client_attacker_auth_postcard() {
            let trace = seed_client_attacker_auth.build_trace();
            test_postcard_serialization(trace);
        }

        #[test_log::test]
        fn test_serialisation_seed_server_attacker_full_json() {
            let trace = seed_server_attacker_full.build_trace();
            test_json_serialization(trace);
        }

        #[test_log::test]
        fn test_serialisation_seed_server_attacker_full_postcard() {
            let trace = seed_server_attacker_full.build_trace();
            test_postcard_serialization(trace);
        }
    }

    pub mod rustls {
        use puffin::codec::{Codec, Reader};

        use crate::tls::rustls::msgs::base::Payload;
        use crate::tls::rustls::msgs::enums::{ContentType, HandshakeType, ProtocolVersion};
        use crate::tls::rustls::msgs::handshake::{
            CipherSuites, ClientExtensions, ClientHelloPayload, Compressions,
            HandshakeMessagePayload, HandshakePayload, Random, SessionID,
        };
        use crate::tls::rustls::msgs::message::MessagePayload::Handshake;
        use crate::tls::rustls::msgs::message::{Message, OpaqueMessage, PlainMessage};

        fn create_message(opaque_message: OpaqueMessage) -> Message {
            Message::try_from(opaque_message.into_plain_message()).unwrap()
        }

        #[test_log::test]
        fn test_rustls_message_stability_ch() {
            let hello_client_hex = "1603010136010001320303aa1795f64f48fcfcd0121368f88f176fe2570b07\
        68bbc85e9f2c80c557553d7d20e1e15d0028932f4f7479cf256302b7847d81a68e708525f9d38d94fc6ef742a30\
        03e130213031301c02cc030009fcca9cca8ccaac02bc02f009ec024c028006bc023c0270067c00ac0140039c009\
        c0130033009d009c003d003c0035002f00ff010000ab00000012001000000d6d6178616d6d616e6e2e6f7267000\
        b000403000102000a000c000a001d0017001e00190018002300000016000000170000000d0030002e0403050306\
        03080708080809080a080b080408050806040105010601030302030301020103020202040205020602002b00090\
        80304030303020301002d00020101003300260024001d00209b8a24e29770f7ed95bf330e7e3929b21090350a41\
        5ab4cdf01b04e9ffc0fc50";

            let hello_client = hex::decode(hello_client_hex).unwrap();

            let opaque_message =
                OpaqueMessage::read(&mut Reader::init(hello_client.as_slice())).unwrap();
            create_message(opaque_message);
        }

        #[test_log::test]
        fn test_heartbleed_ch() {
            // Derived from "openssl s_client -msg -connect localhost:44330" and then pressing R
            let hello_client_hex = "
            16 03 03 00  dc 01 00 00 d8 03 03 53
            43 5b 90 9d 9b 72 0b bc  0c bc 2b 92 a8 48 97 cf
            bd 39 04 cc 16 0a 85 03  90 9f 77 04 33 d4 de 00
            00 66 c0 14 c0 0a c0 22  c0 21 00 39 00 38 00 88
            00 87 c0 0f c0 05 00 35  00 84 c0 12 c0 08 c0 1c
            c0 1b 00 16 00 13 c0 0d  c0 03 00 0a c0 13 c0 09
            c0 1f c0 1e 00 33 00 32  00 9a 00 99 00 45 00 44
            c0 0e c0 04 00 2f 00 96  00 41 c0 11 c0 07 c0 0c
            c0 02 00 05 00 04 00 15  00 12 00 09 00 14 00 11
            00 08 00 06 00 03 00 ff  01 00 00 49 00 0b 00 04
            03 00 01 02 00 0a 00 34  00 32 00 0e 00 0d 00 19
            00 0b 00 0c 00 18 00 09  00 0a 00 16 00 17 00 08
            00 06 00 07 00 14 00 15  00 04 00 05 00 12 00 13
            00 01 00 02 00 03 00 0f  00 10 00 11 00 23 00 00
            00 0f 00 01 01";

            let hello_client =
                hex::decode(hello_client_hex.to_string().replace([' ', '\n'], "")).unwrap();
            //hexdump::hexdump(&hello_client);

            let opaque_message =
                OpaqueMessage::read(&mut Reader::init(hello_client.as_slice())).unwrap();
            create_message(opaque_message);
        }

        #[test_log::test]
        fn test_rustls_message_stability_ch_renegotiation() {
            // Derived from "openssl s_client -msg -connect localhost:44330" and then pressing R
            let hello_client_hex = "16030300cc\
        010000c8030368254f1b232142c49512b09ac3929df07b6d461dc15473c064\
        e1ffdfbfd5cc9d000036c02cc030009fcca9cca8ccaac02bc02f009ec024c028006bc023c0270067c00ac014003\
        9c009c0130033009d009c003d003c0035002f01000069ff01000d0cdcf098f907352157bc31b073000b00040300\
        0102000a000c000a001d0017001e00190018002300000016000000170000000d0030002e0403050306030807080\
        80809080a080b080408050806040105010601030302030301020103020202040205020602";

            let hello_client = hex::decode(hello_client_hex).unwrap();
            //hexdump::hexdump(&hello_client);

            let opaque_message =
                OpaqueMessage::read(&mut Reader::init(hello_client.as_slice())).unwrap();
            create_message(opaque_message);
        }

        /// https://github.com/tlspuffin/rustls/commit/d5d26a119f5a0edee43ebcd77f3bbae8bbd1db7d
        #[test_log::test]
        fn test_server_hello_parsing() {
            let hex = "160303004a020000460303de257a3941501c11fa7898af1b1b2aea4f5e39e521b35dc84ffab\
        e830e9a98ec20e1cb49645b1cd6e2d0aa5c87b5a3837bcf33334e96c37a77a79c9df63413dc15c02f00";
            let binary = hex::decode(hex).unwrap();
            let opaque_message = OpaqueMessage::read(&mut Reader::init(binary.as_slice())).unwrap();
            create_message(opaque_message);
        }

        #[test_log::test]
        fn test_encrypted_tls12_messages() {
            let hexn = vec![
                "1603030028155e38ddd323ca97440b4bb44fe810e9f4d10e5280795ca0660c7d8c8dddcd95355538a3d2cc0256",
                "16030300280d8d288b7a398d5c078280388c71106391756b19d1bb5c95ec18f5de8a0c772062df0d18f24e02b5",
                "16030300280032e43a49aa2134ac20d701f3427aee8cf7c397eb2b9ed88a09bfba4c9fe94a10e6c88be89a7a67",
                "1603030028149ee35e3205a0fea0fd2f14555c7fd0b6acc2bf926a674841375ed061dbf359ac64905c8c616095",
                "1603030028182bdc85dc708633cc973b23173fd1e9a7296c744ce44443c678b2be0d9c0b050b3b26f9cd697ed9",
                "160303002805330e9cee1941f19b744f7ddab94a8caf2afcc8ceb97e4389c4f7c0b329219bcbf4d68c1fc71266",
                "1603030028fe4121bb8fb7467a63b25cc96f2eb3df1ef61fc31431a37db61825a7680d85b9fc04e980055e65db",
            ];

            for hex in hexn {
                let binary = hex::decode(hex).unwrap();
                let opaque_message =
                    OpaqueMessage::read(&mut Reader::init(binary.as_slice())).unwrap();
                create_message(opaque_message);
            }
        }

        #[test_log::test]
        fn test_rustls_message_stability_cert() {
            let cert_hex = "16030309b50b0009b1000009ad00053a308205363082041ea00302010202120400ca59\
        61d39c1622093596f2132488f93e300d06092a864886f70d01010b05003032310b3009060355040613025553311\
        63014060355040a130d4c6574277320456e6372797074310b3009060355040313025233301e170d323130333238\
        3031343335385a170d3231303632363031343335385a301c311a3018060355040313117777772e6d6178616d6d6\
        16e6e2e6f726730820122300d06092a864886f70d01010105000382010f003082010a0282010100b8ad1a3825f4\
        aa8f8cdf5221a5d98d29f93be72f470397e07e1ceca379376bf1b148d19feaf6c5d3b01b344369bcc50dd33f967\
        b281eec6edf4e9ee6b1a134589d40b3d3c2b2d51814ecafebcd59da1b01aea221af57f50e523694ac7603bf363b\
        3a5380d48bef06cffbae66123046a7cfb3055f35755b50c71c93aef4c2a0bc8badb56b37d07be0d3319cac9b2f2\
        10a29115b4b6377734b647088adcbc12cc82a59a5f10fe2478ab2937f4ed667fbbdda3c468148f974da14dda787\
        234811457d4a2d99677f27a3eae68f782c1291243e02653a4fe70ca4cb3d3eda66ba47926e25b25045b92ef8c20\
        a89b1b5fce69ac18091f1229d9be473f96f23ed40d43f0203010001a382025a30820256300e0603551d0f0101ff\
        0404030205a0301d0603551d250416301406082b0601050507030106082b06010505070302300c0603551d13010\
        1ff04023000301d0603551d0e0416041412b43a1e54091741afc831d1e4de7babcb110ebe301f0603551d230418\
        30168014142eb317b75856cbae500940e61faf9d8b14c2c6305506082b0601050507010104493047302106082b0\
        60105050730018615687474703a2f2f72332e6f2e6c656e63722e6f7267302206082b0601050507300286166874\
        74703a2f2f72332e692e6c656e63722e6f72672f302b0603551d1104243022820d6d6178616d6d616e6e2e6f726\
        782117777772e6d6178616d6d616e6e2e6f7267304c0603551d20044530433008060667810c0102013037060b2b\
        0601040182df130101013028302606082b06010505070201161a687474703a2f2f6370732e6c657473656e63727\
        970742e6f726730820103060a2b06010401d6790204020481f40481f100ef0076004494652eb0eeceafc44007d8\
        a8fe28c0dae682bed8cb31b53fd33396b5b681a80000017876b7770e000004030047304502201c5b58adfa5df8a\
        bf6077d94b765750a24d32b49b3af2dcf5c65efaf32c949d6022100866e2301bf3633cf54a33124459c9dc69e6f\
        953c9b2200f7c73919cefee849150075007d3ef2f88fff88556824c2c0ca9e5289792bc50e78097f2e6a9768997\
        e22f0d70000017876b7772e00000403004630440220030a54d2296566cab9b5fa3e6505566e5e014d48f15f6cd8\
        727896e2cc352eb302207aff1ae19ca44c14dc0e136583dde241f742f141ec518adf26c5b08d59d92936300d060\
        92a864886f70d01010b050003820101008c770bcf525fc99d9f8f04d279b724bbb2bebc42184e671aa392b05826\
        5b097de2d9f668f64e696d0048a00023ad2c6dfd5cc6f41bde11810d0fbad97822c6863012a4f0e8430a385cfeb\
        699278e99622af1cca45419cb61d59dcbb80464cf65ff07d15c05f69caf2a69970cae8b4533f5a006b9b9414cba\
        a6d8a8ac862c430dadb8149e6c151ff75efe0a69b17658b85dbd95a6eb363e52784b9f11c78bbe906ca303f58bb\
        eab8748e92d31344a6c297dfab4738351602951622cd3730f2b94ba7e68ecc1f678a79f5535f6758be357cf0a8a\
        9efa907c2980b2d281c270b7fb97d8c3e1d3af37089002d09e7524d8d441950da466ee77489d25018e5cfa05fe0\
        000000469308204653082034da0030201020210400175048314a4c8218c84a90c16cddf300d06092a864886f70d\
        01010b0500303f31243022060355040a131b4469676974616c205369676e617475726520547275737420436f2e3\
        11730150603550403130e44535420526f6f74204341205833301e170d3230313030373139323134305a170d3231\
        303932393139323134305a3032310b300906035504061302555331163014060355040a130d4c6574277320456e6\
        372797074310b300906035504031302523330820122300d06092a864886f70d01010105000382010f003082010a\
        0282010100bb021528ccf6a094d30f12ec8d5592c3f882f199a67a4288a75d26aab52bb9c54cb1af8e6bf975c8a\
        3d70f4794145535578c9ea8a23919f5823c42a94e6ef53bc32edb8dc0b05cf35938e7edcf69f05a0b1bbec09424\
        2587fa3771b313e71cace19befdbe43b45524596a9c153ce34c852eeb5aeed8fde6070e2a554abb66d0e97a5403\
        46b2bd3bc66eb66347cfa6b8b8f572999f830175dba726ffb81c5add286583d17c7e709bbf12bf786dcc1da715d\
        d446e3ccad25c188bc60677566b3f118f7a25ce653ff3a88b647a5ff1318ea9809773f9d53f9cf01e5f5a670171\
        4af63a4ff99b3939ddc53a706fe48851da169ae2575bb13cc5203f5ed51a18bdb150203010001a3820168308201\
        6430120603551d130101ff040830060101ff020100300e0603551d0f0101ff040403020186304b06082b0601050\
        5070101043f303d303b06082b06010505073002862f687474703a2f2f617070732e6964656e74727573742e636f\
        6d2f726f6f74732f647374726f6f74636178332e703763301f0603551d23041830168014c4a7b1a47b2c71fadbe\
        14b9075ffc4156085891030540603551d20044d304b3008060667810c010201303f060b2b0601040182df130101\
        013030302e06082b060105050702011622687474703a2f2f6370732e726f6f742d78312e6c657473656e6372797\
        0742e6f7267303c0603551d1f043530333031a02fa02d862b687474703a2f2f63726c2e6964656e74727573742e\
        636f6d2f445354524f4f544341583343524c2e63726c301d0603551d0e04160414142eb317b75856cbae500940e\
        61faf9d8b14c2c6301d0603551d250416301406082b0601050507030106082b06010505070302300d06092a8648\
        86f70d01010b05000382010100d94ce0c9f584883731dbbb13e2b3fc8b6b62126c58b7497e3c02b7a81f2861ebc\
        ee02e73ef49077a35841f1dad68f0d8fe56812f6d7f58a66e3536101c73c3e5bd6d5e01d76e72fb2aa0b8d35764\
        e55bc269d4d0b2f77c4bc3178e887273dcfdfc6dbde3c90b8e613a16587d74362b55803dc763be8443c639a10e6\
        b579e3f29c180f6b2bd47cbaa306cb732e159540b1809175e636cfb96673c1c730c938bc611762486de400707e4\
        7d2d66b525a39658c8ea80eecf693b96fce68dc033f389f8292d14142d7ef06170955df70be5c0fb24faec8ecb6\
        1c8ee637128a82c053b77ef9b5e0364f051d1e485535cb00297d47ec634d2ce1000e4b1df3ac2ea17be0000";

            let cert = hex::decode(cert_hex).unwrap();

            let mut opaque_message =
                OpaqueMessage::read(&mut Reader::init(cert.as_slice())).unwrap();
            // Required for choosing the correct parsing function
            opaque_message.version = ProtocolVersion::TLSv1_3;
            create_message(opaque_message);
        }

        #[test_log::test]
        fn test_encrypted_tls12_into_message() {
            let opaque_message = OpaqueMessage {
                typ: ContentType::Handshake,
                version: ProtocolVersion::TLSv1_2,
                payload: Payload::new(vec![1, 2, 3]),
            };

            create_message(opaque_message);
        }

        #[test_log::test]
        fn test_rustls_message_stability() {
            let random = [0u8; 32];
            let message = Message {
                version: ProtocolVersion::TLSv1_2,
                payload: Handshake(HandshakeMessagePayload {
                    typ: HandshakeType::ClientHello,
                    payload: HandshakePayload::ClientHello(ClientHelloPayload {
                        client_version: ProtocolVersion::TLSv1_3,
                        random: Random::from(random),
                        session_id: SessionID::empty(),
                        cipher_suites: CipherSuites(vec![]),
                        compression_methods: Compressions(vec![]),
                        extensions: ClientExtensions(vec![]),
                    }),
                }),
            };

            let mut out: Vec<u8> = Vec::new();
            out.append(
                &mut PlainMessage::from(message)
                    .into_unencrypted_opaque()
                    .get_encoding(),
            );
            //hexdump::hexdump(&out);

            let opaque_message = OpaqueMessage::read(&mut Reader::init(out.as_slice())).unwrap();
            create_message(opaque_message);
        }
    }

    /// Check if Messages sent at a failing step are captured
    #[cfg(not(feature = "wolfssl430"))]
    #[apply(test_puts, filter = all(tls13))]
    fn test_trigger_alert(put: &str) {
        // sending an incorrect message
        let trace = Trace {
            prior_traces: vec![],
            descriptors: vec![AgentDescriptor::from_config(
                AgentName::first(),
                TLSDescriptorConfig {
                    tls_version: TLSVersion::V1_3,
                    typ: AgentType::Server,
                    ..TLSDescriptorConfig::default()
                },
            )],
            steps: vec![Step {
                agent: AgentName::first(),
                action: Action::Input(input_action! { term! {
                    // Broken ClientHello
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
                                        (fn_ciphersuites(fn_list_ciphersuite_empty)),
                                        fn_compressions(
                                            fn_list_compression_append(
                                                fn_list_compression_empty,
                                                fn_compression_null
                                            )
                                        ),
                                        (fn_clientextensions(fn_list_clientextension_empty))
                                    )
                                )
                            )
                        )
                    )
                }
                }),
            }],
            ..Default::default()
        };

        let mut ctx = puffin::trace::TraceContext::new(
            puffin::trace::Spawner::new(tls_registry()).with_mapping(&[(
                AgentName::first(),
                PutDescriptor::new(put, PutOptions::empty()),
            )]),
        );
        let _ = trace.execute(&mut ctx, &mut 0, true);

        // Try to find an alert message in the knowledges
        let alert = ctx.find_variable(
            TypeShape::of::<Message>(),
            &Query {
                source: None,
                matcher: Some(TlsQueryMatcher::Alert),
                counter: 0,
                is_claim: false,
            },
        );

        assert!(alert.is_some());
    }

    /// Helper: run all differential seeds between two PUTs and assert no differences.
    #[allow(dead_code)]
    fn assert_no_differential_differences(first_put: &str, second_put: &str) {
        use puffin::execution::{DifferentialRunner, TraceRunner};
        use puffin::protocol::ProtocolTypes;
        use puffin::trace::Spawner;

        use crate::protocol::TLSProtocolTypes;

        let registry = crate::put_registry::tls_registry();
        let first_factory = registry
            .find_by_id(first_put)
            .expect("first differential PUT must exist in the TLS registry");
        let second_factory = registry
            .find_by_id(second_put)
            .expect("second differential PUT must exist in the TLS registry");

        let second_seed_names: std::collections::HashSet<_> = super::create_corpus(second_factory)
            .into_iter()
            .map(|(_, name)| name)
            .collect();
        let corpus: Vec<_> = super::create_corpus(first_factory)
            .into_iter()
            .filter(|(_, name)| second_seed_names.contains(name))
            .collect();

        for (trace, name) in corpus {
            let trace =
                <TLSProtocolTypes as ProtocolTypes>::differential_fuzzing_uniformise_put_config(
                    trace,
                );
            // Map ALL agents in the trace (including prior traces) to the specified PUT.
            // Without this, agents in prior traces silently fall back to the default PUT,
            // producing mixed-PUT executions that hide real differences.
            let first_mappings: Vec<_> = trace
                .all_descriptors()
                .iter()
                .map(|d| {
                    (
                        d.name,
                        PutDescriptor::new(first_put, registry.default_put_options().clone()),
                    )
                })
                .collect();
            let second_mappings: Vec<_> = trace
                .all_descriptors()
                .iter()
                .map(|d| {
                    (
                        d.name,
                        PutDescriptor::new(second_put, registry.default_put_options().clone()),
                    )
                })
                .collect();

            let runner = DifferentialRunner::new(
                registry.clone(),
                Spawner::new(registry.clone()).with_mapping(&first_mappings),
                Spawner::new(registry.clone()).with_mapping(&second_mappings),
            );

            let result = runner.execute(trace, &mut 0);
            assert!(
                result.is_ok(),
                "Differential test failed between {} and {}: seed '{}': {:?}",
                first_put,
                second_put,
                name,
                result.err()
            );
        }
    }

    #[apply(test_differential_puts, first = "openssl340", second = "wolfssl580")]
    fn test_differential_openssl340_vs_wolfssl580() {
        assert_no_differential_differences("openssl340", "wolfssl580");
    }

    #[apply(test_differential_puts, first = "openssl340", second = "libressl421")]
    fn test_differential_openssl340_vs_libressl421() {
        assert_no_differential_differences("openssl340", "libressl421");
    }

    #[apply(
        test_differential_puts,
        first = "openssl340",
        second = "boringssl20260508"
    )]
    fn test_differential_openssl340_vs_boringssl20260508() {
        assert_no_differential_differences("openssl340", "boringssl20260508");
    }
}
