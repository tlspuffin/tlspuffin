use std::ops::BitXor;

use itertools::Itertools;
use log::info;
use puffin::{
    agent::{AgentDescriptor, AgentName, AgentType, TLSVersion},
    algebra::{dynamic_function::DescribableFunction, set_deserialize_signature, Term},
    fuzzer::{
        harness::default_put_options,
        sanitizer::libafl_targets::{EDGES_MAP, MAX_EDGES_NUM},
    },
    libafl::inputs::Input,
    put::PutOptions,
    term,
    trace::{Action, InputAction, Step, Trace, TraceContext},
};

use crate::{
    put_registry::TLS_PUT_REGISTRY,
    query::TlsQueryMatcher,
    tls::{fn_impl::*, trace_helper::TraceHelper, TLS_SIGNATURE},
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
    let certificate_verify = trace.steps.get_mut(2).unwrap();
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

/*#[no_mangle]
pub unsafe extern "C" fn __sanitizer_cov_trace_pc_guard(guard: *mut u32) {
    if (!*guard) return;  // Duplicate the guard check.
    // If you set *guard to 0 this code will not be called again for this edge.
    // Now you can get the PC and do whatever you want:
    //   store it somewhere or symbolize it and print right away.
    // The values of `*guard` are as you set them in
    // __sanitizer_cov_trace_pc_guard_init and so you can make them consecutive
    // and use them to dereference an array or a bit vector.
    void *PC = __builtin_return_address(0);
    char PcDescr[1024];
    // This function is a part of the sanitizer run-time.
    // To use it, link with AddressSanitizer or other sanitizer.
    __sanitizer_symbolize_pc(PC, "%p %F %L", PcDescr, sizeof(PcDescr));
    printf("guard: %p %x PC %s\n", guard, *guard, PcDescr);
}


#[no_mangle]
pub unsafe extern "C" fn __sanitizer_cov_trace_pc_guard_init(mut start: *mut u32, stop: *mut u32) {


    if start == stop || *start != 0 {
        return;
    }

    while start < stop {
        *start = MAX_EDGES_NUM as u32;
        start = start.offset(1);

            MAX_EDGES_NUM = MAX_EDGES_NUM.wrapping_add(1);
            assert!((MAX_EDGES_NUM <= EDGES_MAP.len()), "The number of edges reported by SanitizerCoverage exceed the size of the edges map ({}). Use the LIBAFL_EDGES_MAP_SIZE env to increase it at compile time.", EDGES_MAP.len());

    }
}*/

static COUNT_CLASS_LOOKUP: [u8; 256] = [
    0, 1, 2, 4, 8, 8, 8, 8, 16, 16, 16, 16, 16, 16, 16, 16, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32,
    32, 32, 32, 32, 32, 32, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
];
const CORPUS: &'static str = "2022-11-04-165625-dd2b26-0";

#[test]
#[cfg(feature = "wolfssl510")]
#[cfg(feature = "tls13")] // require version which supports TLS 1.3
#[cfg(feature = "client-authentication-transcript-extraction")]
//#[cfg(not(feature = "fix-CVE-2022-25638"))]
#[ignore]
fn test_seed_cve_2022_25638_coveragetest() {
    set_deserialize_signature(&TLS_SIGNATURE);

    fn perform_class_lookup() {
        unsafe {
            for v in EDGES_MAP[0..MAX_EDGES_NUM].iter_mut() {
                *v = COUNT_CLASS_LOOKUP[*v as usize];
            }
        }
    }

    fn generate_corpus_edges() -> Vec<u8> {
        let paths = std::fs::read_dir(format!("/home/max/Downloads/{CORPUS}/corpus")).unwrap();

        let mut history_map = unsafe { vec![0u8; MAX_EDGES_NUM] };

        for path in paths {
            let entry = path.unwrap();

            if entry.file_name().to_str().unwrap().starts_with(".") {
                continue;
            }

            let trace = Trace::<TlsQueryMatcher>::from_file(entry.path()).unwrap();

            reset_edges();
            trace.execute_deterministic(&TLS_PUT_REGISTRY, PutOptions::default());
            perform_class_lookup();

            unsafe {
                for i in 0..MAX_EDGES_NUM {
                    let history = history_map.get_unchecked_mut(i);
                    let hitcount_or_edge = EDGES_MAP[i];
                    if hitcount_or_edge > *history {
                        *history = hitcount_or_edge;
                    }
                }
            }
        }
        history_map
    }

    fn reset_edges() {
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

    fn write_edges_map(name: &str, map: &[u8]) {
        unsafe {
            std::fs::write(name, map).expect("Unable to write file");
        }
    }

    /*    fn coverage_hash() -> u64 {
        unsafe {
            const K: u64 = 0x517cc1b727220a95;

            EDGES_MAP[0..MAX_EDGES_NUM]
                .iter()
                .map(|n| *n as u64)
                .reduce(|acc, n| acc.rotate_left(5).bitxor(n).wrapping_mul(K))
                .unwrap()
        }
    }*/

    let items: [(&'static str, fn(&mut Trace<TlsQueryMatcher>)); 3] = [
        ("cert_eve", mutate_fn_eve_cert),
        (
            "invalid_signature_algorithm",
            mutate_fn_invalid_signature_algorithm,
        ),
        ("eve_pkcs1_signature", mutate_fn_eve_pkcs1_signature),
    ];

    // Prepare
    assert_eq!(hitcount(), 0);

    //let history_map = generate_corpus_edges();
    //write_edges_map(CORPUS, &history_map);
    let history_map = std::fs::read(CORPUS).unwrap();
    //let mut history_map = unsafe { vec![0u8; MAX_EDGES_NUM] };
    println!("Corpus hitcount {}", hitcount());
    println!("MAX_EDGES_NUM {}", unsafe { MAX_EDGES_NUM });

    let mut maps = Vec::new();

    // Permute
    for (i, perm) in items.iter().permutations(items.len()).enumerate() {
        println!("Permutation: {}", i);

        let mut current_history = history_map.clone();

        let mut trace = seed_client_attacker_auth.build_trace();

        // Verify that executing trace as is does not change coverage
        reset_edges();
        trace
            .execute_deterministic(&TLS_PUT_REGISTRY, PutOptions::default())
            .map_err(|e| println!("{}", e));
        perform_class_lookup();

        let previous_history = current_history.clone();
        unsafe {
            for i in 0..MAX_EDGES_NUM {
                let history = current_history.get_unchecked_mut(i);
                let item = EDGES_MAP[i];
                if item > *history {
                    *history = item;
                }
            }
        }

        if previous_history != current_history {
            for (i, (m, h)) in current_history
                .iter()
                .zip(previous_history.iter())
                .enumerate()
            {
                if m != h {
                    println!("\tat: {i} - {m} != {h}")
                }
            }
            println!("interesting test case which should not be interseting");
        }

        for (name, mutator) in perm {
            println!("{}", name);
            mutator(&mut trace);

            reset_edges();
            trace
                .execute_deterministic(&TLS_PUT_REGISTRY, PutOptions::default())
                .map_err(|e| println!("{}", e));
            perform_class_lookup();

            let previous_history = current_history.clone();
            unsafe {
                for i in 0..MAX_EDGES_NUM {
                    let history = current_history.get_unchecked_mut(i);
                    let item = EDGES_MAP[i];
                    if item > *history {
                        *history = item;
                    }
                }
            }

            maps.push(((i, name), previous_history, current_history.clone()));
        }
    }

    // Evaluation
    for ((i, name), previous_history, current_history) in maps {
        if previous_history != current_history {
            println!("interesting: {i} - {name}");
            for (i, (m, h)) in current_history
                .iter()
                .zip(previous_history.iter())
                .enumerate()
            {
                if m != h {
                    println!("\tat: {i} - {m} != {h}")
                }
            }
        } else {
            println!("not interesting: {i} - {name}")
        }
    }
}
