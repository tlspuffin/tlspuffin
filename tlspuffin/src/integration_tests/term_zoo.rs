/// Test the function symbols that can be generated, evaluated, encoded
#[allow(clippy::ptr_arg)]
#[cfg(test)]
mod tests {
    use std::{any::Any, cmp::max, collections::HashSet, fmt::Debug};

    use itertools::Itertools;
    use log::{debug, error, warn};
    use puffin::{
        agent::AgentName,
        algebra::{
            dynamic_function::DescribableFunction, error::FnError, evaluate_lazy_test,
            signature::FunctionDefinition, ConcreteMessage, Matcher, TermEval, TermType,
        },
        codec,
        codec::Encode,
        error::Error,
        fuzzer::{
            term_zoo::TermZoo,
            utils::{choose, find_term_by_term_path_mut, Choosable, TermConstraints},
        },
        libafl::{bolts::rands::StdRand, prelude::Rand},
        protocol::ProtocolBehavior,
        trace::{Action::Input, InputAction, Step, Trace, TraceContext},
    };

    use crate::{
        protocol::TLSProtocolBehavior,
        put_registry::TLS_PUT_REGISTRY,
        query::TlsQueryMatcher,
        tls::{
            fn_impl::*,
            rustls::{
                hash_hs::HandshakeHash,
                key::{Certificate, PrivateKey},
                msgs::{
                    alert::AlertMessagePayload,
                    enums::{
                        CipherSuite, Compression, ExtensionType, HandshakeType, NamedGroup,
                        ProtocolVersion, SignatureScheme,
                    },
                    handshake::{
                        CertificateEntry, ClientExtension, HasServerExtensions, Random,
                        ServerExtension, SessionID,
                    },
                    message::{Message, MessagePayload, OpaqueMessage},
                },
            },
            trace_helper::TraceHelper,
            TLS_SIGNATURE,
        },
        try_downcast,
    };

    #[test]
    #[test_log::test]
    /// Tests whether all function symbols can be used when generating random terms
    fn test_term_generation() {
        let mut rand = StdRand::with_seed(101);
        let zoo = TermZoo::<TlsQueryMatcher>::generate_many(&TLS_SIGNATURE, &mut rand, 1, None);
        // debug!("zoo size: {}", zoo.terms().len());
        let subgraphs = zoo
            .terms()
            .iter()
            .enumerate()
            .map(|(i, term)| term.dot_subgraph(false, i, i.to_string().as_str()))
            .collect::<Vec<_>>();
        // debug!("subgraph size: {}", subgraphs.len());

        let _graph = format!(
            "strict digraph \"Trace\" {{ splines=true; {} }}",
            subgraphs.join("\n")
        );

        let all_functions = TLS_SIGNATURE
            .functions
            .iter()
            .map(|(shape, _)| shape.name.to_string())
            .collect::<HashSet<String>>();

        let mut successfully_built_functions = zoo
            .terms()
            .iter()
            .map(|term| term.name().to_string())
            .collect::<HashSet<String>>();

        // Those 4 are the function symbols for which we fail to generator a term!
        let ignored_functions = [
            fn_server_finished_transcript.name(),
            fn_client_finished_transcript.name(),
            fn_server_hello_transcript.name(),
            fn_certificate_transcript.name(),
            // OLD STUFF, NOT NEEDED:
            //  fn_decrypt_application.name(), // FIXME: why ignore this?
            //  fn_rsa_sign_client.name(), // FIXME: We are currently excluding this, because an attacker does not have access to the private key of alice, eve or bob.
            //  fn_rsa_sign_server.name(),
            // // transcript functions -> ClaimList is usually available as Variable
        ]
        .iter()
        .map(|fn_name| fn_name.to_string())
        .collect::<HashSet<String>>();

        successfully_built_functions.extend(ignored_functions);

        let difference = all_functions.difference(&successfully_built_functions);
        debug!("Diff: {:?}\n", &difference);
        // debug!("Successfully built: {:?}\n", &successfully_built_functions);
        debug!(
            "Successfully built: #{:?}",
            &successfully_built_functions.len()
        );
        debug!("All functions: #{:?}", &all_functions.len());
        assert_eq!(difference.count(), 0);
        // TESTED OK WITH generate_many CALLED WITH HOW_MANY = 400, mo more functions found with MAX_DEPTH=2000 and MAX_TRIES = 50000
        //debug!("{}", graph);
    }

    #[test]
    #[test_log::test]
    fn test_term_lazy_eval() {
        let mut rand = StdRand::with_seed(101);
        let zoo = TermZoo::<TlsQueryMatcher>::generate_many(&TLS_SIGNATURE, &mut rand, 400, None);
        // debug!("zoo size: {}", zoo.terms().len());
        let subgraphs = zoo
            .terms()
            .iter()
            .enumerate()
            .map(|(i, term)| term.dot_subgraph(false, i, i.to_string().as_str()))
            .collect::<Vec<_>>();
        // debug!("subgraph size: {}", subgraphs.len());

        let _graph = format!(
            "strict digraph \"Trace\" {{ splines=true; {} }}",
            subgraphs.join("\n")
        );

        let all_functions = TLS_SIGNATURE
            .functions
            .iter()
            .map(|(shape, _)| shape.name.to_string())
            .collect::<HashSet<String>>();

        let mut ctx = TraceContext::new(&TLS_PUT_REGISTRY, Default::default());
        let mut successfully_built_functions = zoo
            .terms()
            .iter()
            .filter(|t| evaluate_lazy_test(t, &ctx).is_ok())
            .map(|term| term.name().to_string())
            .collect::<HashSet<String>>();

        let ignored_functions = [
            // "dsfsdfgsdf"
            // Those 4 are the function symbols for which we fail to generator a term!
            fn_server_finished_transcript.name(),
            fn_client_finished_transcript.name(),
            fn_server_hello_transcript.name(),
            fn_certificate_transcript.name(),
            // Those 4 are the function symbols for which we can generate a term but all fail to lazy execute!
            fn_ecdsa_sign_server.name(),
            fn_ecdsa_sign_client.name(),
            fn_decrypt_handshake.name(),
            fn_decrypt_application.name(),
            // Additional failures: we need to be able to decrypt some server's message, very complicated in practice
            fn_find_server_certificate_verify.name(),
            fn_decrypt_multiple_handshake_messages.name(),
            fn_find_encrypted_extensions.name(),
            fn_find_server_certificate.name(),
            fn_find_server_finished.name(),
        ]
        .iter()
        .map(|fn_name| fn_name.to_string())
        .collect::<HashSet<String>>();

        successfully_built_functions.extend(ignored_functions);

        let difference = all_functions.difference(&successfully_built_functions);
        debug!("Successfully built: {:?}", &successfully_built_functions);
        debug!("Diff: {:?}\n", &difference);
        debug!(
            "Successfully built: #{:?}",
            &successfully_built_functions.len()
        );
        debug!("All functions: #{:?}", &all_functions.len());
        assert_eq!(difference.count(), 0);
        // TESTED OK WITH generate_many CALLED WITH HOW_MANY = 200, mo more functions found with how_many = 10 000
        //debug!("{}", graph);
    }

    #[test]
    #[test_log::test]
    /// Tests whether all function symbols can be used when generating random terms and then be correctly evaluated
    fn test_term_eval_() {
        let mut rand = StdRand::with_seed(101);
        let zoo = TermZoo::<TlsQueryMatcher>::generate_many(&TLS_SIGNATURE, &mut rand, 400, None);
        let terms = zoo.terms();
        let number_terms = terms.len();
        let mut ctx = TraceContext::new(&TLS_PUT_REGISTRY, Default::default());
        let mut eval_count = 0;
        let mut count_lazy_fail = 0;
        let mut count_any_encode_fail = 0;
        let mut successfully_built_functions = vec![];

        for term in terms.iter() {
            if successfully_built_functions.contains(&term.name().to_string()) {
                // for speeding up things
                continue;
            }
            if true
                || term.name().to_string()
                    == "tlspuffin::tls::fn_impl::fn_utils::fn_get_ticket_nonce"
            {
                match term.evaluate(&ctx) {
                    Ok(eval) => {
                        // debug!("OKAY");
                        successfully_built_functions.push(term.name().to_string().to_owned());
                        eval_count += 1;

                        // debug!(
                        //     " [x] Succeed evaluation of term: {} \nresulting in {:?}\n",
                        //     term, eval
                        // );
                    }
                    Err(e) => {
                        let t1 = evaluate_lazy_test(&term, &ctx);
                        if t1.is_err() {
                            // debug!("LAZY failed!");
                            count_lazy_fail += 1;
                        } else {
                            count_any_encode_fail += 1;
                            match e.clone() { // for debugging encoding failure only
                            Error::Fn(FnError::Unknown(ee)) =>
                                debug!("[Unknown] Failed evaluation due to FnError::Unknown: [{}]", e),
                            Error::Fn(FnError::Crypto(ee)) =>
                                debug!("[Crypto] Failed evaluation due to FnError::Crypto:[{}]\nTerm: {}", e, term),
                            Error::Fn(FnError::Malformed(ee)) =>
                                debug!("[Malformed] Failed evaluation due to FnError::Crypto:[{}]", e),
                            Error::Term(ee) => {
                                debug!("[Term] Failed evaluation due to Error:Term: [{}]\n ===For Term: [{}]", e, term)
                            },
                            _ => {
                                // _ => {
                                debug!("===========================\n\n\n [OTHER] Failed evaluation of term: {} \n with error {}. Trying to downcast manually:", term, e);
                                let t1 = evaluate_lazy_test(&term, &ctx);
                                if t1.is_ok() {
                                    debug!("Evaluate_lazy success. ");
                                    match t1.expect("NO").downcast_ref::<bool>() {
                                        Some(downcast) => {
                                            print!("Downcast succeeded: {downcast:?}. ");
                                            // let bitstring = Encode::get_encoding(downcast);
                                            // print!("Encoding succeeded:: {bitstring:?}. ");
                                        },
                                        _ => { warn!("Downcast FAILED. ") },
                                    }
                                } else {
                                    warn!("Evaluate_lazy FAILED. ");
                                }
                            }
                            _ => {},
                        }
                        }
                    }
                }
            }
        }

        let all_functions = TLS_SIGNATURE
            .functions
            .iter()
            .map(|(shape, _)| shape.name.to_string())
            .collect::<HashSet<String>>();

        let mut successfully_built_functions_names = successfully_built_functions
            .iter()
            .map(|s| s.to_owned())
            .collect::<HashSet<String>>();

        let ignored_functions = [
            // Those 4 are the function symbols for which we fail to generator a term!
            fn_server_finished_transcript.name(),
            fn_client_finished_transcript.name(),
            fn_server_hello_transcript.name(),
            fn_certificate_transcript.name(),
            // Those 4 are the function symbols for which we can generate a term but all fail to lazy execute!
            fn_ecdsa_sign_server.name(),
            fn_ecdsa_sign_client.name(),
            fn_decrypt_handshake.name(),
            fn_decrypt_application.name(), // All other terms can also be encoded (no additional exception for full eval :) !)
            // Additional failures: we need to be able to decrypt some server's message, very complicated in practice
            fn_find_server_certificate_verify.name(),
            fn_decrypt_multiple_handshake_messages.name(),
            fn_find_encrypted_extensions.name(),
            fn_find_server_certificate.name(),
            fn_find_server_finished.name(),
        ]
        .iter()
        .map(|fn_name| fn_name.to_string())
        .collect::<HashSet<String>>();

        successfully_built_functions_names.extend(ignored_functions);

        let difference = all_functions.difference(&successfully_built_functions_names);

        debug!("Diff: {:?}\n", &difference);
        debug!(
            "Successfully built: #{:?}",
            &successfully_built_functions.len()
        );
        debug!("All functions: #{:?}", &all_functions.len());
        debug!("number_terms: {}, eval_count: {}, count_lazy_fail: {count_lazy_fail}, count_any_encode_fail: {count_any_encode_fail}\n", number_terms, eval_count);
        assert_eq!(difference.count(), 0);
        assert_eq!(count_any_encode_fail, 0);
    }

    fn add_payloads_randomly<M: Matcher, R: Rand, PB: ProtocolBehavior<Matcher = M>>(
        t: &mut TermEval<M>,
        rand: &mut R,
        ctx: &TraceContext<PB>,
    ) {
        let trace = Trace {
            descriptors: vec![],
            steps: vec![Step {
                agent: AgentName::new(),
                action: Input(InputAction { recipe: t.clone() }),
            }],
            prior_traces: vec![],
        };
        let all_subterms: Vec<&TermEval<M>> = t.into_iter().collect_vec();
        let nb_subterms = all_subterms.len() as i32;
        let mut i = 0;
        let nb = (1..max(4, nb_subterms / 3))
            .collect::<Vec<i32>>()
            .choose(rand)
            .unwrap()
            .to_owned();
        error!(
            "Adding {nb} payloads for #subterms={nb_subterms}, max={} in term: {t}...",
            max(2, nb_subterms / 5)
        );
        let mut tries = 0;
        // let nb = 1;
        while i < nb {
            tries += 1;
            if tries > nb * 100 {
                error!("Failed to add the payloads after {} attempts", tries);
                break;
            }
            if let Some((st_, (step, mut path))) = choose(
                &trace,
                TermConstraints {
                    not_inside_list: true,
                    no_payload_in_subterm: true,
                    weighted_depth: true,
                    ..TermConstraints::default()
                },
                rand,
            ) {
                let st = find_term_by_term_path_mut(t, &mut path).unwrap();
                if let Ok(()) = st.make_payload(&ctx) {
                    i += 1;
                    error!("Added payload for subterm at path {path:?}, evaluated={:?}, sub_term: {st_}", st.payloads.as_ref().unwrap().payload_0);
                    if let Some(payloads) = &mut st.payloads {
                        let mut a: Vec<u8> = payloads.payload.clone().into();
                        a.push(2);
                        a.push(2);
                        a.push(2);
                        a[0] = 2;
                        payloads.payload = a.into();
                        debug!("Added a payload at path {path:?}.");
                    }
                }
            }
        }
    }

    #[test]
    #[test_log::test]
    /// Tests whether all function symbols can be used when generating random terms and then be correctly evaluated
    fn test_term_eval_payloads() {
        let mut rand = StdRand::with_seed(101);
        let all_functions_shape = TLS_SIGNATURE.functions.to_owned();
        let mut ctx = TraceContext::new(&TLS_PUT_REGISTRY, Default::default());
        let mut eval_count = 0;
        let mut count_lazy_fail = 0;
        let mut count_payload_fail = 0;
        let mut count_any_encode_fail = 0;
        let mut number_terms = 0;
        let number_shapes = all_functions_shape.len();
        let mut successfully_built_functions = vec![];

        for f in all_functions_shape {
            let zoo =
                TermZoo::<TlsQueryMatcher>::generate_many(&TLS_SIGNATURE, &mut rand, 400, Some(&f));
            let terms = zoo.terms();
            number_terms = number_terms + terms.len();

            for term in terms.iter() {
                if successfully_built_functions.contains(&term.name().to_string()) {
                    // for speeding up things
                    continue; // should never happen
                }
                // ["tlspuffin::tls::fn_impl::fn_fields::fn_get_client_key_share",
                // "tlspuffin::tls::fn_impl::fn_utils::fn_encrypt_handshake",
                // "tlspuffin::tls::fn_impl::fn_utils::fn_derive_psk",
                // "tlspuffin::tls::fn_impl::fn_fields::fn_sign_transcript",
                // "tlspuffin::tls::fn_impl::fn_utils::fn_get_ticket_nonce",
                // "tlspuffin::tls::fn_impl::fn_utils::fn_encrypt12"]

                // FILTRAGE
                // if !(term.name().to_string().to_owned() == "tlspuffin::tls::fn_impl::fn_utils::fn_encrypt_handshake") {
                //     continue;
                // }
                let mut term_with_payloads = term.clone();

                add_payloads_randomly(&mut term_with_payloads, &mut rand, &ctx);

                if term_with_payloads.payloads_to_replace().len() == 0 {
                    warn!("Failed to add paylaods, skipping...");
                    continue;
                }

                error!("Term with paylaods: {term_with_payloads}");

                match &term_with_payloads.evaluate(&ctx) {
                    Ok(eval) => {
                        error!("Eval success!");
                        successfully_built_functions.push(term.name().to_string().to_owned());
                        eval_count += 1;
                    }
                    Err(e) => {
                        match &term_with_payloads.clone().evaluate_symbolic(&ctx) {
                            Ok(_) => {
                                error!("Eval FAILED!");
                                count_payload_fail += 1;
                                error!(
                                    "[Payload] Failed evaluation due to PAYLOADS. Term:\n{}",
                                    term_with_payloads
                                );
                            }
                            Err(_) => {
                                let t1 = evaluate_lazy_test(&term_with_payloads, &ctx);
                                if t1.is_err() {
                                    debug!("LAZY failed!");
                                    count_lazy_fail += 1;
                                } else {
                                    count_any_encode_fail += 1;
                                    match e.clone() { // for debugging encoding failure only
                                        Error::Fn(FnError::Unknown(ee)) =>
                                            debug!("[Unknown] Failed evaluation due to FnError::Unknown: [{}]", e),
                                        Error::Fn(FnError::Crypto(ee)) =>
                                            debug!("[Crypto] Failed evaluation due to FnError::Crypto:[{}]\nTerm: {}", e, term_with_payloads),
                                        Error::Fn(FnError::Malformed(ee)) =>
                                            debug!("[Malformed] Failed evaluation due to FnError::Crypto:[{}]", e),
                                        Error::Term(ee) => {
                                            debug!("[Term] Failed evaluation due to Error:Term: [{}]\n ===For Term: [{}]", e, term_with_payloads)
                                        },
                                        _ => {
                                            // _ => {
                                            debug!("===========================\n\n\n [OTHER] Failed evaluation of term: {} \n with error {}. Trying to downcast manually:", term_with_payloads, e);
                                            let t1 = evaluate_lazy_test(&term_with_payloads, &ctx);
                                            if t1.is_ok() {
                                                debug!("Evaluate_lazy success. ");
                                                match t1.expect("NO").downcast_ref::<bool>() {
                                                    Some(downcast) => {
                                                        print!("Downcast succeeded: {downcast:?}. ");
                                                        // let bitstring = Encode::get_encoding(downcast);
                                                        // print!("Encoding succeeded:: {bitstring:?}. ");
                                                    },
                                                    _ => { warn!("Downcast FAILED. ") },
                                                }
                                            } else {
                                                warn!("Evaluate_lazy FAILED. ");
                                            }
                                        }
                                        _ => {},
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        //["tlspuffin::tls::fn_impl::fn_fields::fn_get_server_key_share",
        // "tlspuffin::tls::fn_impl::fn_utils::fn_get_ticket_nonce",
        // "tlspuffin::tls::fn_impl::fn_utils::fn_encrypt_application",
        // "tlspuffin::tls::fn_impl::fn_fields::fn_sign_transcript",
        // "tlspuffin::tls::fn_impl::fn_utils::fn_get_ticket_age_add",
        // "tlspuffin::tls::fn_impl::fn_fields::fn_get_any_client_curve",
        // "tlspuffin::tls::fn_impl::fn_utils::fn_encrypt_handshake",
        // "tlspuffin::tls::fn_impl::fn_utils::fn_get_ticket",
        // "tlspuffin::tls::fn_impl::fn_fields::fn_get_client_key_share",
        // "tlspuffin::tls::fn_impl::fn_utils::fn_derive_psk",
        // "tlspuffin::tls::fn_impl::fn_utils::fn_encrypt12"]
        // OPAQUE
        // self.fn_container.shape.name == "tlspuffin::tls::fn_impl::fn_utils::fn_encrypt_handshake" //TODO
        //     || self.fn_container.shape.name == "tlspuffin::tls::fn_impl::fn_utils::fn_encrypt12"
        //     || self.fn_container.shape.name == "tlspuffin::tls::fn_impl::fn_utils::fn_derive_binder"
        //     || self.fn_container.shape.name == "tlspuffin::tls::fn_impl::fn_utils::fn_derive_psk"
        //     || self.fn_container.shape.name == "tlspuffin::tls::fn_impl::fn_utils::fn_decode_ecdh_pubkey"
        //     || self.fn_container.shape.name == "tlspuffin::tls::fn_impl::fn_utils::fn_new_pubkey12"
        //     || self.fn_container.shape.name == "tlspuffin::tls::fn_impl::fn_cert::fn_rsa_sign_server"
        //     || self.fn_container.shape.name == "tlspuffin::tls::fn_impl::fn_cert::fn_rsa_sign_client"
        //
        //     // Get functions: opaque as they do not yield a bitstring containing all the bitstrings of their arguments
        //     // (however needed for computing shifts in `replace_payloads`) TODO: improve this in the future
        //     || self.fn_container.shape.name == "tlspuffin::tls::fn_impl::fn_fields::fn_get_server_key_share"
        //     || self.fn_container.shape.name == "tlspuffin::tls::fn_impl::fn_fields::fn_get_client_key_share"
        //     || self.fn_container.shape.name == "tlspuffin::tls::fn_impl::fn_fields::fn_get_any_client_curve"
        //     || self.fn_container.shape.name == "tlspuffin::tls::fn_impl::fn_utils::fn_get_ticket"
        //     || self.fn_container.shape.name == "tlspuffin::tls::fn_impl::fn_utils::fn_get_ticket_age_add"
        //     || self.fn_container.shape.name == "tlspuffin::tls::fn_impl::fn_utils::fn_get_ticket_nonce"
        //     || self.fn_container.shape.name == "tlspuffin::tls::fn_impl::fn_cert::fn_get_context"

        let mut successfully_built_functions_names = successfully_built_functions
            .iter()
            .map(|s| s.to_owned())
            .collect::<HashSet<String>>();

        let ignored_functions = [
            // Those 4 are the function symbols for which we fail to generator a term!
            fn_server_finished_transcript.name(),
            fn_client_finished_transcript.name(),
            fn_server_hello_transcript.name(),
            fn_certificate_transcript.name(),
            // Those 4 are the function symbols for which we can generate a term but all fail to lazy execute!
            fn_ecdsa_sign_server.name(),
            fn_ecdsa_sign_client.name(),
            fn_decrypt_handshake.name(),
            fn_decrypt_application.name(), // All other terms can also be encoded (no additional exception for full eval :) !)
            // Additional failures: we need to be able to decrypt some server's message, very complicated in practice
            fn_find_server_certificate_verify.name(),
            fn_decrypt_multiple_handshake_messages.name(),
            fn_find_encrypted_extensions.name(),
            fn_find_server_certificate.name(),
            fn_find_server_finished.name(),
        ]
        .iter()
        .map(|fn_name| fn_name.to_string())
        .collect::<HashSet<String>>();

        successfully_built_functions_names.extend(ignored_functions);

        let all_functions = TLS_SIGNATURE
            .functions
            .iter()
            .map(|(shape, _)| shape.name.to_string())
            .collect::<HashSet<String>>();
        let difference = all_functions.difference(&successfully_built_functions_names);

        error!("Diff: {:?}\n", &difference);
        debug!(
            "Successfully built: #{:?}",
            &successfully_built_functions.len()
        );
        debug!("All functions: #{:?}", &all_functions.len());
        error!("number_shapes: {}, number_terms: {}, eval_count: {}, count_payload_fail: {count_payload_fail}, count_lazy_fail: {count_lazy_fail}, count_any_encode_fail: {count_any_encode_fail}\n", number_shapes, number_terms, eval_count);
        assert_eq!(difference.count(), 0);
        assert_eq!(count_any_encode_fail, 0);
    }
}

/*
## term_eval_lazy
### for number = 1 --> 42 failing
  ["tlspuffin::tls::fn_impl::fn_utils::fn_decrypt_application", "tlspuffin::tls::fn_impl::fn_messages::fn_server_key_exchange", "tlspuffin::tls::fn_impl::fn_extensions::fn_key_share_server_extension", "tlspuffin::tls::fn_impl::fn_fields::fn_get_client_key_share", "tlspuffin::tls::fn_impl::fn_extensions::fn_renegotiation_info_extension", "tlspuffin::tls::fn_impl::fn_messages::fn_finished", "tlspuffin::tls::fn_impl::fn_fields::fn_get_server_key_share", "tlspuffin::tls::fn_impl::fn_messages::fn_heartbeat_fake_length", "tlspuffin::tls::fn_impl::fn_utils::fn_encrypt_handshake", "tlspuffin::tls::fn_impl::fn_extensions::fn_key_share_hello_retry_extension", "tlspuffin::tls::fn_impl::fn_extensions::fn_transport_parameters_extension", "tlspuffin::tls::fn_impl::fn_extensions::fn_key_share_deterministic_server_extension", "tlspuffin::tls::fn_impl::fn_fields::fn_verify_data", "tlspuffin::tls::fn_impl::fn_utils::fn_encrypt_application", "tlspuffin::tls::fn_impl::fn_utils::fn_get_ticket", "tlspuffin::tls::fn_impl::fn_cert::fn_rsa_sign_client", "tlspuffin::tls::fn_impl::fn_utils::fn_encrypt12", "tlspuffin::tls::fn_impl::fn_extensions::fn_support_group_extension", "tlspuffin::tls::fn_impl::fn_cert::fn_rsa_sign_server", "tlspuffin::tls::fn_impl::fn_extensions::fn_preshared_keys_extension_empty_binder", "tlspuffin::tls::fn_impl::fn_utils::fn_decrypt_handshake", "tlspuffin::tls::fn_impl::fn_cert::fn_ecdsa_sign_client", "tlspuffin::tls::fn_impl::fn_fields::fn_get_any_client_curve", "tlspuffin::tls::fn_impl::fn_messages::fn_client_key_exchange", "tlspuffin::tls::fn_impl::fn_utils::fn_derive_psk", "tlspuffin::tls::fn_impl::fn_utils::fn_derive_binder", "tlspuffin::tls::fn_impl::fn_extensions::fn_transport_parameters_server_extension", "tlspuffin::tls::fn_impl::fn_cert::fn_ecdsa_sign_server", "tlspuffin::tls::fn_impl::fn_extensions::fn_transport_parameters_draft_extension", "tlspuffin::tls::fn_impl::fn_fields::fn_sign_transcript", "tlspuffin::tls::fn_impl::fn_cert::fn_certificate_entry", "tlspuffin::tls::fn_impl::fn_utils::fn_fill_binder", "tlspuffin::tls::fn_impl::fn_fields::fn_verify_data_server", "tlspuffin::tls::fn_impl::fn_utils::fn_new_pubkey12", "tlspuffin::tls::fn_impl::fn_messages::fn_application_data", "tlspuffin::tls::fn_impl::fn_cert::fn_get_context", "tlspuffin::tls::fn_impl::fn_messages::fn_certificate_request13", "tlspuffin::tls::fn_impl::fn_extensions::fn_server_extensions_append", "tlspuffin::tls::fn_impl::fn_extensions::fn_append_vec", "tlspuffin::tls::fn_impl::fn_utils::fn_get_ticket_nonce", "tlspuffin::tls::fn_impl::fn_utils::fn_append_transcript", "tlspuffin::tls::fn_impl::fn_utils::fn_get_ticket_age_add"]
### for number = 10 --> 16 failing
  ["tlspuffin::tls::fn_impl::fn_utils::fn_fill_binder", "tlspuffin::tls::fn_impl::fn_utils::fn_get_ticket_age_add", "tlspuffin::tls::fn_impl::fn_utils::fn_get_ticket_nonce", "tlspuffin::tls::fn_impl::fn_fields::fn_sign_transcript", "tlspuffin::tls::fn_impl::fn_utils::fn_encrypt_handshake", "tlspuffin::tls::fn_impl::fn_fields::fn_get_any_client_curve", "tlspuffin::tls::fn_impl::fn_utils::fn_encrypt_application", "tlspuffin::tls::fn_impl::fn_cert::fn_get_context", "tlspuffin::tls::fn_impl::fn_fields::fn_verify_data", "tlspuffin::tls::fn_impl::fn_utils::fn_decrypt_handshake", "tlspuffin::tls::fn_impl::fn_cert::fn_ecdsa_sign_client", "tlspuffin::tls::fn_impl::fn_utils::fn_decrypt_application", "tlspuffin::tls::fn_impl::fn_utils::fn_get_ticket", "tlspuffin::tls::fn_impl::fn_utils::fn_encrypt12", "tlspuffin::tls::fn_impl::fn_cert::fn_ecdsa_sign_server", "tlspuffin::tls::fn_impl::fn_cert::fn_rsa_sign_server"]
### for number = 100 --> 6 failing
  ["tlspuffin::tls::fn_impl::fn_fields::fn_get_client_key_share",
 "tlspuffin::tls::fn_impl::fn_cert::fn_ecdsa_sign_client",
 "tlspuffin::tls::fn_impl::fn_utils::fn_decrypt_handshake",
 "tlspuffin::tls::fn_impl::fn_cert::fn_ecdsa_sign_server",
 "tlspuffin::tls::fn_impl::fn_utils::fn_decrypt_application",
 "tlspuffin::tls::fn_impl::fn_extensions::fn_preshared_keys_extension_empty_binder"]
 ### For number = 200 --> 4 failing (same for 10 000)
                fn_ecdsa_sign_server.name(),
            fn_ecdsa_sign_client.name(),
            fn_decrypt_handshake.name(),
            fn_decrypt_application.name()

Hard to generate: Diff:
    ["tlspuffin::tls::fn_impl::fn_utils::fn_derive_psk",
    "tlspuffin::tls::fn_impl::fn_utils::fn_get_ticket_age_add"]


## term_eval
### For number = 200 --> all success :) :)
Successfully built: #60563
All functions: #190
number_terms: 74800, eval_count: 60563, count_lazy_fail: 14237, count_any_encode_fail: 0

### For number = 400 --> all success
Successfully built: #30258
All functions: #190
number_terms: 37400, eval_count: 30258, count_lazy_fail: 7142, count_any_encode_fail: 0

 */
