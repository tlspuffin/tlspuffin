use puffin::algebra::TermType;

/// Test the function symbols that can be generated, evaluated, encoded
#[allow(clippy::ptr_arg)]
#[cfg(test)]
mod tests {
    use std::any::{Any, TypeId};
    use std::cmp::max;
    use std::collections::HashSet;
    use std::fmt::Debug;

    use hex::encode;
    use itertools::Itertools;
    use log::{debug, error, warn};
    use puffin::agent::AgentName;
    use puffin::algebra::dynamic_function::DescribableFunction;
    use puffin::algebra::error::FnError;
    use puffin::algebra::signature::FunctionDefinition;
    use puffin::algebra::{evaluate_lazy_test, ConcreteMessage, DYTerm, Matcher, Term, TermType};
    use puffin::codec;
    use puffin::codec::{Codec, Encode};
    use puffin::error::Error;
    use puffin::fuzzer::term_zoo::TermZoo;
    use puffin::fuzzer::utils::{choose, find_term_by_term_path_mut, Choosable, TermConstraints};
    use puffin::libafl_bolts::rands::{Rand, StdRand};
    use puffin::protocol::ProtocolBehavior;
    use puffin::trace::Action::Input;
    use puffin::trace::{InputAction, Step, Trace, TraceContext};

    use crate::protocol::TLSProtocolBehavior;
    use crate::put_registry::tls_registry;
    use crate::query::TlsQueryMatcher;
    use crate::tls::fn_impl::*;
    use crate::tls::rustls::hash_hs::HandshakeHash;
    use crate::tls::rustls::key::{Certificate, PrivateKey};
    use crate::tls::rustls::msgs::alert::AlertMessagePayload;
    use crate::tls::rustls::msgs::enums::{
        CipherSuite, Compression, ExtensionType, HandshakeType, NamedGroup, ProtocolVersion,
        SignatureScheme,
    };
    use crate::tls::rustls::msgs::handshake::{
        CertificateEntry, ClientExtension, HasServerExtensions, Random, ServerExtension, SessionID,
    };
    use crate::tls::rustls::msgs::message::{Message, MessagePayload, OpaqueMessage};
    use crate::tls::trace_helper::TraceHelper;
    use crate::tls::TLS_SIGNATURE;
    use crate::try_downcast;

    pub fn ignore_gen() -> HashSet<String> {
        [
            // As expected, attacker cannot use them as there is no adversarial
            // 'Transcript*Finished'
            fn_server_finished_transcript.name(),
            fn_client_finished_transcript.name(),
            fn_server_hello_transcript.name(),
            fn_certificate_transcript.name(),
            // OLD STUFF, NOT NEEDED:
            //  fn_decrypt_application.name(), // FIXME: why ignore this?
            //  fn_rsa_sign_client.name(), // FIXME: We are currently excluding this, because an
            // attacker does not have access to the private key of alice, eve or bob.
            //  fn_rsa_sign_server.name(),
            // // transcript functions -> ClaimList is usually available as Variable
        ]
        .iter()
        .map(|fn_name| fn_name.to_string())
        .collect::<HashSet<String>>()
    }

    pub fn ignore_payloads() -> HashSet<String> {
        let mut ignore_gen = ignore_gen();
        let ignore_payloads = [
            // Those 2 are the function symbols for which we can generate a term but all fail to
            // lazy execute! Indeed, the HandshakeHash that must be given must be
            // computed in a very specific way! We might give known,valid hash-transcript to help?
            // fn_decrypt_handshake_flight.name(),
            fn_decrypt_application.name(),
            fn_decrypt_multiple_handshake_messages.name(),
        ]
        .iter()
        .map(|fn_name| fn_name.to_string())
        .collect::<HashSet<String>>();
        ignore_gen.extend(ignore_payloads);
        ignore_gen
    }

    pub fn ignore_lazy_eval() -> HashSet<String> {
        let mut ignore_gen = ignore_payloads();
        let ignore_lazy = [
            // Those 2 are the function symbols for which we can generate a term but all fail to
            // lazy execute! Indeed, the HandshakeHash that must be given must be
            // computed in a very specific way! We might give known,valid hash-transcript to help?
            // fn_decrypt_handshake_flight.name(),
            // Additional failures: we need to be able to decrypt some server's message, very
            // complicated in practice
            fn_find_server_certificate_verify.name(),
            fn_find_server_certificate_verify.name(),
            // fn_find_encrypted_extensions.name(),
            // fn_find_server_certificate.name(),
            fn_find_server_finished.name(),
            // fn_find_server_ticket.name(),              // new for boring
            // fn_find_server_certificate_request.name(), // new for boring
        ]
        .iter()
        .map(|fn_name| fn_name.to_string())
        .collect::<HashSet<String>>();
        ignore_gen.extend(ignore_lazy);
        ignore_gen
    }

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
        let ignored_functions = ignore_gen();

        let successfully_built_functions_0 = successfully_built_functions.clone();
        successfully_built_functions.extend(ignored_functions.clone());

        let difference = all_functions.difference(&successfully_built_functions);
        debug!("Diff: {:?}\n", &difference);
        let difference_inverse = successfully_built_functions_0.intersection(&ignored_functions);
        debug!("Intersec with ignored: {:?}\n", &difference_inverse);
        // debug!("Successfully built: {:?}\n", &successfully_built_functions);
        debug!(
            "Successfully built: #{:?}",
            &successfully_built_functions.len()
        );
        debug!("All functions: #{:?}", &all_functions.len());
        assert_eq!(difference.count(), 0);
        assert_eq!(difference_inverse.count(), 0);
        // TESTED OK WITH generate_many CALLED WITH HOW_MANY = 400, mo more functions found with
        // MAX_DEPTH=2000 and MAX_TRIES = 50000 debug!("{}", graph);
    }

    #[test]
    #[test_log::test]
    fn test_term_lazy_eval() {
        let tls_registry = tls_registry();
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

        let mut ctx = TraceContext::new(&tls_registry, Default::default());
        let mut successfully_built_functions = zoo
            .terms()
            .iter()
            .filter(|t| evaluate_lazy_test(t, &ctx).is_ok())
            .map(|term| term.name().to_string())
            .collect::<HashSet<String>>();

        let ignored_functions = ignore_lazy_eval();

        let successfully_built_functions_0 = successfully_built_functions.clone();
        successfully_built_functions.extend(ignored_functions.clone());

        let difference = all_functions.difference(&successfully_built_functions);
        debug!("Diff: {:?}\n", &difference);
        let difference_inverse = successfully_built_functions_0.intersection(&ignored_functions);
        debug!("Intersec with ignored: {:?}\n", &difference_inverse);

        debug!(
            "Successfully built: #{:?}",
            &successfully_built_functions.len()
        );
        debug!("All functions: #{:?}", &all_functions.len());
        assert_eq!(difference.count(), 0);
        assert_eq!(difference_inverse.count(), 0);
        // TESTED OK WITH generate_many CALLED WITH HOW_MANY = 200, mo more functions found with
        // how_many = 10 000 debug!("{}", graph);
    }

    #[test]
    #[test_log::test]
    /// Tests whether all function symbols can be used when generating random terms and then be
    /// correctly evaluated
    fn test_term_eval() {
        let tls_registry = tls_registry();
        let mut rand = StdRand::with_seed(101);
        let zoo = TermZoo::<TlsQueryMatcher>::generate_many(&TLS_SIGNATURE, &mut rand, 400, None);
        let terms = zoo.terms();
        let number_terms = terms.len();
        let mut ctx = TraceContext::new(&tls_registry, Default::default());
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
            // || term.name().to_string()
            //     == "tlspuffin::tls::fn_impl::fn_utils::fn_get_ticket_nonce"
            {
                match term.evaluate(&ctx) {
                    Ok(eval) => {
                        debug!("OKAY for {}", term.name().to_string().to_owned());
                        successfully_built_functions.push(term.name().to_string().to_owned());
                        eval_count += 1;

                        // debug!(
                        //     " [x] Succeed evaluation of term: {} \nresulting in {:?}\n",
                        //     term, eval
                        // );
                    }
                    Err(e) => {
                        debug!(
                            "Error for {}, so we're trying lazy eval!!",
                            term.name().to_string().to_owned()
                        );
                        let t1 = evaluate_lazy_test(&term, &ctx);
                        if t1.is_err() {
                            debug!("LAZY failed!");
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

        let mut successfully_built_functions = successfully_built_functions
            .iter()
            .map(|s| s.to_owned())
            .collect::<HashSet<String>>();

        let ignored_functions = ignore_lazy_eval();

        let successfully_built_functions_0 = successfully_built_functions.clone();
        successfully_built_functions.extend(ignored_functions.clone());

        let difference = all_functions.difference(&successfully_built_functions);
        debug!("Diff: {:?}\n", &difference);
        let difference_inverse = successfully_built_functions_0.intersection(&ignored_functions);
        debug!("Intersec with ignored: {:?}\n", &difference_inverse);
        debug!(
            "Successfully built: #{:?}",
            &successfully_built_functions.len()
        );
        debug!("All functions: #{:?}", &all_functions.len());
        debug!("number_terms: {}, eval_count: {}, count_lazy_fail: {count_lazy_fail}, count_any_encode_fail: {count_any_encode_fail}\n", number_terms, eval_count);
        assert_eq!(difference.count(), 0);
        assert_eq!(difference_inverse.count(), 0);
        assert_eq!(count_any_encode_fail, 0);
    }

    fn add_one_payload_randomly<M: Matcher, R: Rand, PB: ProtocolBehavior<Matcher = M>>(
        t: &mut Term<M>,
        rand: &mut R,
        ctx: &TraceContext<PB>,
    ) -> Result<(), Error> {
        let trace = Trace {
            descriptors: vec![],
            steps: vec![Step {
                agent: AgentName::new(),
                action: Input(InputAction { recipe: t.clone() }),
            }],
            prior_traces: vec![],
        };
        if let Some((st_, (step, mut path))) = choose(
            &trace,
            TermConstraints {
                // as for Make_message.mutate
                no_payload_in_subterm: false,
                not_inside_list: false, // should be true, TODO: fix this
                weighted_depth: false,  // should be true, TODO: fix this
                ..TermConstraints::default()
            },
            rand,
            // Tests by varying TermConstraints (diff=2 corresponds to fn_derive_psk.name(),
            // fn_get_ticket.name()) Before   not_inside_list: true,
            // no_payload_in_subterm: true,     weighted_depth: true, : number_shapes:
            // 201, number_terms: 78800, eval_count: 182, count_payload_fail: 53, count_lazy_fail:
            // 3668, count_any_encode_fail: 0 DIF=5

            // Default (all false): number_shapes: 201, number_terms: 78800, eval_count: 185,
            // count_payload_fail: 22, count_lazy_fail: 3839, count_any_encode_fail: 0
            // Dif=2
            //
            // MAke_message: true, false, true
            //  number_shapes: 201, number_terms: 78800, eval_count: 181, count_payload_fail: 34,
            // count_lazy_fail: 3957, count_any_encode_fail: 0 Diff = 6

            // MAke_message + inside: false, false, true
            // number_shapes: 201, number_terms: 78800, eval_count: 183, count_payload_fail: 23,
            // count_lazy_fail: 3260, count_any_encode_fail: 0 Diff = 4

            // weighted_Depth = false
            // number_shapes: 201, number_terms: 78800, eval_count: 184, count_payload_fail: 31,
            // count_lazy_fail: 4018, count_any_encode_fail: 0 Diff = 3
        ) {
            let st = find_term_by_term_path_mut(t, &mut path).unwrap();
            if let Ok(()) = st.make_payload(&ctx) {
                debug!("Added payload for subterm at path {path:?}, step{step},\n - sub_term: {st_}\n  - whole_term {trace}\n  - evaluated={:?}, ", st.payloads.as_ref().unwrap().payload_0);
                if let Some(payloads) = &mut st.payloads {
                    let mut a: Vec<u8> = payloads.payload.clone().into();
                    a.push(2); // TODO: make something random here! (I suggest mutate with bit-level mutations)
                    a.push(2);
                    a.push(2);
                    a[0] = 2;
                    payloads.payload = a.into();
                    debug!("Added a payload at path {path:?}.");
                    Ok(())
                } else {
                    panic!("Should never happen")
                }
            } else {
                Err(Error::Term(
                    "[add_one_payload_randomly] Unable to make_message".to_string(),
                ))
            }
        } else {
            Err(Error::Term(
                "[add_one_payload_randomly] Unable to choose a suitable sub-term".to_string(),
            ))
        }
    }

    fn add_payloads_randomly<M: Matcher, R: Rand, PB: ProtocolBehavior<Matcher = M>>(
        t: &mut Term<M>,
        rand: &mut R,
        ctx: &TraceContext<PB>,
    ) {
        let all_subterms: Vec<&Term<M>> = t.into_iter().collect_vec();
        let nb_subterms = all_subterms.len() as i32;
        let mut i = 0;
        let nb = (1..max(4, nb_subterms / 3))
            .collect::<Vec<i32>>()
            .choose(rand)
            .unwrap()
            .to_owned();
        debug!(
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
            if let Ok(()) = add_one_payload_randomly(t, rand, ctx) {
                i += 1;
            }
        }
    }

    /// Sanity check for the next test
    pub fn test_pay<M: Matcher>(term: &Term<M>) {
        rec_inside(term, false, term);
        pub fn rec_inside<M: Matcher>(term: &Term<M>, already_found: bool, whole_term: &Term<M>) {
            let already_found = already_found || !term.is_symbolic();
            match &term.term {
                DYTerm::Variable(_) => {}
                DYTerm::Application(_, sub) => {
                    for ti in sub {
                        if already_found && !ti.is_symbolic() {
                            panic!("Eheh, found one! Sub: {ti},\n whole_term: {whole_term}")
                        } else {
                            rec_inside(ti, already_found, whole_term)
                        }
                    }
                }
            }
        }
    }

    #[cfg(all(feature = "tls13", feature = "deterministic"))] // require version which supports TLS 1.3
    #[test]
    // #[test_log::test]
    // #[ignore]
    /// Tests whether all function symbols can be used when generating random terms and then be
    /// correctly evaluated
    fn test_term_payloads_eval() {
        let tls_registry = tls_registry();
        let mut rand = StdRand::with_seed(101);
        let all_functions_shape = TLS_SIGNATURE.functions.to_owned();
        let mut ctx = TraceContext::new(&tls_registry, Default::default());
        let mut eval_count = 0;
        let mut count_lazy_fail = 0;
        let mut count_payload_fail = 0;
        let mut count_any_encode_fail = 0;
        let mut number_terms = 0;
        let number_shapes = all_functions_shape.len();
        let mut successfully_built_functions = vec![];

        for f in all_functions_shape {
            let zoo = TermZoo::<TlsQueryMatcher>::generate_many(
                &TLS_SIGNATURE,
                &mut rand,
                2000,
                Some(&f),
            );
            let terms = zoo.terms();
            number_terms = number_terms + terms.len();

            for term in terms.iter() {
                if successfully_built_functions.contains(&term.name().to_string()) {
                    // for speeding up things
                    continue;
                }
                // FILTER
                // if !(term.name().to_string().to_owned() ==
                // "tlspuffin::tls::fn_impl::fn_utils::fn_encrypt_handshake") {
                //     continue;
                // }

                if let Err(_) = term.evaluate(&ctx) {
                    // not a candidate for adding a payload as it is already not executable
                    continue;
                }

                let mut term_with_payloads = term.clone();

                add_payloads_randomly(&mut term_with_payloads, &mut rand, &ctx);

                if term_with_payloads.all_payloads().len() == 0 {
                    warn!("Failed to add payloads, skipping... For:\n   {term_with_payloads}");
                    continue;
                }

                debug!("Term with payloads: {term_with_payloads}");

                // Sanity check:
                test_pay(&term_with_payloads);

                match &term_with_payloads.evaluate(&ctx) {
                    Ok(eval) => {
                        debug!("Eval success!");
                        successfully_built_functions.push(term.name().to_string().to_owned());
                        eval_count += 1;
                    }
                    Err(e) => {
                        error!("Eval FAILED with payloads.");
                        match &term_with_payloads.clone().evaluate_symbolic(&ctx) {
                            Ok(_) => {
                                error!("Eval FAILED with payloads but succeeded without payloads!");
                                count_payload_fail += 1;
                                error!(
                                    "[Payload] Failed evaluation due to PAYLOADS. Term:\n{}",
                                    term_with_payloads
                                );
                            }
                            Err(_) => {
                                let t1 = evaluate_lazy_test(&term_with_payloads, &ctx);
                                if t1.is_err() {
                                    warn!("LAZY failed!");
                                    count_lazy_fail += 1;
                                } else {
                                    count_any_encode_fail += 1;
                                    match e.clone() { // for debugging encoding failure only
                                        Error::Fn(FnError::Unknown(ee)) =>
                                            error!("[Unknown] Failed evaluation due to FnError::Unknown: [{}]", e),
                                        Error::Fn(FnError::Crypto(ee)) =>
                                            error!("[Crypto] Failed evaluation due to FnError::Crypto:[{}]\nTerm: {}", e, term_with_payloads),
                                        Error::Fn(FnError::Malformed(ee)) =>
                                            error!("[Malformed] Failed evaluation due to FnError::Crypto:[{}]", e),
                                        Error::Term(ee) => {
                                            error!("[Term] Failed evaluation due to Error:Term: [{}]\n ===For Term: [{}]", e, term_with_payloads)
                                        },
                                        _ => {
                                            // _ => {
                                            error!("===========================\n\n\n [OTHER] Failed evaluation of term: {} \n with error {}. Trying to downcast manually:", term_with_payloads, e);
                                            let t1 = evaluate_lazy_test(&term_with_payloads, &ctx);
                                            if t1.is_ok() {
                                                debug!("Evaluate_lazy success. ");
                                                match t1.expect("NO").downcast_ref::<bool>() {
                                                    Some(downcast) => {
                                                        print!("Downcast succeeded: {downcast:?}. ");
                                                        // let bitstring = Encode::get_encoding(downcast);
                                                        // print!("Encoding succeeded:: {bitstring:?}. ");
                                                    },
                                                    _ => { error!("Downcast FAILED. ") },
                                                }
                                            } else {
                                                error!("Evaluate_lazy FAILED. ");
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
        // DONE
        // Understand warning and errors, try also without limiting to once a function
        // Issues to address:
        //       A. cycling between:  [FIXED WITH tried_depth_path]
        //          1.window_depth +1 when !st.unique_match
        //          2. window depth -1 when !st.unique_window
        //       B. Related and example of A:  [FIXED WITH fallback_end_parent]
        //           always fails when BS// is in a term t such that just before or after is a
        // similar t with same encoding           there won't be a suitable window then!
        //           Also always fail when the payload is at pos p and a sibling encoding contains
        // the same encoding [ALSO FIXED]       C.  Read_bytes fail because of MakeMessage
        // but even without adding a != payload for: HandshakeHash, Vec<ClientExtension>,
        // Vec<ServerExtension>           Could add a test that encode and read many
        // different types, as in this test FIXED       E. Other failures when running this
        // with DEBUG level=warn  MOST OF THEM FIXED TODO: run fuzzing campaign, measure
        // failure rates, measure efficiency (execs/s)
        let all_functions = TLS_SIGNATURE
            .functions
            .iter()
            .map(|(shape, _)| shape.name.to_string())
            .collect::<HashSet<String>>();

        let mut successfully_built_functions = successfully_built_functions
            .iter()
            .map(|s| s.to_owned())
            .collect::<HashSet<String>>();

        let ignored_functions = ignore_payloads();

        let successfully_built_functions_0 = successfully_built_functions.clone();
        successfully_built_functions.extend(ignored_functions.clone());

        let difference = all_functions.difference(&successfully_built_functions);
        let difference_inverse = successfully_built_functions_0.intersection(&ignored_functions);
        error!(
            "Successfully built: #{:?}",
            &successfully_built_functions.len()
        );
        error!("All functions: #{:?}", &all_functions.len());
        error!("number_shapes: {}, number_terms: {}, eval_count: {}, count_payload_fail: {count_payload_fail}, count_lazy_fail: {count_lazy_fail}, count_any_encode_fail: {count_any_encode_fail}\n", number_shapes, number_terms, eval_count);
        error!("Diff: {:?}\n", &difference);
        error!("Intersec with ignored: {:?}\n", &difference_inverse);
        assert_eq!(difference.count(), 0);
        assert_eq!(difference_inverse.count(), 0);
        assert_eq!(count_any_encode_fail, 0);
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

    #[cfg(all(feature = "tls13", feature = "deterministic"))] // require version which supports TLS 1.3
    #[test]
    // #[test_log::test]
    // #[ignore]
    /// Tests whether all function symbols can be used when generating random terms and then be
    /// correctly evaluated
    fn test_term_read_encode() {
        let tls_registry = tls_registry();
        let mut rand = StdRand::with_seed(101);
        let all_functions_shape = TLS_SIGNATURE.functions.to_owned();
        let mut ctx = TraceContext::new(&tls_registry, Default::default());
        let mut eval_count = 0;
        let mut count_lazy_fail = 0;
        let mut read_count = 0;
        let mut read_wrong = 0;
        let mut read_fail = 0;
        let mut read_success = 0;
        let mut count_any_encode_fail = 0;
        let mut number_terms = 0;
        let number_shapes = all_functions_shape.len();
        let mut successfully_built_functions = vec![];

        for f in all_functions_shape {
            let zoo = TermZoo::<TlsQueryMatcher>::generate_many(
                &TLS_SIGNATURE,
                &mut rand,
                1000,
                Some(&f),
            );
            let terms = zoo.terms();
            number_terms = number_terms + terms.len();

            for term in terms.iter() {
                if successfully_built_functions.contains(&term.name().to_string()) {
                    // for speeding up things
                    continue;
                }
                match &term.evaluate(&ctx) {
                    Ok(eval) => {
                        debug!("Eval success!");
                        eval_count += 1;
                        let type_id: TypeId = (*term.get_type_shape()).into();
                        match TLSProtocolBehavior::try_read_bytes(eval, type_id) {
                            Ok(message_back) => {
                                debug!("Read success!");
                                read_count += 1;
                                match TLSProtocolBehavior::any_get_encoding(&message_back) {
                                    Ok(eval2) => {
                                        if eval2 == *eval {
                                            debug!("Consistent for term {term}");
                                            successfully_built_functions
                                                .push(term.name().to_string().to_owned());
                                            read_success += 1;
                                        } else {
                                            error!("[FAIL] Not the same read for term {}!\n  -Encoding1: {:?}\n  -Encoding2: {:?}\n  - TypeShape:{}, TypeId: {:?}", term, eval, eval2, term.get_type_shape(), type_id);
                                            read_wrong += 1;
                                        }
                                    }
                                    Err(e) => {
                                        error!("[FAIL] Failed to re-encode read term {}!\n  -Encoding1: {:?}\n Read message {:?}\n  - TypeShape:{}, TypeId: {:?}", term, eval, message_back, term.get_type_shape(), type_id);
                                        error!("Error: {}", e);
                                        read_wrong += 1;
                                    }
                                }
                            }
                            Err(e) => {
                                error!("[FAIL] Failed to read for term {}!\n  and encoding: {:?}\n  - TypeShape:{}, TypeId: {:?}", term, eval, term.get_type_shape(), type_id);
                                error!("Error: {}", e);
                                read_fail += 1;
                            }
                        }
                    }
                    Err(e) => {
                        let t1 = evaluate_lazy_test(&term, &ctx);
                        if t1.is_err() {
                            warn!("LAZY failed!");
                            count_lazy_fail += 1;
                        } else {
                            count_any_encode_fail += 1;
                            match e.clone() { // for debugging encoding failure only
                                Error::Fn(FnError::Unknown(ee)) =>
                                    error!("[Unknown] Failed evaluation due to FnError::Unknown: [{}]", e),
                                Error::Fn(FnError::Crypto(ee)) =>
                                    error!("[Crypto] Failed evaluation due to FnError::Crypto:[{}]\nTerm: {}", e, term),
                                Error::Fn(FnError::Malformed(ee)) =>
                                    error!("[Malformed] Failed evaluation due to FnError::Crypto:[{}]", e),
                                Error::Term(ee) => {
                                    error!("[Term] Failed evaluation due to Error:Term: [{}]\n ===For Term: [{}]", e, term)
                                },
                                _ => {
                                    // _ => {
                                    error!("===========================\n\n\n [OTHER] Failed evaluation of term: {} \n with error {}. Trying to downcast manually:", term, e);
                                    let t1 = evaluate_lazy_test(&term, &ctx);
                                    if t1.is_ok() {
                                        debug!("Evaluate_lazy success. ");
                                        match t1.expect("NO").downcast_ref::<bool>() {
                                            Some(downcast) => {
                                                print!("Downcast succeeded: {downcast:?}. ");
                                                // let bitstring = Encode::get_encoding(downcast);
                                                // print!("Encoding succeeded:: {bitstring:?}. ");
                                            },
                                            _ => { error!("Downcast FAILED. ") },
                                        }
                                    } else {
                                        error!("Evaluate_lazy FAILED. ");
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

        let mut successfully_built_functions = successfully_built_functions
            .iter()
            .map(|s| s.to_owned())
            .collect::<HashSet<String>>();

        let ignored_functions = ignore_payloads();

        let successfully_built_functions_0 = successfully_built_functions.clone();
        successfully_built_functions.extend(ignored_functions.clone());

        let difference = all_functions.difference(&successfully_built_functions);
        let difference_inverse = successfully_built_functions_0.intersection(&ignored_functions);

        debug!(
            "Successfully built: #{:?}",
            &successfully_built_functions.len()
        );
        debug!("All functions: #{:?}", &all_functions.len());
        error!("number_shapes: {}, number_terms: {}, eval_count: {}, count_lazy_fail: {count_lazy_fail}, count_any_encode_fail: {count_any_encode_fail}\n", number_shapes, number_terms, eval_count);
        error!("Read stats: read_count: {read_count}, read_success: {read_success}, read_fail: {read_fail}, read_wrong: {read_wrong}");

        debug!("Diff: {:?}\n", &difference);
        debug!("Intersec with ignored: {:?}\n", &difference_inverse);
        assert_eq!(difference.count(), 0);
        assert_eq!(difference_inverse.count(), 0);
        assert_eq!(count_any_encode_fail, 0);
        // Excluding fn_heartbleed_fake_length:
        // Read stats: read_count: 163085, read_success: 162481, read_fail: 2963, read_wrong: 604
        // --> OKAY :) number_shapes: 213, number_terms: 209000, eval_count: 166048,
        // count_lazy_fail: 41952, count_any_encode_fail: 0 --> TODO: address some of those
    }
}
