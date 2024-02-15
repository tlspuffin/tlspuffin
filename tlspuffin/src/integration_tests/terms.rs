/// Test evaluations of terms.
#[allow(clippy::ptr_arg)]
#[cfg(test)]
mod tests {
    use itertools::Itertools;
    use log::{debug, error, warn};
    use std::any::Any;
    use std::cmp::max;
    use std::collections::HashSet;
    use std::fmt::Debug;

    use puffin::agent::AgentName;
    use puffin::algebra::error::FnError;
    use puffin::algebra::signature::FunctionDefinition;
    use puffin::algebra::{
        evaluate_lazy_test, replace_payloads, ConcreteMessage, Matcher, Payloads, TermEval,
        TermType,
    };
    use puffin::codec::Codec;
    use puffin::error::Error;
    use puffin::fuzzer::utils::{
        choose, find_term_by_term_path, find_term_by_term_path_mut, Choosable, TermConstraints,
    };
    use puffin::libafl::prelude::Rand;
    use puffin::protocol::{ProtocolBehavior, ProtocolMessage};
    use puffin::put::PutOptions;
    use puffin::trace::Action::Input;
    use puffin::trace::{Action, InputAction, OutputAction, Step, Trace, TraceContext};
    use puffin::{
        algebra::dynamic_function::DescribableFunction, codec, fuzzer::term_zoo::TermZoo,
        libafl::bolts::rands::StdRand,
    };

    use crate::protocol::TLSProtocolBehavior;
    use crate::tls::{
        fn_impl::*,
        rustls::msgs::{
            enums::{CipherSuite, Compression, HandshakeType, ProtocolVersion},
            handshake::{Random, ServerExtension, SessionID},
        },
        trace_helper::TraceHelper,
    };
    use crate::{
        query::TlsQueryMatcher,
        tls::{fn_impl::*, TLS_SIGNATURE},
        try_downcast,
    };

    use crate::put_registry::TLS_PUT_REGISTRY;
    use crate::tls::rustls::hash_hs::HandshakeHash;
    use crate::tls::rustls::key::{Certificate, PrivateKey};
    use crate::tls::rustls::msgs::alert::AlertMessagePayload;
    use crate::tls::rustls::msgs::enums::{ExtensionType, NamedGroup, SignatureScheme};
    use crate::tls::rustls::msgs::handshake::{
        CertificateEntry, ClientExtension, HasServerExtensions,
    };
    use crate::tls::rustls::msgs::message::{Message, MessagePayload, OpaqueMessage};
    use crate::tls::seeds::{create_corpus, seed_client_attacker_boring};

    fn test_one_replace(
        trace: &mut Trace<TlsQueryMatcher>,
        ctx: &TraceContext<TLSProtocolBehavior>,
        step_nb: usize,
        path: Vec<usize>,
        new_sub_vec: Vec<u8>,  // this will replace the payload at step_nb/path
        expected_vec: Vec<u8>, // expected bitstring for the whole recipe at step_nb
    ) {
        debug!("\n=========================\nReplacing step {step_nb} with path {path:?} and new vec: {new_sub_vec:?}.");
        if let Input(input) = &mut trace.steps[step_nb].action {
            let mut term = &mut input.recipe;
            let e_before = term.evaluate(&ctx).expect("OUPS1");
            debug!("Term: {term}\nTerm eval: {e_before:?}.");

            let mut sub = find_term_by_term_path_mut(&mut term, &mut path.clone()).expect("OUPS2");
            sub.erase_payloads_subterms(false);
            sub.make_payload(&ctx); // will remove payloads in strict sub-terms, as expected
            let sub_before = sub.clone();
            let e_sub_before = sub_before.evaluate_symbolic(&ctx).expect("OUPS3"); // evaluate_symbolic:
                                                                                   // mimicking term::make_payload ! We loose all previous mutations on sub-terms!
            debug!("Subterm before: {sub_before}\nSubterm eval_symbolic before: {e_sub_before:?}");
            if let Some(p) = &mut sub.payloads {
                p.payload = new_sub_vec.clone().into();
                debug!("Payload_0: {:?}", p.payload_0);
            } else {
                panic!("No payload after make_payload!");
            }
            // now that we added a different payload in term, we re-evaluate
            let e_after = term.evaluate(&ctx).expect("OUPS4");
            let sub_after = find_term_by_term_path(&term, &mut path.clone()).expect("OUPS5");
            let e_sub_after = sub_after.evaluate(&ctx).expect("OUPS6");
            debug!("Subterm eval after: {e_sub_after:?}");
            debug!("Eval before: {e_before:?}");
            debug!("Eval after: {e_after:?}");
            debug!("Assert eq for step {step_nb} with path {path:?}:");
            assert_eq!(e_after, expected_vec);
        }
    }

    // UNI TESTS for eval_until_opaque and replace_payloads
    // #[test_log::test] // Does not work as it makes Cargo runs tests twice, so tests are failing the second time! Could
    // be useful in RUST_LOG=DEBUG/TRACE mode to see all the replacements and wimdow refinement of `eval_until_opaque`
    // in detail.
    #[test]
    #[cfg(all(feature = "deterministic", feature = "boringssl-binding"))]
    fn test_replace_bitstring_multiple() {
        let mut ctx = TraceContext::new(&TLS_PUT_REGISTRY, PutOptions::default());
        let mut trace = seed_client_attacker_boring.build_trace();
        ctx.set_deterministic(true);
        trace.execute(&mut ctx);
        let step0_before = vec![
            22,
            3, 3, // path=0: fn_protocol_version12 -> ProtocolVersion,
            0, 211, 1, 0, 0, 207, 3, 3,  // Client Hello structure
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // path=1: fn_new_random -> Random,
            32, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, // path=2: fn_new_session_id -> SessionID,
            0, 2, 19, 1, // path=fn_append_cipher_suite(...)
            1, 0, // path= 4 fn_compressions -> Vec<Compression>,
            // path = 5 until the end
            0, 132,
            // path = 5,0,0,0,0  (empty) -> 44, 44, 0, 10, 0, 4, 0, 2, 0, 24, 44, 44
            0, 10, 0, 4, 0, 2, 0,
            24, // path = 5,0,0,0,1 -> 41, 41, 0, 40, 0, 4, 0, 2, 0, 24, 37, 37
            0, 13, 0, 6, 0, 4, 4, 1, 8, 4, 0, 51, 0, 103, 0, 101, 0, 24, 0, 97, 4, 83, 62, 229,
            191, 64, 236, 45, 103, 152, 139, 119, 243, 23, 72, 155, 182, 223, 149, 41, 37, 199, 9,
            252, 3, 129, 17, 26, 89, 86, 242, 215, 88, 17, 14, 89, 211, 215, 193, 114, 158, 44, 13,
            112, 234, 247, 115, 230, 18, 1, 22, 66, 109, 226, 67, 106, 47, 95, 221, 127, 229, 79,
            175, 149, 43, 4, 253, 19, 245, 22, 206, 98, 127, 137, 210, 1, 157, 76, 135, 150, 149,
            158, 67, 51, 199, 6, 91, 73, 108, 166, 52, 213, 220, 99, 189, 233, 31, 0, 43, 0, 3, 2,
            3, 4,
        ];
        // fn_client_hello(
        //     fn_protocol_version12 -> ProtocolVersion, // 0
        //     fn_new_random -> Random,                  // 1
        //     fn_new_session_id -> SessionID,           // 2
        //     fn_append_cipher_suite(                   // 3
        //         fn_new_cipher_suites -> Vec<CipherSuite>,
        //         fn_cipher_suite13_aes_128_gcm_sha256 -> CipherSuite
        //     ) -> Vec<CipherSuite>,
        //     fn_compressions -> Vec<Compression>,      // 4
        //     BS//fn_client_extensions_make( // 5: [0, 132, 0, 10, 0, 4, 0, 2, 0, 24, 0, 13, 0, 6, 0, 4, 4, 1, 8, 4, 0, 51, 0, 103, 0, 101, 0, 24, 0, 97, 4, 83, 62, 229, 191, 64, 236, 45, 103, 152, 139, 119, 243, 23, 72, 155, 182, 223, 149, 41, 37, 199, 9, 252, 3, 129, 17, 26, 89, 86, 242, 215, 88, 17, 14, 89, 211, 215, 193, 114, 158, 44, 13, 112, 234, 247, 115, 230, 18, 1, 22, 66, 109, 226, 67, 106, 47, 95, 221, 127, 229, 79, 175, 149, 43, 4, 253, 19, 245, 22, 206, 98, 127, 137, 210, 1, 157, 76, 135, 150, 149, 158, 67, 51, 199, 6, 91, 73, 108, 166, 52, 213, 220, 99, 189, 233, 31, 0, 43, 0, 3, 2, 3, 4])]
        //     fn_client_extensions_append(
        //         fn_client_extensions_append(
        //             fn_client_extensions_append(
        //                 fn_client_extensions_append(
        //                     fn_client_extensions_new -> Vec<ClientExtension>,
        //                     fn_support_group_extension(
        //                         fn_named_group_secp384r1 -> NamedGroup
        //                     ) -> ClientExtension
        //                 ) -> Vec<ClientExtension>,
        //                 fn_signature_algorithm_extension -> ClientExtension
        //             ) -> Vec<ClientExtension>,
        //             fn_key_share_deterministic_extension(
        //                 fn_named_group_secp384r1 -> NamedGroup
        //             ) -> ClientExtension
        //         ) -> Vec<ClientExtension>,
        //         fn_supported_versions13_extension -> ClientExtension
        //     ) -> Vec<ClientExtension>
        // ) -> ClientExtensions
        // ) -> Message


        // This one operates below encryption! (we are able to replace payload under encryption: fn_encrypt_handshake)
        let step_nb = 2;
        let path = vec![6];
        let new_vec = vec![0, 0, 4, 0, 0, 0, 0, 0];
        let expected_vec = vec![
            23, 3, 3, 0, 53, 251, 233, 101, 230, 35, 15, 65, 183, 119, 129, 97, 173, 184, 63, 178,
            106, 10, 216, 38, 93, 20, 100, 73, 54, 199, 204, 92, 177, 71, 49, 53, 150, 122, 106,
            221, 167, 19, 59, 240, 185, 191, 111, 202, 253, 48, 228, 38, 20, 212, 131, 114, 84, 63,
        ];
        test_one_replace(&mut trace, &ctx, step_nb, path, new_vec, expected_vec);

        // This one is tricky since it replaces an empty bitstring with an nonempty one, thus it requires to find it
        // using left or right brother
        let step_nb = 0;
        let path = vec![5, 0, 0, 0, 0,  0];
        let new_vec = vec![44, 44, 0, 10, 0, 4, 0, 2, 0, 24, 44, 44];
        let expected_vec = vec![
            22, 3, 3, 0, 211, 1, 0, 0, 207, 3, 3, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 32, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
            3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 0, 2, 19, 1, 1, 0, 0, 132,
            44, 44, 0, 10, 0, 4, 0, 2, 0, 24, 44,
            44, // was empty, adding this! (compare with `step0_before` above)
            0, 10, 0, 4, 0, 2, 0, 24, 0, 13, 0, 6, 0, 4, 4, 1, 8, 4, 0, 51, 0, 103, 0, 101, 0, 24,
            0, 97, 4, 83, 62, 229, 191, 64, 236, 45, 103, 152, 139, 119, 243, 23, 72, 155, 182,
            223, 149, 41, 37, 199, 9, 252, 3, 129, 17, 26, 89, 86, 242, 215, 88, 17, 14, 89, 211,
            215, 193, 114, 158, 44, 13, 112, 234, 247, 115, 230, 18, 1, 22, 66, 109, 226, 67, 106,
            47, 95, 221, 127, 229, 79, 175, 149, 43, 4, 253, 19, 245, 22, 206, 98, 127, 137, 210,
            1, 157, 76, 135, 150, 149, 158, 67, 51, 199, 6, 91, 73, 108, 166, 52, 213, 220, 99,
            189, 233, 31, 0, 43, 0, 3, 2, 3, 4,
        ];
        test_one_replace(&mut trace, &ctx, step_nb, path, new_vec, expected_vec);

        // Also tricky because the path 5,0,0,1 is located right after the previous location that was
        // an empty bitstring but is now, after replacement, a 12-bytes bitstring!
        // Tricky since the previse byte location to operate the replace is impacted (hence `shift` in `replace_payloads`).
        let step_nb = 0;
        let path = vec![5, 0, 0, 0, 0, 1];
        let new_vec = vec![41, 41, 0, 40, 0, 4, 0, 2, 0, 24, 37, 37];
        let expected_vec = vec![
            22, 3, 3, 0, 211, 1, 0, 0, 207, 3, 3, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 32, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
            3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 0, 2, 19, 1, 1, 0, 0, 132,
            44, 44, 0, 10, 0, 4, 0, 2, 0, 24, 44, 44, // from previous replacement
            41, 41, 0, 40, 0, 4, 0, 2, 0, 24, 37, 37, // replace
            0, 13, 0, 6, 0, 4, 4, 1, 8, 4, 0, 51, 0, 103, 0, 101, 0, 24, 0, 97, 4, 83, 62, 229,
            191, 64, 236, 45, 103, 152, 139, 119, 243, 23, 72, 155, 182, 223, 149, 41, 37, 199, 9,
            252, 3, 129, 17, 26, 89, 86, 242, 215, 88, 17, 14, 89, 211, 215, 193, 114, 158, 44, 13,
            112, 234, 247, 115, 230, 18, 1, 22, 66, 109, 226, 67, 106, 47, 95, 221, 127, 229, 79,
            175, 149, 43, 4, 253, 19, 245, 22, 206, 98, 127, 137, 210, 1, 157, 76, 135, 150, 149,
            158, 67, 51, 199, 6, 91, 73, 108, 166, 52, 213, 220, 99, 189, 233, 31, 0, 43, 0, 3, 2,
            3, 4,
        ];
        test_one_replace(&mut trace, &ctx, step_nb, path, new_vec, expected_vec);

        // This one drops all previous payloads below path 5!
        let step_nb = 0;
        let path = vec![5];
        let new_vec = vec![0, 132, 0, 10, 0, 4, 0, 2, 0, 24, 0];
        let expected_vec = vec![
            22, 3, 3, 0, 211, 1, 0, 0, 207, 3, 3, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 32, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
            3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 0, 2, 19, 1, 1, 0,
            0, 132, 0, 10, 0, 4, 0, 2, 0, 24, 0, // replace
        ];
        test_one_replace(&mut trace, &ctx, step_nb, path, new_vec, expected_vec);

        let step_nb = 0;
        let path = vec![3, 0, 1];
        let new_vec = vec![19, 1, 11];
        let expected_vec = vec![
            22, 3, 3, 0, 211, 1, 0, 0, 207, 3, 3, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 32, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
            3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 0, 2,
            19, 1, 11, // replace
            1, 0,
            0, 132, 0, 10, 0, 4, 0, 2, 0, 24, 0, // from previous replacement
        ];
        test_one_replace(&mut trace, &ctx, step_nb, path, new_vec, expected_vec);

        // Tricky as well, similar to what is required to process path [5, 0, 0, 0, 1] above
        let step_nb = 0;
        let path = vec![4];
        let new_vec = vec![33, 33, 33, 33];
        let expected_vec = vec![
            22, 3, 3, 0, 211, 1, 0, 0, 207, 3, 3, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 32, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
            3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 0, 2,
            19, 1, 11, // from previous replacement
            // 1, 0,
            33, 33, 33, 33, // replace
            0, 132, 0, 10, 0, 4, 0, 2, 0, 24, 0, // from previous replacement
        ];
        test_one_replace(&mut trace, &ctx, step_nb, path, new_vec, expected_vec);
    }

    // OLD STUFF! SHOULD BE REMOVED!?
    #[cfg(feature = "tls13")] // require version which supports TLS 1.3
                              // #[test]
    fn test_evaluate_recipe_input_compare_new() {
        use crate::tls::trace_helper::TraceExecutor;

        for (tr, name) in create_corpus() {
            debug!("\n\n============= Executing trace {name}");
            if name == "tlspuffin::tls::seeds::seed_client_attacker_auth" {
                // currently failing traces because of broken certs (?), even before my edits
                continue;
            }
            let mut ctx = TraceContext::new(&TLS_PUT_REGISTRY, PutOptions::default());
            ctx.set_deterministic(true);

            for trace in &tr.prior_traces {
                trace.spawn_agents(&mut ctx).expect("d");
                trace.execute(&mut ctx).expect("d");
                ctx.reset_agents().expect("d");
            }

            tr.spawn_agents(&mut ctx).unwrap();
            let steps = &tr.steps;
            for (i, step) in steps.iter().enumerate() {
                debug!("Executing step #{}", i);

                match &step.action {
                    Action::Input(input) => {
                        debug!("Running custom test for inputs...");
                        {
                            let evaluated_lazy = evaluate_lazy_test(&input.recipe, &ctx).expect("a");
                            if let Some(msg_old) = evaluated_lazy.as_ref().downcast_ref::<<TLSProtocolBehavior as ProtocolBehavior>::ProtocolMessage>() {
                                debug!("Term {}\n could be parsed as ProtocolMessage", input.recipe);
                                let evaluated = input.recipe.evaluate(&mut ctx).expect("a");
                                if let Some(msg) = <TLSProtocolBehavior as ProtocolBehavior>::OpaqueProtocolMessage::read_bytes(&evaluated) {
                                    debug!("=====> and was successfully handled with the new input evaluation routine! We now check they are equal...");
                                    assert_eq!(msg_old.create_opaque().get_encoding(), msg.get_encoding());
                                    ctx.add_to_inbound(step.agent, &msg).expect("");
                                } else {
                                    panic!("Should not happen")
                                }

                            } else if let Some(opaque_message_old) = evaluated_lazy
                                .as_ref()
                                .downcast_ref::<<TLSProtocolBehavior as ProtocolBehavior>::OpaqueProtocolMessage>()
                            {
                                debug!("Term {}\n could be parsed as OpaqueProtocolMessage", input.recipe);
                                let evaluated = input.recipe.evaluate(&mut ctx).expect("c");
                                if let Some(msg) = <TLSProtocolBehavior as ProtocolBehavior>::OpaqueProtocolMessage::read_bytes(&evaluated) {
                                    debug!("=====> and was successfully handled with the new input evaluation routine! We now check they are equal...");
                                    assert_eq!(opaque_message_old.get_encoding(), msg.get_encoding());
                                    ctx.add_to_inbound(step.agent, &msg).expect("");
                                } else {
                                    panic!("Should not happen")
                                }
                            } else {
                                panic!("Should not happen")
                            }

                            ctx.next_state(step.agent)
                        }.expect("TODO: panic message");

                        let output_step = &OutputAction::<TlsQueryMatcher>::new_step(step.agent);
                        output_step.action.execute(output_step, &mut ctx);
                    }
                    Action::Output(_) => {
                        step.action.execute(step, &mut ctx);
                    }
                }

                // ctx.claims.deref_borrow().log();

                // ctx.verify_security_violations();
            }
            assert!(ctx.agents_successful());
        }
    }
}
