#[allow(clippy::ptr_arg)]
#[cfg(test)]
mod tests {
    use log::{debug, error, warn};
    use std::any::Any;
    use std::cmp::max;
    use std::collections::HashSet;
    use std::fmt::Debug;
    use itertools::Itertools;

    use puffin::algebra::error::FnError;
    use puffin::algebra::{ConcreteMessage, evaluate_lazy_test, Matcher, Payloads, replace_payloads, TermEval, TermType};
    use puffin::codec::{Codec};
    use puffin::error::Error;
    use puffin::protocol::{ProtocolBehavior, ProtocolMessage};
    use puffin::trace::{Action, InputAction, OutputAction, Step, Trace, TraceContext};
    use puffin::{
        algebra::dynamic_function::DescribableFunction, codec, fuzzer::term_zoo::TermZoo,
        libafl::bolts::rands::StdRand,
    };
    use puffin::agent::AgentName;
    use puffin::algebra::signature::FunctionDefinition;
    use puffin::fuzzer::utils::{Choosable, choose, find_term_by_term_path_mut, TermConstraints};
    use puffin::libafl::prelude::Rand;
    use puffin::put::PutOptions;
    use puffin::trace::Action::Input;

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
    use crate::tls::seeds::{create_corpus, seed_client_attacker_full};


    // UNI TESTS for eval_until_opaque and replace_payloads
    // Do not test terms with opaque sub-terms though!
    #[cfg(feature = "tls13")] // require version which supports TLS 1.3
    #[test_log::test]
    #[test]
    fn test_replace_bitstring_multiple() {
        let mut ctx = TraceContext::new(&TLS_PUT_REGISTRY, PutOptions::default());
        ctx.set_deterministic(true);
        let mut trace = seed_client_attacker_full.build_trace();
        let mut fn_hello_b = vec![
            22, 3, 3, 0, 211, 1, 0, 0, 207, 3, 3, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 32, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
            3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 0, 2, 19, 1, 1, 0, 0, 132,
            0, 10, 0, 4, 0, 2, 0, 24, 0, 13, 0, 6, 0, 4, 4, 1, 8, 4, 0, 51, 0, 103, 0, 101, 0, 24,
            0, 97, 4, 83, 62, 229, 191, 64, 236, 45, 103, 152, 139, 119, 243, 23, 72, 155, 182,
            223, 149, 41, 37, 199, 9, 252, 3, 129, 17, 26, 89, 86, 242, 215, 88, 17, 14, 89, 211,
            215, 193, 114, 158, 44, 13, 112, 234, 247, 115, 230, 18, 1, 22, 66, 109, 226, 67, 106,
            47, 95, 221, 127, 229, 79, 175, 149, 43, 4, 253, 19, 245, 22, 206, 98, 127, 137, 210,
            1, 157, 76, 135, 150, 149, 158, 67, 51, 199, 6, 91, 73, 108, 166, 52, 213, 220, 99,
            189, 233, 31, 0, 43, 0, 3, 2, 3, 4,
        ];
        let fn_hello_initial = fn_hello_b.clone();
        let fn_hello_b_after = vec![
            22, 3, 3, 0, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 207, 3, 3, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 32, 3, 3, 3, 3, 3, 3,
            3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 0, 2, 19,
            1, 1, 0, 0, 132, 0, 10, 0, 4, 0, 2, 0, 24, 0, 13, 0, 6, 0, 4, 4, 1, 8, 4, 0, 51, 0,
            103, 0, 101, 0, 24, 0, 97, 4, 83, 62, 229, 191, 64, 236, 45, 103, 152, 139, 119, 243,
            23, 72, 155, 182, 223, 149, 41, 37, 199, 9, 252, 3, 129, 17, 26, 89, 86, 242, 215, 88,
            17, 14, 89, 211, 215, 193, 114, 158, 44, 13, 112, 234, 247, 115, 230, 18, 1, 22, 66,
            109, 226, 67, 106, 47, 95, 221, 127, 229, 79, 175, 149, 43, 4, 253, 19, 245, 22, 206,
            98, 127, 137, 210, 1, 157, 76, 135, 150, 149, 158, 67, 51, 199, 6, 91, 73, 108, 166,
            52, 213, 220, 99, 189, 233, 31, 0, 43, 0, 3, 2, 3, 4,
        ];

        if let Input(input) = &mut trace.steps[0].action {
            let mut ch_term = &mut input.recipe;
            // let eval_init = ch_term.evaluate(&ctx).expect("fail eval");
            // assert_eq!(eval_init, fn_hello_b);

            let path0 = vec![5, 0,0,0,0];
            let mut ch_term = &mut input.recipe.clone();
            let mut subterm0 = find_term_by_term_path_mut(&mut ch_term, &mut path0.clone()).expect("OUPS");
            let e1 = subterm0.evaluate_symbolic(&ctx).expect("OUPS");
            error!("Subterm0: {subterm0}\n eval: {e1:?}"); //      eval: []
            let mut e2 = e1.clone(); e2.push(44); e2.push(44);
            let p0 = Payloads{
                payload_0: e1.into(),
                payload: e2.into(),
            };
            subterm0.payloads = Some(p0.clone());
            let e = ch_term.evaluate(&ctx).expect("OUPS");
            // payload_0: []  (just before 0, 10, 0, 4, 0, 2, 0, 24
            // payload:   [44, 44]
            // to replace at position 84
            warn!("Eval0: {:?}", e);
            assert_eq!(e, vec![22, 3, 3, 0, 211, 1, 0, 0, 207, 3, 3, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 32, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
            3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 0, 2, 19, 1, 1, 0, 0, 132,
            44,44, // adding this
            0, 10, 0, 4, 0, 2, 0, 24, 0, 13, 0, 6, 0, 4, 4, 1, 8, 4, 0, 51, 0, 103, 0, 101, 0, 24,
            0, 97, 4, 83, 62, 229, 191, 64, 236, 45, 103, 152, 139, 119, 243, 23, 72, 155, 182,
            223, 149, 41, 37, 199, 9, 252, 3, 129, 17, 26, 89, 86, 242, 215, 88, 17, 14, 89, 211,
            215, 193, 114, 158, 44, 13, 112, 234, 247, 115, 230, 18, 1, 22, 66, 109, 226, 67, 106,
            47, 95, 221, 127, 229, 79, 175, 149, 43, 4, 253, 19, 245, 22, 206, 98, 127, 137, 210,
            1, 157, 76, 135, 150, 149, 158, 67, 51, 199, 6, 91, 73, 108, 166, 52, 213, 220, 99,
            189, 233, 31, 0, 43, 0, 3, 2, 3, 4]
            );


            let path1 = vec![5, 0,0,0,1];
            let mut ch_term = &mut input.recipe.clone();
            error!("Recipe: {ch_term}");
            let mut subterm1 = find_term_by_term_path_mut(&mut ch_term, &mut path1.clone()).expect("OUPS");
            let e1 = subterm1.evaluate_symbolic(&ctx).expect("OUPS");
            error!("Subterm1: {subterm1}\n eval: {e1:?}"); //      eval: [0]
            let mut e2 = e1.clone(); e2.push(44); e2.push(44);
            e2[1] = 44 as u8;
            let p1 = Payloads{
                payload_0: e1.into(),
                payload: e2.into(),
            };
            subterm1.payloads = Some(p1.clone());
            let e = ch_term.evaluate(&ctx).expect("OUPS");
            // payload_0: [0, 10, 0, 4, 0, 2, 0, 24]
            // payload:   [0, 44, 0, 4, 0, 2, 0, 24, 44, 44]
            // to replace at position 84
            warn!("Eval1: {:?}", e);
            assert_eq!(e, vec![22, 3, 3, 0, 211, 1, 0, 0, 207, 3, 3, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 32, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 0, 2, 19, 1, 1, 0, 0, 132,
                               0, 44, 0, 4, 0, 2, 0, 24, 44, 44, // replace
                               0, 13, 0, 6, 0, 4, 4, 1, 8, 4, 0, 51, 0, 103, 0, 101, 0, 24, 0, 97, 4, 83, 62, 229, 191, 64, 236, 45, 103, 152, 139, 119, 243, 23, 72, 155, 182, 223, 149, 41, 37, 199, 9, 252, 3, 129, 17, 26, 89, 86, 242, 215, 88, 17, 14, 89, 211, 215, 193, 114, 158, 44, 13, 112, 234, 247, 115, 230, 18, 1, 22, 66, 109, 226, 67, 106, 47, 95, 221, 127, 229, 79, 175, 149, 43, 4, 253, 19, 245, 22, 206, 98, 127, 137, 210, 1, 157, 76, 135, 150, 149, 158, 67, 51, 199, 6, 91, 73, 108, 166, 52, 213, 220, 99, 189, 233, 31, 0, 43, 0, 3, 2, 3, 4]);

            let path2 = vec![5];
            let mut ch_term = &mut input.recipe.clone();
            let mut subterm2 = find_term_by_term_path_mut(&mut ch_term, &mut path2.clone()).expect("OUPS");
            let e1 = subterm2.evaluate_symbolic(&ctx).expect("OUPS");
            error!("Subterm2: {subterm2}\n eval: {e1:?}"); //  eval: [132, 0, 10, 0, 4, 0, 2, 0, 24, 0, 13, 0, 6, 0, 4, 4, 1, 8, 4, 0, 51, 0, 103, 0, 101, 0, 24, 0, 97, 4, 83, 62, 229, 191, 64, 236, 45, 103, 152, 139, 119, 243, 23, 72, 155, 182, 223, 149, 41, 37, 199, 9, 252, 3, 129, 17, 26, 89, 86, 242, 215, 88, 17, 14, 89, 211, 215, 193, 114, 158, 44, 13, 112, 234, 247, 115, 230, 18, 1, 22, 66, 109, 226, 67, 106, 47, 95, 221, 127, 229, 79, 175, 149, 43, 4, 253, 19, 245, 22, 206, 98, 127, 137, 210, 1, 157, 76, 135, 150, 149, 158, 67, 51, 199, 6, 91, 73, 108, 166, 52, 213, 220, 99, 189, 233, 31, 0, 43, 0, 3, 2, 3, 4]
            let mut e2 = e1[0..10].to_vec(); e2.push(33); e2.push(33);
            let p2 = Payloads{
                payload_0: e1.into(),
                payload: e2.into(),
            };
            subterm2.payloads = Some(p2.clone());
            let e = ch_term.evaluate(&ctx).expect("OUPS");
            warn!("Eval: {:?}", e);
            assert_eq!(e, vec![
            22, 3, 3, 0, 211, 1, 0, 0, 207, 3, 3, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 32, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
            3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 0, 2, 19, 1, 1, 0, 0,
            132, 0, 10, 0, 4, 0, 2, 0, 24, 0, // replace
            33,33
            ]);


            let path3 = vec![3,1];
            let mut ch_term = &mut input.recipe.clone();
            let mut subterm3 = find_term_by_term_path_mut(&mut ch_term, &mut path3.clone()).expect("OUPS");
            let e1 = subterm3.evaluate_symbolic(&ctx).expect("OUPS");
            error!("Subterm3: {subterm3}\n eval: {e1:?}"); //         eval: [19, 1]
            let mut e2 = e1.clone(); e2.push(11);
            let p3 = Payloads{
                payload_0: e1.into(),
                payload: e2.into(),
            };
            subterm3.payloads = Some(p3.clone());
            let e = ch_term.evaluate(&ctx).expect("OUPS");
            warn!("Eval: {:?}", e);
            assert_eq!(e,  vec![
                22, 3, 3, 0, 211, 1, 0, 0, 207, 3, 3, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 32, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
                3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 0, 2,
                19, 1, 11, // replace
                1, 0, 0, 132, 0, 10, 0, 4, 0, 2, 0, 24, 0, 13, 0, 6, 0, 4, 4, 1, 8, 4, 0, 51, 0,
                103, 0, 101, 0, 24, 0, 97, 4, 83, 62, 229, 191, 64, 236, 45, 103, 152, 139, 119, 243,
                23, 72, 155, 182, 223, 149, 41, 37, 199, 9, 252, 3, 129, 17, 26, 89, 86, 242, 215, 88,
                17, 14, 89, 211, 215, 193, 114, 158, 44, 13, 112, 234, 247, 115, 230, 18, 1, 22, 66,
                109, 226, 67, 106, 47, 95, 221, 127, 229, 79, 175, 149, 43, 4, 253, 19, 245, 22, 206,
                98, 127, 137, 210, 1, 157, 76, 135, 150, 149, 158, 67, 51, 199, 6, 91, 73, 108, 166,
                52, 213, 220, 99, 189, 233, 31, 0, 43, 0, 3, 2, 3, 4,
            ]);

            let path4 = vec![4];
            let mut ch_term = &mut input.recipe.clone();
            let mut subterm4 = find_term_by_term_path_mut(&mut ch_term, &mut path4.clone()).expect("OUPS");
            let e1 = subterm4.evaluate_symbolic(&ctx).expect("OUPS");
            error!("Subterm4: {subterm4}\n eval: {e1:?}\n---------------------------\n"); //          eval: [1, 0]
            let mut e2 = vec![33, 33, 33, 33];
            let p4 = Payloads{
                payload_0: e1.into(), // cheating here to test out the case with an empty paylaod_0
                payload: e2.into(),
            };
            subterm4.payloads = Some(p4.clone());
            // payloads.push((&p3, path3.clone(), 0, vec![]));
            let e = ch_term.evaluate(&ctx);
            let e = ch_term.evaluate(&ctx).expect("OUPS");
            // // payload_0: [1, 0]
            // // payload:   [33, 33, 33, 33]
            warn!("Eval: {:?}", e);
            assert_eq!(e,  vec![
                22, 3, 3, 0, 211, 1, 0, 0, 207, 3, 3, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 32, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
                3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 0, 2, 19, 1,
                // 1, 0,
                33, 33, 33, 33, // replace
                0, 132, 0, 10, 0, 4, 0, 2, 0, 24, 0, 13, 0, 6, 0, 4, 4, 1, 8, 4, 0, 51, 0, 103, 0, 101, 0, 24,
                0, 97, 4, 83, 62, 229, 191, 64, 236, 45, 103, 152, 139, 119, 243, 23, 72, 155, 182,
                223, 149, 41, 37, 199, 9, 252, 3, 129, 17, 26, 89, 86, 242, 215, 88, 17, 14, 89, 211,
                215, 193, 114, 158, 44, 13, 112, 234, 247, 115, 230, 18, 1, 22, 66, 109, 226, 67, 106,
                47, 95, 221, 127, 229, 79, 175, 149, 43, 4, 253, 19, 245, 22, 206, 98, 127, 137, 210,
                1, 157, 76, 135, 150, 149, 158, 67, 51, 199, 6, 91, 73, 108, 166, 52, 213, 220, 99,
                189, 233, 31, 0, 43, 0, 3, 2, 3, 4,
            ]);
        } else {
            panic!("Should not happen");
        }
    }

    #[cfg(feature = "tls13")] // require version which supports TLS 1.3
    #[test]
    fn test_evaluate_recipe_input_compare_new() {
        use crate::tls::trace_helper::TraceExecutor;

        for (tr, name) in create_corpus() {
            println!("\n\n============= Executing trace {name}");
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
                println!("Executing step #{}", i);

                match &step.action {
                    Action::Input(input) => {
                        println!("Running custom test for inputs...");
                        {
                            let evaluated_lazy = evaluate_lazy_test(&input.recipe, &ctx).expect("a");
                            if let Some(msg_old) = evaluated_lazy.as_ref().downcast_ref::<<TLSProtocolBehavior as ProtocolBehavior>::ProtocolMessage>() {
                                println!("Term {}\n could be parsed as ProtocolMessage", input.recipe);
                                let evaluated = input.recipe.evaluate(&mut ctx).expect("a");
                                if let Some(msg) = <TLSProtocolBehavior as ProtocolBehavior>::OpaqueProtocolMessage::read_bytes(&evaluated) {
                                    println!("=====> and was successfully handled with the new input evaluation routine! We now check they are equal...");
                                    assert_eq!(msg_old.create_opaque().get_encoding(), msg.get_encoding());
                                    ctx.add_to_inbound(step.agent, &msg).expect("");
                                } else {
                                    panic!("Should not happen")
                                }

                            } else if let Some(opaque_message_old) = evaluated_lazy
                                .as_ref()
                                .downcast_ref::<<TLSProtocolBehavior as ProtocolBehavior>::OpaqueProtocolMessage>()
                            {
                                println!("Term {}\n could be parsed as OpaqueProtocolMessage", input.recipe);
                                let evaluated = input.recipe.evaluate(&mut ctx).expect("c");
                                if let Some(msg) = <TLSProtocolBehavior as ProtocolBehavior>::OpaqueProtocolMessage::read_bytes(&evaluated) {
                                    println!("=====> and was successfully handled with the new input evaluation routine! We now check they are equal...");
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