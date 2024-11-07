use std::any::TypeId;
use std::collections::HashSet;

use puffin::algebra::dynamic_function::DescribableFunction;
use puffin::algebra::error::FnError;
use puffin::algebra::TermType;
use puffin::codec::CodecP;
use puffin::error::Error;
use puffin::fuzzer::term_zoo::TermZoo;
use puffin::libafl_bolts::rands::StdRand;
use puffin::protocol::ProtocolBehavior;
use puffin::trace::{Spawner, TraceContext};
use tlspuffin::protocol::{TLSProtocolBehavior, TLSProtocolTypes};
use tlspuffin::put_registry::tls_registry;
use tlspuffin::tls::fn_impl::*;
use tlspuffin::tls::TLS_SIGNATURE;

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

#[test_log::test]
/// Tests whether all function symbols can be used when generating random terms
fn test_term_generation() {
    let mut rand = StdRand::with_seed(101);
    let zoo = TermZoo::<TLSProtocolTypes>::generate(&TLS_SIGNATURE, &mut rand);

    let subgraphs = zoo
        .terms()
        .iter()
        .enumerate()
        .map(|(i, term)| term.dot_subgraph(false, i, i.to_string().as_str()))
        .collect::<Vec<_>>();

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

    let ignored_functions = [
        fn_decrypt_application.name(), // FIXME: why ignore this?
        fn_rsa_sign_client.name(),     /* FIXME: We are currently excluding this, because an
                                        * attacker does not have access to the private key
                                        * of alice, eve or bob. */
        fn_rsa_sign_server.name(),
        // transcript functions -> ClaimList is usually available as Variable
        fn_server_finished_transcript.name(),
        fn_client_finished_transcript.name(),
        fn_server_hello_transcript.name(),
        fn_certificate_transcript.name(),
    ]
    .iter()
    .map(|fn_name| fn_name.to_string())
    .collect::<HashSet<String>>();

    successfully_built_functions.extend(ignored_functions);

    let difference = all_functions.difference(&successfully_built_functions);
    println!("{:?}", &difference);
    assert_eq!(difference.count(), 0);
    //println!("{}", graph);
}

#[cfg(all(feature = "tls13", feature = "deterministic"))] // require version which supports TLS 1.3
#[test_log::test]
// #[ignore]
/// Tests whether all function symbols can be used when generating random terms and then be
/// correctly evaluated
fn test_term_read_encode() {
    use puffin::algebra::dynamic_function::TypeShape;
    use tlspuffin::protocol::TLSProtocolTypes;

    let tls_registry = tls_registry();
    let spawner = Spawner::new(tls_registry.clone());
    let mut rand = StdRand::with_seed(101);
    let all_functions_shape = TLS_SIGNATURE.functions.to_owned();
    let ctx = TraceContext::new(spawner);
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
        let zoo =
            TermZoo::<TLSProtocolTypes>::generate_many(&TLS_SIGNATURE, &mut rand, 1000, Some(&f));
        let terms = zoo.terms();
        number_terms = number_terms + terms.len();

        for term in terms.iter() {
            if successfully_built_functions.contains(&term.name().to_string()) {
                // for speeding up things
                continue;
            }
            match &term.evaluate(&ctx) {
                Ok(eval) => {
                    // TODO: simplify this function now that we have Codec for EvaluatedTerm
                    let eval = eval.get_encoding();
                    log::debug!("Eval success!");
                    eval_count += 1;
                    let type_id: TypeId =
                        <TypeShape<TLSProtocolTypes> as Clone>::clone(&(*term.get_type_shape()))
                            .into();
                    match TLSProtocolBehavior::try_read_bytes(&*eval, type_id) {
                        Ok(message_back) => {
                            log::debug!("Read success!");
                            read_count += 1;
                            let eval2 =
                                TLSProtocolBehavior::any_get_encoding(message_back.as_ref());
                            if eval2 == *eval {
                                log::debug!("Consistent for term {term}");
                                successfully_built_functions
                                    .push(term.name().to_string().to_owned());
                                read_success += 1;
                            } else {
                                log::error!("[FAIL] Not the same read for term {}!\n  -Encoding1: {:?}\n  -Encoding2: {:?}\n  - TypeShape:{}, TypeId: {:?}", term, eval, eval2, term.get_type_shape(), type_id);
                                read_wrong += 1;
                            }
                        }
                        Err(e) => {
                            log::error!("[FAIL] Failed to read for term {}!\n  and encoding: {:?}\n  - TypeShape:{}, TypeId: {:?}", term, eval, term.get_type_shape(), type_id);
                            log::error!("Error: {}", e);
                            read_fail += 1;
                        }
                    }
                }
                Err(e) => {
                    log::error!("Evaluate FAILED with {e}. ");
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

    log::debug!(
        "Successfully built: #{:?}",
        &successfully_built_functions.len()
    );
    log::debug!("All functions: #{:?}", &all_functions.len());
    log::error!("number_shapes: {}, number_terms: {}, eval_count: {}, count_lazy_fail: {count_lazy_fail}, count_any_encode_fail: {count_any_encode_fail}\n", number_shapes, number_terms, eval_count);
    log::error!("Read stats: read_count: {read_count}, read_success: {read_success}, read_fail: {read_fail}, read_wrong: {read_wrong}");

    log::error!("Diff: {:?}\n", &difference);
    log::error!("Intersec with ignored: {:?}\n", &difference_inverse);
    assert_eq!(difference.count(), 0);
    assert_eq!(difference_inverse.count(), 0);
    assert_eq!(count_any_encode_fail, 0);
    // Excluding fn_heartbleed_fake_length:
    // Read stats: read_count: 163085, read_success: 162481, read_fail: 2963, read_wrong: 604
    // --> OKAY :) number_shapes: 213, number_terms: 209000, eval_count: 166048,
    // count_lazy_fail: 41952, count_any_encode_fail: 0 --> TODO: address some of those
}
