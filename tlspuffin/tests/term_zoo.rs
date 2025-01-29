use std::any::TypeId;
use std::collections::HashSet;

use puffin::algebra::dynamic_function::{DescribableFunction, TypeShape};
use puffin::algebra::error::FnError;
use puffin::algebra::signature::FunctionDefinition;
use puffin::algebra::{Term, TermType};
use puffin::error::Error;
use puffin::fuzzer::term_zoo::TermZoo;
use puffin::libafl_bolts::prelude::RomuDuoJrRand;
use puffin::libafl_bolts::rands::StdRand;
use puffin::protocol::ProtocolBehavior;
use puffin::trace::{Spawner, TraceContext};
use tlspuffin::protocol::{TLSProtocolBehavior, TLSProtocolTypes};
use tlspuffin::put_registry::tls_registry;
use tlspuffin::tls::fn_impl::*;
use tlspuffin::tls::TLS_SIGNATURE;

/// Functions that are known to fail to be adversarially generated
pub fn ignore_gen() -> HashSet<String> {
    [
        // As expected, attacker cannot use them as there is no adversarial
        // '*Transcript*', which are required as argument
        fn_server_finished_transcript.name(),
        fn_client_finished_transcript.name(),
        fn_server_hello_transcript.name(),
        fn_certificate_transcript.name(),
    ]
    .iter()
    .map(|fn_name| fn_name.to_string())
    .collect::<HashSet<String>>()
}

/// Functions that are known to fail to be evaluated (without payloads)
pub fn ignore_eval() -> HashSet<String> {
    let mut ignore_gen = ignore_gen();
    let ignore_eval = [
        // Those 2 are the function symbols for which we can generate a term but all fail to
        // DY_execute! Indeed, the HandshakeHash that is fed as argument must be
        // computed in a very specific way! We might give known,valid hash-transcript to help?
        fn_decrypt_application.name(),
        fn_decrypt_multiple_handshake_messages.name(),
    ]
    .iter()
    .map(|fn_name| fn_name.to_string())
    .collect::<HashSet<String>>();
    ignore_gen.extend(ignore_eval);
    ignore_gen
}

/// Functions that are known to fail to be adversarially generated
pub fn ignore_add_payload() -> HashSet<String> {
    let mut ignore_eval = ignore_eval();
    let ignore_pay: HashSet<String> = [
        // No additional failures
        // fn_find_server_certificate_verify.name(),
        // fn_find_server_certificate_verify.name(),
        // fn_find_server_finished.name(),
    ]
    .iter()
    .map(|fn_name: &&str| fn_name.to_string())
    .collect::<HashSet<String>>();
    ignore_eval.extend(ignore_pay);
    ignore_eval
}
/// Parametric test for testing operations on terms (closure `test_map`, e.g., evaluation) through
/// the generation of a zoo of terms
pub fn zoo_test<Ft>(
    mut test_map: Ft,
    mut rand: RomuDuoJrRand,
    how_many: usize, // number of terms to generate for each function symbol (at root position)
    stop_on_success: bool, /* do not test further term if its function at root position was
                      * already positively tested */
    stop_on_error: bool, /* for each function, stop testing further terms if an error is
                          * encountered */
    filter: Option<&FunctionDefinition<TLSProtocolTypes>>,
    ignored_functions: &HashSet<String>,
) -> bool
where
    Ft: FnMut(
        &Term<TLSProtocolTypes>,
        &TraceContext<TLSProtocolBehavior>,
        &mut RomuDuoJrRand,
    ) -> Result<(), Error>,
{
    let tls_registry = tls_registry();
    let spawner = Spawner::new(tls_registry.clone());
    let ctx = TraceContext::new(spawner);

    let all_functions_shape = TLS_SIGNATURE.functions.to_owned();
    let number_functions = all_functions_shape.len();
    let mut number_terms = 0;
    let mut number_success = 0;
    let mut number_failure = 0;
    let mut number_failure_on_ignored = 0;
    let mut successful_functions = vec![];

    let bucket_size = 200;
    for f in &all_functions_shape {
        if filter.is_none() || (filter.is_some() && filter.unwrap().0.name == f.0.name) {
            'outer: for i in 0..(how_many / bucket_size) {
                let bucket_size_step = if i < how_many / bucket_size - 1 {
                    bucket_size
                } else {
                    how_many - bucket_size * (how_many / bucket_size - 1)
                };
                let zoo_f = TermZoo::<TLSProtocolTypes>::generate_many(
                    &TLS_SIGNATURE,
                    &mut rand,
                    bucket_size_step,
                    Some(&f),
                );
                let terms_f = zoo_f.terms();
                if terms_f.len() != how_many {
                    log::error!(
                        "Failed to generate {bucket_size_step} terms (only {}) for function {}.",
                        terms_f.len(),
                        f.0.name
                    );
                }
                number_terms += terms_f.len();

                for term in terms_f.iter() {
                    match test_map(term, &ctx, &mut rand) {
                        Ok(_) => {
                            successful_functions.push(term.name().to_string());
                            number_success += 1;
                            if stop_on_success {
                                break 'outer;
                            }
                        }
                        Err(e) => {
                            if ignored_functions.contains(term.name()) {
                                log::debug!("[Ignored function] Failed to test_map term {term} with error {e}. ");
                                number_failure_on_ignored += 1;
                            } else {
                                log::error!("[Not ignored function] Failed to test_map term {term} with error {e}. ");
                                number_failure += 1;
                                if stop_on_error {
                                    break 'outer;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    let all_functions = all_functions_shape
        .iter()
        .map(|(shape, _)| shape.name.to_string())
        .collect::<HashSet<String>>();

    let mut successful_functions = successful_functions
        .into_iter()
        .collect::<HashSet<String>>();
    let successful_functions_tested = successful_functions.clone();
    successful_functions.extend(ignored_functions.clone());

    let difference = all_functions.difference(&successful_functions);
    let difference_inverse = successful_functions_tested.intersection(&ignored_functions);

    log::debug!("[zoo_test] ignored_functions: {:?}\n", &ignored_functions);
    log::error!("[zoo_test] Diff: {:?}", &difference);
    log::error!(
        "[zoo_test] Intersection with ignored: {:?}",
        &difference_inverse
    );
    log::error!(
        "[zoo_test] Stats: how_many: {how_many}, stop_on_success: {stop_on_success}, stop_on_error: {stop_on_error}\n\
        --> number_functions: {}, number_terms: {}, number_success: {}, number_failure: {}, number_failure_on_ignored: {}\n\
        --> Successfully built (out of {:?} functions): {:?}",
        number_functions,
        number_terms,
        number_success,
        number_failure,
        number_failure_on_ignored,
        &all_functions.len(),
        &successful_functions_tested.len()
    );
    (difference.count() == 0) && (difference_inverse.count() == 0)
}

#[test_log::test]
/// Tests whether all function symbols can be used when generating random terms
fn test_term_generation() {
    let rand = StdRand::with_seed(102);
    for i in 0..10 {
        let res = zoo_test(
            |_term, _ctx, _rand| Ok(()),
            rand,
            200,
            false,
            true, // it should never fail
            None,
            &ignore_gen(),
        );
        log::error!("Step {i}");
        assert!(res);
    }
    /* (Step 9)
    [2024-11-14T15:02:07Z ERROR term_zoo] [zoo_test] Stats: how_many: 200, stop_on_success: false, stop_on_error: true
        --> number_functions: 221, number_terms: 43400, number_success: 43400, number_failure: 0, number_failure_on_ignored: 0
        --> Successfully built (out of 220 functions): 216
    */
}

/// Tests whether all function symbols can be used when generating random terms and then be
/// correctly DY evaluated
#[test_log::test]
fn test_term_dy_eval() {
    for i in 0..5 {
        let rand = StdRand::with_seed(i as u64);
        let res = zoo_test(
            |term, ctx, _| term.evaluate_dy(&ctx).map(|_| ()),
            rand,
            1200,
            true,
            false, /* it could fail since some terms need to have an appropriate structure to be
                    * evaluated correctly */
            None,
            &ignore_eval(),
        );
        log::error!("Step {i}");
        assert!(res);
    }
    /* (Step 4)
    [2024-11-14T15:10:16Z ERROR term_zoo] [zoo_test] Stats: how_many: 800, stop_on_success: true, stop_on_error: false
        --> number_functions: 221, number_terms: 45200, number_success: 215, number_failure: 1620, number_failure_on_ignored: 1600
        --> Successfully built (out of 220 functions): 214
     */
    // Remark: some functions are tricky to generate terms for and we spend a lot of failures on a
    // small number of those, which is not visible in the above stats! Only 37 functions fail when
    // enabling stop_on_error.
}

/// Tests whether all function symbols can be used when generating random terms and then be
/// correctly evaluated
#[test_log::test]
fn test_term_eval() {
    for i in 0..5 {
        let rand = StdRand::with_seed(i as u64);
        let res = zoo_test(
            |term, ctx, _| term.evaluate(&ctx).map(|_| ()),
            rand,
            1200,
            true,
            false,
            None,
            &ignore_eval(),
        );
        log::error!("Step {i}");
        assert!(res);
    }
    /* (Step 4)
    [2024-11-14T15:11:18Z ERROR term_zoo] [zoo_test] Stats: how_many: 800, stop_on_success: true, stop_on_error: false
        --> number_functions: 221, number_terms: 45200, number_success: 215, number_failure: 1620, number_failure_on_ignored: 1600
        --> Successfully built (out of 220 functions): 214
     */
}
#[test_log::test]
/// Tests whether all function symbols can be used when generating random terms and then be
/// correctly evaluated, read, and re-encoded yielding the same encoding
fn test_term_read_encode() {
    let mut read_count = 0;
    let mut read_success = 0;
    let mut read_fail = 0;
    let mut read_wrong = 0;
    let ignored_functions = ignore_eval();
    let mut closure = |term: &Term<TLSProtocolTypes>,
                       ctx: &TraceContext<TLSProtocolBehavior>,
                       _: &mut RomuDuoJrRand| {
        let type_id: TypeId =
            <TypeShape<TLSProtocolTypes> as Clone>::clone(&(*term.get_type_shape())).into();
        term.evaluate(&ctx)
            .map(|eval1| {
                match TLSProtocolBehavior::try_read_bytes(&*eval1, type_id) {
                    Ok(message_back) => {
                        log::debug!("Read success!");
                        read_count += 1;
                        let eval2 =
                            TLSProtocolBehavior::any_get_encoding(message_back.as_ref());
                        if eval2 == *eval1 {
                            read_success += 1;
                            Ok(())
                        } else {
                            log::error!("[FAIL] Not the same read for term {}!\n  -Encoding1: {:?}\n  -Encoding2: {:?}\n  - TypeShape:{}, TypeId: {:?}", term, eval1, eval2, term.get_type_shape(), type_id);
                            if !ignored_functions.contains(term.name()) {
                                read_wrong += 1;
                            }
                            Err(Error::Term("Not the same read".to_string()))
                        }
                    }
                    Err(_e) => {
                        log::error!("Failed to read for term {}!\n  and encoding: {:?}\n  - TypeShape:{}, TypeId: {:?}", term, eval1, term.get_type_shape(), type_id);
                        if !ignored_functions.contains(term.name()) {
                            read_fail += 1;
                        }
                        Err(Error::Fn(FnError::Unknown("Failed to read: {_e}".to_string())))
                    }
                }
            })?
    };

    for i in 0..5 {
        let rand = StdRand::with_seed(i as u64);
        let res = zoo_test(
            &mut closure,
            rand,
            1200,
            true,
            false,
            None,
            &ignored_functions,
        );
        log::error!("Step {i}");
        assert!(res);
    }
    log::error!("[test_term_read_encode] Read stats: read_count: {read_count}, read_success: {read_success}, read_fail: {read_fail}, read_wrong: {read_wrong}");
    /* (Step 4)
    [2024-11-14T15:12:16Z ERROR term_zoo] [zoo_test] Stats: how_many: 1000, stop_on_success: true, stop_on_error: false
        --> number_functions: 221, number_terms: 46200, number_success: 215, number_failure: 2611, number_failure_on_ignored: 2000
        --> Successfully built (out of 220 functions): 214
       (Global)
    [2024-11-14T15:16:17Z ERROR term_zoo] [test_term_read_encode] Read stats: read_count: 2105, read_success: 1075, read_fail: 205, read_wrong: 1030
     */
}
