use std::any::TypeId;
use std::cmp::max;
use std::collections::HashSet;

use itertools::Itertools;
use puffin::agent::AgentName;
use puffin::algebra::dynamic_function::{DescribableFunction, TypeShape};
use puffin::algebra::error::FnError;
use puffin::algebra::signature::FunctionDefinition;
use puffin::algebra::{DYTerm, Term, TermType};
use puffin::codec::CodecP;
use puffin::error::Error;
use puffin::fuzzer::term_zoo::TermZoo;
use puffin::fuzzer::utils::{choose, find_term_by_term_path_mut, Choosable, TermConstraints};
use puffin::libafl_bolts::prelude::RomuDuoJrRand;
use puffin::libafl_bolts::rands::{Rand, StdRand};
use puffin::protocol::{ProtocolBehavior, ProtocolTypes};
use puffin::trace::Action::Input;
use puffin::trace::{InputAction, Spawner, Step, Trace, TraceContext};
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
            2600,
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
            2600,
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
            1600,
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

#[cfg(all(feature = "tls13", feature = "deterministic"))] // require version which supports TLS 1.3
#[test_log::test]
/// Tests whether all function symbols can be used when generating random terms and then some
/// payloads be added while preserving a successful evaluation
fn test_term_payloads_eval() {
    let mut success_count = 0;
    let mut add_payload_fail = 0;
    let mut eval_payload_fail = 0;
    let mut rand = StdRand::with_seed(102);
    let ignored_functions = ignore_add_payload(); // currently is the same as ignore_eval()
    let mut closure = |term: &Term<TLSProtocolTypes>,
                       ctx: &TraceContext<TLSProtocolBehavior>,
                       rand2: &mut RomuDuoJrRand| {
        term.evaluate(&ctx).map(|_eval| {
            let mut term_with_payloads = term.clone();
            add_payloads_randomly(&mut term_with_payloads, rand2, &ctx);
            if term_with_payloads.all_payloads().len() == 0 {
                log::warn!("Failed to add payloads, skipping... For:\n   {term_with_payloads}");
                if !ignored_functions.contains(term.name()) {
                    add_payload_fail += 1;
                }
                return Err(Error::Term("Failed to add payloads".to_string()));
            } else {
                log::debug!("Term with payloads: {term_with_payloads}");
                // Sanity check:
                test_pay(&term_with_payloads);
                match &term_with_payloads.evaluate(&ctx) {
                    Ok(_eval) => {
                        log::debug!("Eval success!");
                        success_count += 1;
                        return Ok(());
                    }
                    Err(e) => {
                        log::error!("Eval FAILED with payloads: {term_with_payloads}.");
                        if !ignored_functions.contains(term.name()) {
                            eval_payload_fail += 1;
                        }
                        return Err(Error::Term("Failed to evaluate with payloads".to_string()));
                    }
                }
            }
        })?
    };

    for i in 0..3 {
        let mut rand = StdRand::with_seed(i as u64);
        let res = zoo_test(
            &mut closure,
            rand,
            8000,
            true,
            false,
            None,
            &ignored_functions,
        );
        log::error!("Step {i}");
        assert!(res);
    }
    log::error!("[test_term_payloads_eval] Stats: success_count: {success_count}, add_payload_fail: {add_payload_fail}, eval_payload_fail: {eval_payload_fail}");

    /* (Step 4)
    [2024-11-14T15:15:11Z ERROR term_zoo] [zoo_test] Stats: how_many: 8000, stop_on_success: true, stop_on_error: false
        --> number_functions: 221, number_terms: 63400, number_success: 215, number_failure: 6651, number_failure_on_ignored: 16000
        --> Successfully built (out of 220 functions): 214
           (Global)
    [2024-11-14T15:15:11Z ERROR term_zoo] [test_term_payloads_eval] Stats: success_count: 645, add_payload_fail: 0, eval_payload_fail: 187
         */
}

// OLD
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

fn add_one_payload_randomly<
    PT: ProtocolTypes,
    R: Rand,
    PB: ProtocolBehavior<ProtocolTypes = PT>,
>(
    t: &mut Term<PT>,
    rand: &mut R,
    ctx: &TraceContext<PB>,
) -> Result<(), Error> {
    let trace = Trace {
        descriptors: vec![],
        steps: vec![Step {
            agent: AgentName::new(),
            action: Input(InputAction {
                precomputations: vec![],
                recipe: t.clone(),
            }),
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
        if let Ok(()) = st.make_payload(ctx) {
            log::debug!("Added payload for subterm at path {path:?}, step{step},\n - sub_term: {st_}\n  - whole_term {trace}\n  - evaluated={:?}, ", st.payloads.as_ref().unwrap().payload_0);
            if let Some(payloads) = &mut st.payloads {
                let mut a: Vec<u8> = payloads.payload.clone().into();
                a.push(2); // TODO: make something random here! (I suggest mutate with bit-level mutations)
                a.push(2);
                a.push(2);
                a[0] = 2;
                payloads.payload = a.into();
                log::debug!("Added a payload at path {path:?}.");
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

fn add_payloads_randomly<PT: ProtocolTypes, R: Rand, PB: ProtocolBehavior<ProtocolTypes = PT>>(
    t: &mut Term<PT>,
    rand: &mut R,
    ctx: &TraceContext<PB>,
) {
    let all_subterms: Vec<&Term<PT>> = t.into_iter().collect_vec();
    let nb_subterms = all_subterms.len() as i32;
    let mut i = 0;
    let nb = (1..max(4, nb_subterms / 3))
        .collect::<Vec<i32>>()
        .choose(rand)
        .unwrap()
        .to_owned();
    log::debug!(
        "Adding {nb} payloads for #subterms={nb_subterms}, max={} in term: {t}...",
        max(2, nb_subterms / 5)
    );
    let mut tries = 0;
    // let nb = 1;
    while i < nb {
        tries += 1;
        if tries > nb * 100 {
            log::error!("Failed to add the payloads after {} attempts", tries);
            break;
        }
        if let Ok(()) = add_one_payload_randomly(t, rand, ctx) {
            i += 1;
        }
    }
}

/// Sanity check for the next test
pub fn test_pay<PT: ProtocolTypes>(term: &Term<PT>) {
    rec_inside(term, false, term);
    pub fn rec_inside<PT: ProtocolTypes>(
        term: &Term<PT>,
        already_found: bool,
        whole_term: &Term<PT>,
    ) {
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
