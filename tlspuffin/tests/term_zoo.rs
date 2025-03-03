use std::any::TypeId;
use std::cmp::max;
use std::collections::HashSet;

use anyhow::anyhow;
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
use tlspuffin::test_utils::*;
use tlspuffin::tls::fn_impl::*;
use tlspuffin::tls::TLS_SIGNATURE;

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
                            Err(anyhow!(Error::Term("Not the same read".to_string())))
                        }
                    }
                    Err(e) => {
                        log::error!("Failed to read for term {}!\n  and encoding: {:?}\n  - TypeShape:{}, TypeId: {:?}", term, eval1, term.get_type_shape(), type_id);
                        if !ignored_functions.contains(term.name()) {
                            read_fail += 1;
                        }
                        Err(anyhow!(Error::Fn(FnError::Codec(format!("Failed to read: {e}")))))
                    }
                }
            })?
    };

    for i in 0..5 {
        let rand = StdRand::with_seed(i as u64);
        let res = zoo_test(
            &mut closure,
            rand,
            1800,
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
                return Err(anyhow!(Error::Term("Failed to add payloads".to_string())));
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
                        return Err(anyhow!(Error::Term(
                            "Failed to evaluate with payloads".to_string()
                        )));
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
            17000, // TODO: investigate potential root causes we can fix
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
