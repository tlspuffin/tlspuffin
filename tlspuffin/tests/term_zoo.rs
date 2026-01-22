#![allow(unused_imports)]
use std::any::TypeId;
use std::cmp::max;
use std::collections::HashSet;

use itertools::Itertools;
use puffin::agent::AgentName;
use puffin::algebra::bitstrings::Payloads;
use puffin::algebra::dynamic_function::{DescribableFunction, TypeShape};
use puffin::algebra::error::FnError;
use puffin::algebra::signature::FunctionDefinition;
use puffin::algebra::{DYTerm, Term, TermType};
use puffin::codec::CodecP;
use puffin::error::Error;
use puffin::fuzzer::term_zoo::TermZoo;
use puffin::fuzzer::utils::{choose, find_term_by_term_path_mut, Choosable, TermConstraints};
use puffin::libafl;
use puffin::libafl::inputs::HasBytesVec;
use puffin::libafl::mutators::{MutationResult, Mutator, MutatorsTuple};
use puffin::libafl::prelude::HasRand;
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
            true,
            false,
            false,
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
#[ignore] // redundant
fn test_term_dy_eval() {
    for i in 0..1 {
        let rand = StdRand::with_seed(i as u64);
        let res = zoo_test(
            |term, ctx, _| term.evaluate_dy(&ctx).map(|_| ()),
            rand,
            1,
            true,
            true,
            true,
            false,
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
}

/// Tests whether all function symbols can be used when generating random terms and then be
/// correctly evaluated
#[test_log::test]
fn test_term_eval() {
    assert_eq!(ignore_eval(), ignore_eval_attribute()); // make sure the signature flag [no_gen] is consistent with this uni tests
    for i in 0..2 {
        let rand = StdRand::with_seed(i as u64);
        let res = zoo_test(
            |term, ctx, _| term.evaluate(&ctx).map(|_| ()),
            rand,
            1,
            true,
            true, // test_map should never map because we set filter_executable to true
            true,
            true,
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
    // Remark: some functions are tricky to generate terms for and we spend a lot of failures on a
    // small number of those, which is not visible in the above stats! Only 37 functions fail when
    // enabling stop_on_error.
    // The test passes for all function symbols except ignore_eval for zoo:MAX_TRIES = 110k
    // With zoo:MAX_TRIES = 1000: only a few failures:
    // [fn_sign_transcript, fn_find_server_finished, fn_derive_psk, fn_encrypt_application]
    // With zoo:MAX_TRIES = 200, quite a lot of failures now.
    // For much larger values (I tested 11_000_000), we still fail to generate the excluded two
    // symbols.
}

/// Tests whether all function symbols can be used when generating random terms and then be
/// correctly evaluated. We use the old generation method: no filtering out on successful
/// evaluation.
#[test_log::test]
#[ignore] // redundant
fn test_term_old_eval() {
    for i in 0..2 {
        let rand = StdRand::with_seed(i as u64);
        let res = zoo_test(
            |term, ctx, _| term.evaluate(&ctx).map(|_| ()),
            rand,
            2600,
            true,
            false, // test_map should never map because we set filter_executable to true
            false,
            false,
            None,
            &ignore_eval(),
        );
        log::error!("Step {i}");
        assert!(res);
    }
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
        let type_id: TypeId = term.get_type_shape().clone().into();
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
                    Err(e) => {
                        log::error!("Failed to read for term {}!\n  and encoding: {:?}\n  - TypeShape:{}, TypeId: {:?}", term, eval1, term.get_type_shape(), type_id);
                        if !ignored_functions.contains(term.name()) {
                            read_fail += 1;
                        }
                        Err(Error::Fn(FnError::Codec(format!("Failed to read: {e}"))))
                    }
                }
            })?
    };

    for i in 0..2 {
        let rand = StdRand::with_seed(i as u64);
        let res = zoo_test(
            &mut closure,
            rand,
            50,
            true,
            false,
            true,
            true,
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
