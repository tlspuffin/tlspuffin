use puffin::algebra::TermType;
use puffin::libafl_bolts::rands::StdRand;
use puffin::test_utils::{term_payloads_eval, term_payloads_mutate_eval, term_read_encode};
use tlspuffin::test_utils::*;

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
    let zoo = ZooTest {
        ignored_functions: ignore_eval(),
        ..tls_zoo()
    };
    let (ok, stats) = term_read_encode(&zoo, 0..2);
    log::error!("[test_term_read_encode] Read stats: {stats:?}");
    assert!(ok);
    /* (Step 4)
    [2024-11-14T15:12:16Z ERROR term_zoo] [zoo_test] Stats: how_many: 1000, stop_on_success: true, stop_on_error: false
        --> number_functions: 221, number_terms: 46200, number_success: 215, number_failure: 2611, number_failure_on_ignored: 2000
        --> Successfully built (out of 220 functions): 214
       (Global)
    [2024-11-14T15:16:17Z ERROR term_zoo] [test_term_read_encode] Read stats: read_count: 2105, read_success: 1075, read_fail: 205, read_wrong: 1030
     */
}

#[test_log::test]
// #[ignore] // redundant
/// Tests whether all function symbols can be used when generating random terms and then some
/// payloads be added while preserving a successful evaluation
fn test_term_payloads_eval() {
    let zoo = ZooTest {
        ignored_functions: ignore_add_payload(), // currently is the same as ignore_eval()
        ..tls_zoo()
    };
    let (ok, stats) = term_payloads_eval(&zoo, 0..2);
    log::error!("[test_term_payloads_eval] Stats: {stats:?}");
    assert!(ok);
    assert_eq!(stats.term_bug, 0, "{:#?}", stats.term_bug_terms);
    /*
       Harder symbol to obtain is `fn_preshared_keys_extension_empty_binder` and forces us to fo from how_many=50 to 100.
    */
    /* (Step 4)
    [2024-11-14T15:15:11Z ERROR term_zoo] [zoo_test] Stats: how_many: 8000, stop_on_success: true, stop_on_error: false
        --> number_functions: 221, number_terms: 63400, number_success: 215, number_failure: 6651, number_failure_on_ignored: 16000
        --> Successfully built (out of 220 functions): 214
           (Global)
    [2024-11-14T15:15:11Z ERROR term_zoo] [test_term_payloads_eval] Stats: success_count: 645, add_payload_fail: 0, eval_payload_fail: 187
         */
}

#[test_log::test]
/// Tests whether all function symbols can be used when generating random terms and then some
/// payloads be added **and bit-level mutated** while preserving a successful evaluation
fn test_term_payloads_mutate_eval() {
    let zoo = ZooTest {
        ignored_functions: ignore_add_payload_mutate(), // currently is the same as ignore_eval()
        ..tls_zoo()
    };
    let (ok, stats) = term_payloads_mutate_eval(&zoo, 0..1);
    log::error!("[test_term_payloads_mutate_eval] Stats: {stats:?}");
    assert!(ok);
    assert_eq!(stats.term_bug, 0, "{:#?}", stats.term_bug_terms);
}

/* Old:
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
