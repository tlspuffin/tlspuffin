use puffin::algebra::TermType;
use puffin::fuzzer::utils::{find_term_by_term_path, find_term_by_term_path_mut};
use puffin::protocol::ProtocolBehavior;
use puffin::trace::Action::Input;
use puffin::trace::{Trace, TraceContext};
use tlspuffin::protocol::TLSProtocolBehavior;
use tlspuffin::test_utils::prelude::*;
use tlspuffin::tls::seeds::*;

fn test_one_replace(
    trace: &mut Trace<<TLSProtocolBehavior as ProtocolBehavior>::ProtocolTypes>,
    ctx: &TraceContext<TLSProtocolBehavior>,
    step_nb: usize,
    path: Vec<usize>,
    new_sub_vec: Vec<u8>,  // this will replace the payload at step_nb/path
    expected_vec: Vec<u8>, // expected bitstring for the whole recipe at step_nb
) {
    println!("\n=========================\nReplacing step {step_nb} with path {path:?} and new vec: {new_sub_vec:?}.");
    if let Input(input) = &mut trace.steps[step_nb].action {
        let term = &mut input.recipe;
        let e_before = term.evaluate(ctx).expect("OUPS1");
        log::debug!("Term: {term}\nTerm eval: {e_before:?}.");

        let sub = find_term_by_term_path_mut(term, &mut path.clone()).expect("OUPS2");
        sub.erase_payloads_subterms(false);
        sub.make_payload(ctx).unwrap(); // will remove payloads in strict sub-terms, as expected
        let sub_before = sub.clone();
        let e_sub_before = sub_before.evaluate_symbolic(ctx).expect("OUPS3"); // evaluate_symbolic:
                                                                              // mimicking term::make_payload ! We loose all previous mutations on sub-terms!
        log::debug!("Subterm before: {sub_before}\nSubterm eval_symbolic before: {e_sub_before:?}");
        if let Some(p) = &mut sub.payloads {
            p.payload = new_sub_vec.clone().into();
            log::debug!("Payload_0: {:?}", p.payload_0);
        } else {
            panic!("No payload after make_payload!");
        }
        // now that we added a different payload in term, we re-evaluate
        let e_after = term.evaluate(ctx).expect("OUPS4");
        let sub_after = find_term_by_term_path(term, &mut path.clone()).expect("OUPS5");
        let e_sub_after = sub_after.evaluate(ctx).expect("OUPS6");
        log::debug!("Subterm eval after: {e_sub_after:?}");
        log::debug!("Eval before: {e_before:?}");
        log::debug!("Eval after: {e_after:?}");
        log::debug!("Assert eq for step {step_nb} with path {path:?}:");
        assert_eq!(e_after, expected_vec);
    }
}

// UNIT TESTS for eval_until_opaque and replace_payloads
// Could be useful in RUST_LOG=DEBUG/TRACE mode to see all the replacements and window refinement
// of `eval_until_opaque` in detail.
// Only for BoringSSL 0.20260508.0: the answer of the PUT (hard-coded in the first replacement
// below, below the encryption) is deterministic but specific to this library and version.
#[apply(test_puts, filter = boringssl20260508)]
fn test_replace_bitstring_multiple(put: &str) {
    let runner = default_runner_for(put);
    let mut trace = seed_client_attacker_full.build_trace();
    let ctx = runner.execute(&trace, &mut 0).unwrap();

    let _step0_before = vec![
        22, 3, 3, // path=0: fn_protocol_version12 -> ProtocolVersion,
        0, 217, 1, 0, 0, 213, 3, 3, // Client Hello structure
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, // path=1: fn_new_random -> Random,
        32, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
        3, 3, 3, // path=2: fn_new_session_id -> SessionID,
        0, 2, 19, 1, // path=fn_append_cipher_suite(...)
        1, 0, // path= 4 fn_compressions -> Vec<Compression>,
        // path = 5 until the end
        0, 138, // path = 5,0,0,0,0,0,0  (empty) -> 44, 44, 0, 10, 0, 4, 0, 2, 0, 24, 44, 44
        0, 10, 0, 4, 0, 2, 0,
        24, // path = 5,0,0,0,0,0,1 -> 41, 41, 0, 40, 0, 4, 0, 2, 0, 24, 37, 37
        0, 13, 0, 6, 0, 4, 4, 1, 8, 4, 0, 51, 0, 103, 0, 101, 0, 24, 0, 97, 4, 83, 62, 229, 191,
        64, 236, 45, 103, 152, 139, 119, 243, 23, 72, 155, 182, 223, 149, 41, 37, 199, 9, 252, 3,
        129, 17, 26, 89, 86, 242, 215, 88, 17, 14, 89, 211, 215, 193, 114, 158, 44, 13, 112, 234,
        247, 115, 230, 18, 1, 22, 66, 109, 226, 67, 106, 47, 95, 221, 127, 229, 79, 175, 149, 43,
        4, 253, 19, 245, 22, 206, 98, 127, 137, 210, 1, 157, 76, 135, 150, 149, 158, 67, 51, 199,
        6, 91, 73, 108, 166, 52, 213, 220, 99, 189, 233, 31, 0, 43, 0, 3, 2, 3, 4, 0, 45, 0, 2, 1,
        1, // psk_key_exchange_modes extension
    ];
    // Structure of the ClientHello of `seed_client_attacker_full` (path of each sub-term):
    // fn_client_hello(
    //     fn_protocol_version12 -> ProtocolVersion,           // 0
    //     fn_new_random -> Random,                            // 1
    //     fn_new_session_id -> SessionID,                     // 2
    //     fn_cipher_suites_make(                              // 3
    //         fn_append_cipher_suite(                         // 3,0
    //             fn_new_cipher_suites,                       // 3,0,0
    //             fn_cipher_suite13_aes_128_gcm_sha256        // 3,0,1
    //         )
    //     ) -> Vec<CipherSuite>,
    //     fn_compressions -> Vec<Compression>,                // 4
    //     fn_client_extensions_make(                          // 5 (see the bytes above)
    //         fn_client_extensions_append(                    // 5,0
    //             fn_client_extensions_append(                // 5,0,0
    //                 fn_client_extensions_append(            // 5,0,0,0
    //                     fn_client_extensions_append(        // 5,0,0,0,0
    //                         fn_client_extensions_append(    // 5,0,0,0,0,0
    //                             fn_client_extensions_new,   // 5,0,0,0,0,0,0 (empty)
    //                             fn_support_group_extension_make(...) // 5,0,0,0,0,0,1
    //                         ),
    //                         fn_signature_algorithm_extension(...)    // 5,0,0,0,0,1
    //                     ),
    //                     fn_key_share_extension_make(...)            // 5,0,0,0,1
    //                 ),
    //                 fn_supported_versions13_extension               // 5,0,0,1
    //             ),
    //             fn_psk_exchange_mode_dhe_ke_extension               // 5,0,1
    //         )
    //     ) -> ClientExtensions
    // ) -> Message

    // This one operates below encryption! (we are able to replace payload under encryption:
    // fn_encrypt_handshake)
    let step_nb = 2;
    let path = vec![6];
    let new_vec = vec![0, 0, 4, 0, 0, 0, 0, 0];
    let expected_vec = vec![
        23, 3, 3, 0, 53, 218, 166, 94, 97, 108, 204, 150, 174, 34, 251, 112, 222, 209, 171, 9, 155,
        133, 213, 89, 187, 184, 194, 26, 208, 243, 59, 222, 233, 22, 117, 97, 112, 197, 11, 244,
        59, 174, 190, 58, 43, 207, 20, 34, 24, 135, 201, 216, 195, 167, 151, 238, 59, 130,
    ];
    test_one_replace(&mut trace, &ctx, step_nb, path, new_vec, expected_vec);

    // This one is tricky since it replaces an empty bitstring with an nonempty one, thus it
    // requires to find it using left or right brother
    let step_nb = 0;
    let path = vec![5, 0, 0, 0, 0, 0, 0];
    let new_vec = vec![44, 44, 0, 10, 0, 4, 0, 2, 0, 24, 44, 44];
    let expected_vec = vec![
        22, 3, 3, 0, 217, 1, 0, 0, 213, 3, 3, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 32, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
        3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 0, 2, 19, 1, 1, 0, 0, 138, 44, 44, 0,
        10, 0, 4, 0, 2, 0, 24, 44,
        44, // was empty, adding this! (compare with `step0_before` above)
        0, 10, 0, 4, 0, 2, 0, 24, 0, 13, 0, 6, 0, 4, 4, 1, 8, 4, 0, 51, 0, 103, 0, 101, 0, 24, 0,
        97, 4, 83, 62, 229, 191, 64, 236, 45, 103, 152, 139, 119, 243, 23, 72, 155, 182, 223, 149,
        41, 37, 199, 9, 252, 3, 129, 17, 26, 89, 86, 242, 215, 88, 17, 14, 89, 211, 215, 193, 114,
        158, 44, 13, 112, 234, 247, 115, 230, 18, 1, 22, 66, 109, 226, 67, 106, 47, 95, 221, 127,
        229, 79, 175, 149, 43, 4, 253, 19, 245, 22, 206, 98, 127, 137, 210, 1, 157, 76, 135, 150,
        149, 158, 67, 51, 199, 6, 91, 73, 108, 166, 52, 213, 220, 99, 189, 233, 31, 0, 43, 0, 3, 2,
        3, 4, 0, 45, 0, 2, 1, 1,
    ];
    test_one_replace(&mut trace, &ctx, step_nb, path, new_vec, expected_vec);

    // Also tricky because the path 5,0,0,1 is located right after the previous location that
    // was an empty bitstring but is now, after replacement, a 12-bytes bitstring!
    // Tricky since the previse byte location to operate the replace is impacted (hence `shift`
    // in `replace_payloads`).
    let step_nb = 0;
    let path = vec![5, 0, 0, 0, 0, 0, 1];
    let new_vec = vec![41, 41, 0, 40, 0, 4, 0, 2, 0, 24, 37, 37];
    let expected_vec = vec![
        22, 3, 3, 0, 217, 1, 0, 0, 213, 3, 3, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 32, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
        3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 0, 2, 19, 1, 1, 0, 0, 138, 44, 44, 0,
        10, 0, 4, 0, 2, 0, 24, 44, 44, // from previous replacement
        41, 41, 0, 40, 0, 4, 0, 2, 0, 24, 37, 37, // replace
        0, 13, 0, 6, 0, 4, 4, 1, 8, 4, 0, 51, 0, 103, 0, 101, 0, 24, 0, 97, 4, 83, 62, 229, 191,
        64, 236, 45, 103, 152, 139, 119, 243, 23, 72, 155, 182, 223, 149, 41, 37, 199, 9, 252, 3,
        129, 17, 26, 89, 86, 242, 215, 88, 17, 14, 89, 211, 215, 193, 114, 158, 44, 13, 112, 234,
        247, 115, 230, 18, 1, 22, 66, 109, 226, 67, 106, 47, 95, 221, 127, 229, 79, 175, 149, 43,
        4, 253, 19, 245, 22, 206, 98, 127, 137, 210, 1, 157, 76, 135, 150, 149, 158, 67, 51, 199,
        6, 91, 73, 108, 166, 52, 213, 220, 99, 189, 233, 31, 0, 43, 0, 3, 2, 3, 4, 0, 45, 0, 2, 1,
        1, // psk_key_exchange_modes extension
    ];
    test_one_replace(&mut trace, &ctx, step_nb, path, new_vec, expected_vec);

    // This one drops all previous payloads below path 5!
    let step_nb = 0;
    let path = vec![5];
    let new_vec = vec![0, 132, 0, 10, 0, 4, 0, 2, 0, 24, 0];
    let expected_vec = vec![
        22, 3, 3, 0, 217, 1, 0, 0, 213, 3, 3, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 32, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
        3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 0, 2, 19, 1, 1, 0, 0, 132, 0, 10, 0, 4,
        0, 2, 0, 24, 0, // replace
    ];
    test_one_replace(&mut trace, &ctx, step_nb, path, new_vec, expected_vec);

    let step_nb = 0;
    let path = vec![3, 0, 1];
    let new_vec = vec![19, 1, 11];
    let expected_vec = vec![
        22, 3, 3, 0, 217, 1, 0, 0, 213, 3, 3, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 32, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
        3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 0, 2, 19, 1, 11, // replace
        1, 0, 0, 132, 0, 10, 0, 4, 0, 2, 0, 24, 0, // from previous replacement
    ];
    test_one_replace(&mut trace, &ctx, step_nb, path, new_vec, expected_vec);

    // Tricky as well, similar to what is required to process path [5, 0, 0, 0, 1] above
    let step_nb = 0;
    let path = vec![4];
    let new_vec = vec![33, 33, 33, 33];
    let expected_vec = vec![
        22, 3, 3, 0, 217, 1, 0, 0, 213, 3, 3, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 32, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
        3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 0, 2, 19, 1,
        11, // from previous replacement
        // 1, 0,
        33, 33, 33, 33, // replace
        0, 132, 0, 10, 0, 4, 0, 2, 0, 24, 0, // from previous replacement
    ];
    test_one_replace(&mut trace, &ctx, step_nb, path, new_vec, expected_vec);
}
