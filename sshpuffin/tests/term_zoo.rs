//! Term-zoo checks of the SSH signature, with the shared puffin implementation
//! (`puffin::test_utils`, also used by `tlspuffin/tests/term_zoo.rs`). They check the
//! signature flags: `[no_gen]` (`test_term_eval`), `[opaque]` / `[get]` / `[list]`
//! (`test_term_payloads_eval`, `unflagged_symbols_contain_their_arguments`), and the codec
//! (`test_term_read_encode`). PUT-gated because the evaluation context needs a linked registry.
#![cfg(any(has_put = "libssh0114", has_put = "wolfssh150"))]

use std::collections::HashSet;

use puffin::algebra::dynamic_function::DescribableFunction;
use puffin::algebra::{DYTerm, TermType};
use puffin::libafl_bolts::rands::StdRand;
use puffin::test_utils::{
    term_payloads_eval, term_payloads_mutate_eval, term_read_encode, ZooTest,
};
use sshpuffin::protocol::SshProtocolBehavior;
use sshpuffin::put_registry::ssh_registry;
use sshpuffin::ssh::fn_impl::{
    fn_claim_exchange_hash, fn_concat_raw_flights, fn_encrypt_packet_aesgcm, fn_onwire_message,
};
use sshpuffin::ssh::SSH_SIGNATURE;

fn ssh_zoo() -> ZooTest<'static, SshProtocolBehavior> {
    ZooTest::new(&SSH_SIGNATURE, ssh_registry())
}

/// The `[no_gen]` symbols: the zoo does not generate them.
fn no_gen() -> HashSet<String> {
    SSH_SIGNATURE
        .functions
        .iter()
        .filter(|f| SSH_SIGNATURE.attrs_by_name[f.0.name].no_gen)
        .map(|f| f.0.name.to_string())
        .collect()
}

#[test_log::test]
/// Every symbol can be used when generating random terms.
fn test_term_generation() {
    let zoo = ZooTest {
        how_many: 200,
        stop_on_success: false,
        stop_on_error: true,
        filter_executable: false,
        filter_no_gen: false,
        // Its argument is a claim, which only a PUT emits: no term builds one.
        ignored_functions: [fn_claim_exchange_hash.name().to_string()].into(),
        ..ssh_zoo()
    };
    assert!(zoo.run(StdRand::with_seed(102), |_, _, _| Ok(())));
}

#[test_log::test]
/// Every symbol without `[no_gen]` is the root of some generated term that evaluates: a symbol
/// the zoo cannot build an evaluable term for must be `[no_gen]`, or every campaign spends its
/// zoo budget on it for nothing.
fn test_term_eval() {
    let zoo = ZooTest {
        how_many: 1,
        ignored_functions: no_gen(),
        ..ssh_zoo()
    };
    for seed in 0..2 {
        assert!(zoo.run(StdRand::with_seed(seed), |term, ctx, _| term
            .evaluate(ctx)
            .map(|_| ())));
    }
}

#[test_log::test]
/// Evaluate, read back and re-encode: whenever a value reads back as its declared type,
/// re-encoding it is byte-identical (`encode` and `try_read_bytes` are consistent).
fn test_term_read_encode() {
    // `fn_concat_raw_flights` is the one documented exception to byte-exact
    // round-tripping, and it is BY DESIGN, not a codec bug. It joins two flights
    // at the message level; `RawSshMessageFlight::encode` then just concatenates
    // each message's wire bytes, while `RawSshMessageFlight::read` re-deframes the
    // WHOLE joined stream from scratch (`SshMessageDeframer`). For arbitrary,
    // misaligned zoo-generated pairs the re-deframe legitimately re-canonicalises
    // framing — e.g. a partial `OnWire` packet at the A/B boundary completes with
    // B's bytes and parses as a typed message, or a NEWKEYS in A flips the
    // deframer into opaque mode for B — so `encode ∘ read` need not reproduce the
    // naive concatenation. This is exactly the chunk-boundary re-framing the
    // decryption recipes rely on; the aligned-input identity property is locked
    // separately by `message::tests::concatenated_flights_reread_as_one_stream`.
    let mut ignored_functions = no_gen();
    // Its output is a sealed packet: the length, then ciphertext, which `RawSshMessage`
    // does not read back (only the deframer re-frames encrypted packets).
    ignored_functions.insert(fn_encrypt_packet_aesgcm.name().to_string());
    let zoo = ZooTest {
        how_many: 20,
        stop_on_success: false,
        ignored_functions,
        // Their outcome depends on the bytes they carry: `fn_concat_raw_flights`, see above;
        // `fn_onwire_message` wraps arbitrary bytes, which rarely read back as that same
        // `OnWire` message rather than as a banner or a packet.
        unstable_functions: [
            fn_concat_raw_flights.name().to_string(),
            fn_onwire_message.name().to_string(),
        ]
        .into(),
        ..ssh_zoo()
    };
    let (ok, stats) = term_read_encode(&zoo, 0..1);
    log::info!("[test_term_read_encode] {stats:?}");
    assert!(ok);
    let wrong: Vec<_> = stats
        .wrong_functions
        .iter()
        .filter(|f| !zoo.unstable_functions.contains(*f))
        .collect();
    assert!(
        wrong.is_empty(),
        "values read back as their declared type but re-encoded differently: {wrong:?} ({stats:?})"
    );
}

#[test_log::test]
/// Payloads placed on generated terms (the `MakeMessage` path) never hit `Error::TermBug`, i.e.
/// no parent symbol is missing its `[opaque]` / `[get]` / `[list]` flag.
fn test_term_payloads_eval() {
    let zoo = ZooTest {
        how_many: 20,
        stop_on_success: false,
        ignored_functions: no_gen(),
        ..ssh_zoo()
    };
    let (ok, stats) = term_payloads_eval(&zoo, 0..1);
    log::info!("[test_term_payloads_eval] {stats:?}");
    assert!(ok);
    assert_eq!(stats.term_bug, 0, "{:#?}", stats.term_bug_terms);
}

#[test_log::test]
/// As `test_term_payloads_eval`, with a bit-level mutation of one payload.
fn test_term_payloads_mutate_eval() {
    let zoo = ZooTest {
        how_many: 5,
        ignored_functions: no_gen(),
        ..ssh_zoo()
    };
    let (ok, stats) = term_payloads_mutate_eval(&zoo, 0..1);
    log::info!("[test_term_payloads_mutate_eval] {stats:?}");
    assert!(ok);
    assert_eq!(stats.term_bug, 0, "{:#?}", stats.term_bug_terms);
}

#[test_log::test]
/// The claim behind every UNFLAGGED symbol: its encoding contains the encoding of each of its
/// arguments, so a payload placed in an argument can be found in the parent's bytes. For each
/// non-constant symbol without `[opaque]` / `[get]` / `[list]`, over generated terms that
/// evaluate, every argument's encoding must be a sub-string of the term's encoding. A symbol
/// failing this needs a faithful encoding or a flag (see the legend above `define_signature!`).
fn unflagged_symbols_contain_their_arguments() {
    fn contains(hay: &[u8], needle: &[u8]) -> bool {
        needle.is_empty() || hay.windows(needle.len()).any(|w| w == needle)
    }

    let zoo = ZooTest {
        how_many: 100,
        stop_on_success: false,
        filter_executable: false,
        filter_no_gen: false,
        ..ssh_zoo()
    };
    let (mut checked, mut failures) = (0usize, Vec::new());
    zoo.run(StdRand::with_seed(7), |term, ctx, _| {
        let DYTerm::Application(f, args) = &term.term else {
            return Ok(());
        };
        let attrs = f.attrs();
        if args.is_empty() || attrs.is_opaque || attrs.is_get || attrs.is_list {
            return Ok(());
        }
        let (Ok(out), Ok(args)) = (
            term.evaluate(ctx),
            args.iter()
                .map(|a| a.evaluate(ctx).map(Vec::<u8>::from))
                .collect::<Result<Vec<_>, _>>(),
        ) else {
            return Ok(());
        };
        checked += 1;
        if let Some(i) = args.iter().position(|a| !contains(&out, a)) {
            failures.push(format!("{} (argument {i}): {term}", f.name()));
        }
        Ok(())
    });
    assert!(
        checked > 1000,
        "containment check was vacuous: {checked} terms"
    );
    assert!(
        failures.is_empty(),
        "unflagged symbols whose encoding lacks an argument: {failures:#?}"
    );
}
