//! Tier-2 Q4/Q5 (CVE-2021-3634) — how a single DY mutation turns the honest curve25519 rekey seed
//! into the group16 rekey that triggers the heap overflow, measured at the term level and by
//! execution.
//!
//! IMPORTANT (2026-11-24): run these with `ASAN_OPTIONS=abort_on_error=1:detect_leaks=0`. Without
//! `abort_on_error`, an ASan error ends the forked child with `exit(1)` instead of `SIGABRT`, so
//! `ForkedRunner` reports `ExecutionStatus::Failure(1)` rather than `Crashed` — exactly the bug that
//! made the Q2/Q5 CAMPAIGNS look like "0 finds" while they were really dropping ~95 real crashes.
//! `cargo test` gets the right options from `.cargo/config.toml` `[env]`; a directly-launched binary
//! or a shell that pre-sets `ASAN_OPTIONS` does NOT (see `puffin::fuzzer::sanitizer::asan`). With the
//! crash correctly recorded, the honest seed is found organically in ~53 s, and `ReplaceReuse` on the
//! group16-fallback seed reaches it at E≈294.
//!
//! The census tests below count how often one mutator produces the group16 kex swap; `quantify_*` and
//! `diagnose_*` then EXECUTE the mutants. A symbol-count census is only a pre-filter — a count match
//! is not a crash (it can be a reorder or a malformed splice); the executing tests are ground truth.
//!
//! Run: `ASAN_OPTIONS=abort_on_error=1:detect_leaks=0 cargo test -p sshpuffin \
//!   --test reachability_cve_2021_3634 -- --ignored --nocapture` (needs a built libssh vendor).

#![cfg(has_libssh)]

use puffin::agent::AgentName;
use puffin::algebra::dynamic_function::DescribableFunction;
use puffin::execution::{ExecutionStatus, ForkedRunner, Runner, TraceRunner};
use puffin::fuzzer::mutations::{
    MutationConfig, RemoveAndLiftMutator, ReplaceMatchMutator, ReplaceReuseMutator, SwapMutator,
};
use puffin::libafl::corpus::InMemoryCorpus;
use puffin::libafl::mutators::{MutationResult, Mutator};
use puffin::libafl::prelude::StdState;
use puffin::libafl_bolts::bolts_prelude::{RomuDuoJrRand, StdRand};
use puffin::protocol::ProtocolTypes;
use puffin::trace::{Spawner, Trace};
use sshpuffin::protocol::{SshProtocolBehavior, SshProtocolTypes};
use sshpuffin::put_registry::ssh_registry;
use sshpuffin::ssh::fn_impl::{fn_algo_curve25519_sha256, fn_algo_dh_group16_sha512};
use sshpuffin::ssh::seeds::{
    seed_client_attacker_rekey, seed_client_attacker_rekey_dh_group16,
    seed_client_attacker_rekey_g16_fallback, seed_client_attacker_rekey_kex,
    seed_probe_rekey_g16_ecdhmsg, RekeyKexOffer,
};

/// The CVE-2021-3634-only PUT (libssh 0.9.5, ASan, isolated to this bug): any heap-buffer-overflow
/// here is unambiguously the target crash.
const PUT: &str = "libssh095-asan-only-CVE-2021-3634";

type SshState = StdState<
    InMemoryCorpus<Trace<SshProtocolTypes>>,
    Trace<SshProtocolTypes>,
    RomuDuoJrRand,
    InMemoryCorpus<Trace<SshProtocolTypes>>,
>;

fn create_state(seed: u64) -> SshState {
    let rand = StdRand::with_seed(seed);
    let corpus: InMemoryCorpus<Trace<SshProtocolTypes>> = InMemoryCorpus::new();
    StdState::new(rand, corpus, InMemoryCorpus::new(), &mut (), &mut ()).unwrap()
}

/// How many single `ReplaceMatch` applications on the honest rekey seed until the crash-triggering
/// `curve25519 -> group16` swap on the rekey-KEX leaf — the Q5 "# of mutations until the wanted
/// one".
#[test]
#[ignore] // quantification harness; run explicitly with --ignored --nocapture
fn quantify_mutations_to_group16_swap() {
    let server = AgentName::first().next();
    let seed = seed_client_attacker_rekey(server);

    let g16 = fn_algo_dh_group16_sha512.name();
    let c25519 = fn_algo_curve25519_sha256.name();

    // The census the detection relies on: exactly one curve25519 (rekey KEX slot), zero group16.
    let base_c = seed.count_functions_by_name(c25519);
    let base_g = seed.count_functions_by_name(g16);
    let total_fns = seed.count_functions(); // T: number of function-symbol (Application) nodes
    println!("seed: {total_fns} function nodes; curve25519={base_c}, group16={base_g}");
    assert_eq!(
        base_c, 1,
        "expected exactly one curve25519 (the rekey KEX leaf)"
    );
    assert_eq!(base_g, 0, "group16 must not be in the honest seed");

    let config = MutationConfig {
        with_dy: true,
        with_bit_level: false,
        with_focus: false,
        ..MutationConfig::default()
    };
    let signature = <SshProtocolTypes as ProtocolTypes>::signature();
    // AlgoName replacement pool size, for the analytic prediction: nullary signature functions
    // whose return type matches curve25519's (ReplaceMatch picks uniformly among these).
    let algoname_ty = signature
        .functions
        .iter()
        .find(|(s, _)| s.name == c25519)
        .map(|(s, _)| s.return_type.clone())
        .expect("curve25519 must be in the signature");
    let n_algoname: usize = signature
        .functions
        .iter()
        .filter(|(s, _)| s.is_constant() && s.return_type == algoname_ty)
        .count();

    let mut mutator = ReplaceMatchMutator::<SshState, SshProtocolTypes>::new(config, signature);
    let mut state = create_state(0xC0FFEE);

    let n: u64 = std::env::var("Q5_TRIES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3_000_000);

    let (mut mutated_ok, mut synth_anywhere, mut kex_changed, mut wanted) =
        (0u64, 0u64, 0u64, 0u64);
    // "while loop until we hit the wanted one", sampled: record the mutation index of each wanted
    // hit.
    let mut wanted_hit_indices: Vec<u64> = Vec::new();
    for i in 0..n {
        let mut m = seed.clone();
        if let Ok(MutationResult::Mutated) = mutator.mutate(&mut state, &mut m) {
            mutated_ok += 1;
        }
        let nc = m.count_functions_by_name(c25519);
        let ng = m.count_functions_by_name(g16);
        if ng >= 1 {
            synth_anywhere += 1;
        }
        if nc == 0 {
            kex_changed += 1;
        }
        if nc == 0 && ng == 1 {
            wanted += 1;
            if wanted_hit_indices.len() < 12 {
                wanted_hit_indices.push(i);
            }
        }
    }

    let p = |hits: u64| hits as f64 / n as f64;
    let e = |hits: u64| {
        if hits == 0 {
            f64::INFINITY
        } else {
            n as f64 / hits as f64
        }
    };
    println!("\n==== CVE-2021-3634 Q5: ReplaceMatch-only, {n} fresh-seed applications ====");
    println!("AlgoName replacement pool (type-mates of curve25519): {n_algoname}");
    println!(
        "mutate->Mutated: {mutated_ok} ({:.1}%)",
        100.0 * p(mutated_ok)
    );
    println!(
        "group16 synthesized ANYWHERE:  hits={synth_anywhere}  P={:.3e}  E[muts]={:.0}",
        p(synth_anywhere),
        e(synth_anywhere)
    );
    println!(
        "rekey-KEX leaf replaced (any):  hits={kex_changed}  P={:.3e}  E[muts]={:.0}",
        p(kex_changed),
        e(kex_changed)
    );
    println!(
        "WANTED (KEX leaf -> group16):   hits={wanted}  P={:.3e}  E[muts]={:.0}",
        p(wanted),
        e(wanted)
    );
    println!(
        "analytic prediction: P(wanted) ~= (1/{total_fns})*(1/{}) = {:.3e}  E[muts] ~= {:.0}",
        n_algoname.saturating_sub(1).max(1),
        (1.0 / total_fns as f64) * (1.0 / (n_algoname.saturating_sub(1).max(1)) as f64),
        total_fns as f64 * (n_algoname.saturating_sub(1).max(1)) as f64
    );
    if !wanted_hit_indices.is_empty() {
        // Gaps between successive wanted hits = sampled "mutations until the next wanted one".
        let gaps: Vec<u64> = wanted_hit_indices.windows(2).map(|w| w[1] - w[0]).collect();
        println!("first wanted-hit mutation indices: {wanted_hit_indices:?}");
        println!("gaps between successive wanted hits (mutations-until-next): {gaps:?}");
    }

    assert!(
        wanted > 0 || n < 50_000,
        "no wanted swap in {n} ReplaceMatch applications — investigate term constraints"
    );
}

/// Execution-based crash detector (mirrors the tlspuffin `ForkedRunner` / `ExecutionStatus::Crashed`
/// template): apply ONE mutation of operator `m` to a fresh clone of `seed`, run the mutant against
/// the vulnerable PUT in a forked child, and count real ASan crashes. Unlike a symbol-count census
/// this is correct for EVERY operator — including `SwapMutator` (which only reorders, so counts are
/// unchanged) and `RemoveAndLiftMutator` (which drops a subterm) — because it asks the ground-truth
/// question "did libssh over-read in `ssh_packet_set_newkeys`?" directly.
fn measure_operator<M>(
    label: &str,
    mut m: M,
    seed: &Trace<SshProtocolTypes>,
    runner: &Runner<SshProtocolBehavior>,
    state: &mut SshState,
    n: u64,
    timeout: std::time::Duration,
) where
    M: Mutator<Trace<SshProtocolTypes>, SshState>,
{
    let (mut applied, mut crashed, mut failed, mut other) = (0u64, 0u64, 0u64, 0u64);
    for _ in 0..n {
        let mut mutant = seed.clone();
        if !matches!(m.mutate(state, &mut mutant), Ok(MutationResult::Mutated)) {
            continue; // Skipped / no-op application
        }
        applied += 1;
        let fr = ForkedRunner::new(runner).with_timeout(timeout);
        match fr.execute(&mutant, &mut 0) {
            Ok(ExecutionStatus::Crashed) => crashed += 1,
            Ok(ExecutionStatus::Failure(_)) => failed += 1, // malformed/invalid trace
            _ => other += 1,                                 // Success / Timeout / Interrupted
        }
    }
    let p = crashed as f64 / n as f64;
    let e = if crashed == 0 {
        f64::INFINITY
    } else {
        n as f64 / crashed as f64
    };
    println!(
        "{label}: applied={applied}/{n}  crashed={crashed} failed={failed} other={other}  \
         P(crash)={p:.3e}  E[muts]={e:.0}"
    );
}

/// Q5 experiment — proposed improvement #2 (autonomous-safe, `sshpuffin/`-only): does enriching the
/// honest rekey seed so its rekey KEXINIT offers `[curve25519, group16]` (server still picks
/// curve25519 → honest completion, no crash) make CVE-2021-3634 reachable by the CHEAP operators,
/// and by how much? Baseline: on the plain curve25519 seed only `ReplaceMatchMutator` can reach it,
/// at E ≈ 12,500 (see `quantify_mutations_to_group16_swap`). Here we measure, by real execution, the
/// per-operator crash rate on the enriched seed.
///
/// Run: `cargo test -p sshpuffin --test reachability_cve_2021_3634 \
///         quantify_operators_on_g16_fallback_seed -- --ignored --nocapture`
/// (needs a built libssh 0.9.5 ASan vendor; Q5_TRIES overrides the per-operator trial count).
#[test]
#[ignore] // execution harness; run explicitly with --ignored --nocapture
fn quantify_operators_on_g16_fallback_seed() {
    let server = AgentName::first().next();
    let seed = seed_client_attacker_rekey_g16_fallback(server);

    let c25519 = fn_algo_curve25519_sha256.name();
    let g16 = fn_algo_dh_group16_sha512.name();
    println!(
        "g16-fallback seed: {} fn nodes; curve25519={}, group16={} (group16 is the non-selected fallback)",
        seed.count_functions(),
        seed.count_functions_by_name(c25519),
        seed.count_functions_by_name(g16),
    );
    assert_eq!(seed.count_functions_by_name(c25519), 1, "one curve25519 (the selected rekey KEX)");
    assert_eq!(seed.count_functions_by_name(g16), 1, "one group16 (the in-trace fallback)");

    let mut registry = ssh_registry();
    registry
        .set_default_factory(PUT)
        .unwrap_or_else(|e| panic!("PUT {PUT} not registered: {e}"));
    let spawner = Spawner::new(registry.clone());
    let runner = Runner::new(registry, spawner);

    let timeout = std::time::Duration::from_secs(8);

    // (0) Sanity: the enriched seed must itself COMPLETE HONESTLY (negotiate curve25519 → 32-byte
    // digest → no digest-size mismatch), otherwise it would be a crash witness, not an honest seed.
    let base = {
        let fr = ForkedRunner::new(&runner).with_timeout(timeout);
        fr.execute(&seed, &mut 0).expect("fork the enriched seed")
    };
    println!("enriched seed executes as: {base:?} (must NOT be Crashed)");
    assert!(
        !matches!(base, ExecutionStatus::Crashed),
        "enriched g16-fallback seed must complete honestly (negotiates curve25519), got Crashed"
    );

    let config = MutationConfig {
        with_dy: true,
        with_bit_level: false,
        with_focus: false,
        ..MutationConfig::default()
    };
    let signature = <SshProtocolTypes as ProtocolTypes>::signature();
    let tc = config.term_constraints;
    // Q5_SEED lets independent parallel processes explore different mutation sequences (for pooling
    // crash counts); Q5_OP restricts to one operator ("reuse"/"swap"/"match"/"lift"/"all").
    let rng_seed: u64 = std::env::var("Q5_SEED")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0xC0FFEE);
    let op = std::env::var("Q5_OP").unwrap_or_else(|_| "all".to_string());
    let want = |o: &str| op == "all" || op == o;
    let mut state = create_state(rng_seed);

    let n: u64 = std::env::var("Q5_TRIES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5_000);

    println!(
        "\n==== CVE-2021-3634 Q5: per-operator CRASH reachability (execution) on the g16-fallback seed, {n} trials, seed={rng_seed:#x}, op={op} ===="
    );
    // Can reach the crash only when it copies the in-trace group16 leaf (not some other algo) onto
    // the curve25519 kex leaf → [group16, …] → group16 negotiated. Overwriting with a non-kex algo
    // does NOT crash (the server does not fall through to group16), so the true crash rate is far
    // below the count-census — this execution measurement is the ground truth.
    if want("reuse") {
        measure_operator(
            "ReplaceReuse ",
            ReplaceReuseMutator::<SshState>::new(config),
            &seed, &runner, &mut state, n, timeout,
        );
    }
    // Reorders the rekey kex list to [group16, curve25519] → group16 negotiated. Count-blind: only
    // execution can see this crash.
    if want("swap") {
        measure_operator(
            "Swap         ",
            SwapMutator::<SshState>::new(tc, true),
            &seed, &runner, &mut state, n, timeout,
        );
    }
    // Expected NOT to reach it: on append(list1(curve25519), group16) the only same-type lift drops
    // group16, leaving [curve25519]. Measured to confirm the structural analysis.
    if want("lift") {
        measure_operator(
            "RemoveAndLift",
            RemoveAndLiftMutator::<SshState>::new(tc, true),
            &seed, &runner, &mut state, n, timeout,
        );
    }
    // Still works but must SYNTHESIZE group16 (1-of-21 type-mates) onto the kex leaf, ~ the baseline
    // E ≈ 12,500 — at small n this shows 0 crashes.
    if want("match") {
        measure_operator(
            "ReplaceMatch ",
            ReplaceMatchMutator::<SshState, SshProtocolTypes>::new(config, signature),
            &seed, &runner, &mut state, n, timeout,
        );
    }
}

/// Fast census detector (no PUT execution) for the g16-fallback seed. Tracks two predicates on the
/// mutant:
///   * `curve_gone`  = `curve25519==0 && group16>=1` — the curve leaf was overwritten by *something*.
///     NOTE this does NOT imply a crash: a non-group16 algo in the kex-first slot does not make the
///     server fall through to group16 (confirmed by execution), so this badly OVERCOUNTS.
///   * `g16_overwrote` = `curve25519==0 && group16>=2` — group16 *specifically* was copied/synthesised
///     onto the curve leaf → `[group16, group16]`, which DOES crash (see `diagnose_rekey_kex_shapes`).
///     This is the exact single-replacement crash census for `ReplaceReuse`/`ReplaceMatch`.
/// Comparing the two to the execution crash rate shows whether the operator reaches the crash STATE.
fn census_operator<M>(label: &str, mut m: M, seed: &Trace<SshProtocolTypes>, state: &mut SshState, n: u64)
where
    M: Mutator<Trace<SshProtocolTypes>, SshState>,
{
    let c25519 = fn_algo_curve25519_sha256.name();
    let g16 = fn_algo_dh_group16_sha512.name();
    let (mut applied, mut wanted, mut g16_over) = (0u64, 0u64, 0u64);
    for _ in 0..n {
        let mut mutant = seed.clone();
        if !matches!(m.mutate(state, &mut mutant), Ok(MutationResult::Mutated)) {
            continue;
        }
        applied += 1;
        let nc = mutant.count_functions_by_name(c25519);
        let ng = mutant.count_functions_by_name(g16);
        if nc == 0 && ng >= 1 {
            wanted += 1;
        }
        if nc == 0 && ng >= 2 {
            g16_over += 1; // group16 copied onto the curve leaf -> [group16, group16] -> crashes
        }
    }
    let pe = |h: u64| if h == 0 { f64::INFINITY } else { n as f64 / h as f64 };
    println!(
        "{label}: applied={applied}/{n}  curve_gone(overcount)={wanted} (E={:.0})  \
         g16_overwrote_curve(crash-state)={g16_over} (E={:.0})",
        pe(wanted),
        pe(g16_over)
    );
}

/// Q5 experiment (fast, symbol-count census): intended to quantify the g16-fallback reachability
/// GAIN. WARNING — the count census is an UNFAITHFUL crash oracle here: `curve_gone` over-counts
/// badly, and even the tighter `g16_overwrote_curve` crash-state does NOT execute-crash (all such
/// mutants are malformed — see `diagnose_census_crashstate_execution`). The ground-truth answer is
/// that improvement #2 yields 0 organic crashes; this test is retained to EXHIBIT the census/execution
/// gap, not to claim reachability. Trust `quantify_operators_on_g16_fallback_seed` (execution) instead.
///
/// Run: `cargo test -p sshpuffin --test reachability_cve_2021_3634 \
///         quantify_census_on_g16_fallback_seed -- --ignored --nocapture`
#[test]
#[ignore]
fn quantify_census_on_g16_fallback_seed() {
    let server = AgentName::first().next();
    let seed = seed_client_attacker_rekey_g16_fallback(server);
    let c25519 = fn_algo_curve25519_sha256.name();
    let g16 = fn_algo_dh_group16_sha512.name();
    let total = seed.count_functions();
    println!(
        "g16-fallback seed: {total} fn nodes; curve25519={}, group16={}",
        seed.count_functions_by_name(c25519),
        seed.count_functions_by_name(g16),
    );
    assert_eq!(seed.count_functions_by_name(c25519), 1);
    assert_eq!(seed.count_functions_by_name(g16), 1);

    let config = MutationConfig {
        with_dy: true,
        with_bit_level: false,
        with_focus: false,
        ..MutationConfig::default()
    };
    let signature = <SshProtocolTypes as ProtocolTypes>::signature();
    let mut state = create_state(0xC0FFEE);
    let n: u64 = std::env::var("Q5_TRIES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3_000_000);

    println!(
        "\n==== CVE-2021-3634 Q5: census crash reachability on the g16-fallback seed, {n} applications each ===="
    );
    // Previously IMPOSSIBLE (E=inf): copies the now-in-trace group16 onto the curve25519 kex leaf.
    census_operator(
        "ReplaceReuse (was E=inf)",
        ReplaceReuseMutator::<SshState>::new(config),
        &seed, &mut state, n,
    );
    // Still available; rate ~ the plain-seed baseline (must still synthesize group16 1-of-21).
    census_operator(
        "ReplaceMatch (base ~12500)",
        ReplaceMatchMutator::<SshState, SshProtocolTypes>::new(config, signature),
        &seed, &mut state, n,
    );
}

/// DIAGNOSTIC: resolve why random mutants show 0 crashes though the census says the group16 swap is
/// reached. Executes, through the SAME `ForkedRunner` path the per-operator test uses:
///   (A) the witness `seed_client_attacker_rekey_dh_group16` (group16 KEXINIT + proper `fn_kex_dh_init`)
///       — POSITIVE CONTROL, must be `Crashed` (if not, the harness/PUT is the problem, not the seed);
///   (B) `seed_probe_rekey_g16_ecdhmsg` (group16 KEXINIT but keeps `fn_kex_ecdh_init`) — the exact
///       "distance-1 from honest" trace the whole Q4 claim and improvement #2 depend on;
///   (C) the honest `seed_client_attacker_rekey_g16_fallback` — must NOT crash.
/// If (A)=Crashed and (B)!=Crashed, the single KEXINIT-name swap does NOT trigger — the crash needs the
/// exchange *message* to be a real group16 `fn_kex_dh_init`, so the true mutation distance is >= 2.
#[test]
#[ignore]
fn diagnose_g16_crash_paths() {
    let server = AgentName::first().next();
    let mut registry = ssh_registry();
    registry
        .set_default_factory(PUT)
        .unwrap_or_else(|e| panic!("PUT {PUT} not registered: {e}"));
    let spawner = Spawner::new(registry.clone());
    let runner = Runner::new(registry, spawner);
    let timeout = std::time::Duration::from_secs(10);

    let mut check = |label: &str, trace: &Trace<SshProtocolTypes>| {
        let fr = ForkedRunner::new(&runner).with_timeout(timeout);
        let st = fr.execute(trace, &mut 0);
        println!("DIAG {label}: {st:?}");
    };
    check(
        "(A) witness dh_group16 [group16 KEXINIT + fn_kex_dh_init]  EXPECT Crashed",
        &seed_client_attacker_rekey_dh_group16(server),
    );
    check(
        "(B) probe g16 KEXINIT + fn_kex_ecdh_init (distance-1 hypothesis)",
        &seed_probe_rekey_g16_ecdhmsg(server),
    );
    check(
        "(C) g16-fallback honest seed  EXPECT Success/not-Crashed",
        &seed_client_attacker_rekey_g16_fallback(server),
    );
}

/// DIAGNOSTIC 2: execute every rekey-kex list shape to pin down EXACTLY which one crashes, i.e. what
/// a single mutation on the g16-fallback seed must reach. `CurveThenG16` is the honest fallback seed;
/// `G16G16` is what `ReplaceReuse`/`ReplaceMatch` make when they overwrite the curve leaf with
/// group16; `G16ThenCurve` is what `Swap` makes. If those crash, the 0-crash execution result is a
/// mutation-probability problem; if they do NOT, look at ASAN_OPTIONS first.
/// RESOLVED 2026-11-24: the mutants ARE byte-identical to the crashing reference (differ_from_reference
/// = []); the `Failure(1)` was ASan's exit(1) without abort_on_error, not a malformed trace.
#[test]
#[ignore]
fn diagnose_rekey_kex_shapes() {
    let server = AgentName::first().next();
    let mut registry = ssh_registry();
    registry
        .set_default_factory(PUT)
        .unwrap_or_else(|e| panic!("PUT {PUT} not registered: {e}"));
    let spawner = Spawner::new(registry.clone());
    let runner = Runner::new(registry, spawner);
    let timeout = std::time::Duration::from_secs(10);

    for (label, mode) in [
        ("CurveOnly    [curve25519]            (honest baseline)", RekeyKexOffer::CurveOnly),
        ("CurveThenG16 [curve25519, group16]   (fallback seed)  ", RekeyKexOffer::CurveThenG16),
        ("G16ThenCurve [group16, curve25519]   (Swap result)    ", RekeyKexOffer::G16ThenCurve),
        ("G16G16       [group16, group16]      (Reuse/Match)    ", RekeyKexOffer::G16G16),
        ("G16Only      [group16]               (= probe B)      ", RekeyKexOffer::G16Only),
    ] {
        let fr = ForkedRunner::new(&runner).with_timeout(timeout);
        let st = fr.execute(&seed_client_attacker_rekey_kex(server, mode), &mut 0);
        println!("DIAG2 {label}: {st:?}");
    }
}

/// DIAGNOSTIC 3: the airtight reconciliation. Among `ReplaceReuse` mutants that satisfy the census
/// "crash-state" (`curve25519==0 && group16>=2`, i.e. group16 was copied onto the curve kex leaf),
/// EXECUTE each and report the status breakdown. If these do not actually crash, the symbol-count
/// census is proven to be an unfaithful crash oracle and improvement #2 does not yield organic
/// discovery despite the count proxy; execution is the ground truth.
#[test]
#[ignore]
fn diagnose_census_crashstate_execution() {
    let server = AgentName::first().next();
    let seed = seed_client_attacker_rekey_g16_fallback(server);
    let c25519 = fn_algo_curve25519_sha256.name();
    let g16 = fn_algo_dh_group16_sha512.name();

    let mut registry = ssh_registry();
    registry.set_default_factory(PUT).unwrap();
    let spawner = Spawner::new(registry.clone());
    let runner = Runner::new(registry, spawner);
    let timeout = std::time::Duration::from_secs(10);

    let config = MutationConfig {
        with_dy: true,
        with_bit_level: false,
        with_focus: false,
        ..MutationConfig::default()
    };
    let mut mutator = ReplaceReuseMutator::<SshState>::new(config);
    let mut state = create_state(0xC0FFEE);

    let target_samples: usize = std::env::var("Q5_SAMPLES").ok().and_then(|s| s.parse().ok()).unwrap_or(40);
    let (mut found, mut crashed, mut failed, mut success, mut other, mut tries) = (0usize, 0, 0, 0, 0, 0u64);
    while found < target_samples && tries < 5_000_000 {
        tries += 1;
        let mut m = seed.clone();
        if !matches!(mutator.mutate(&mut state, &mut m), Ok(MutationResult::Mutated)) {
            continue;
        }
        if m.count_functions_by_name(c25519) == 0 && m.count_functions_by_name(g16) >= 2 {
            found += 1;
            let fr = ForkedRunner::new(&runner).with_timeout(timeout);
            match fr.execute(&m, &mut 0) {
                Ok(ExecutionStatus::Crashed) => crashed += 1,
                Ok(ExecutionStatus::Failure(_)) => failed += 1,
                Ok(ExecutionStatus::Success) => success += 1,
                _ => other += 1,
            }
        }
    }
    println!(
        "DIAG3 ReplaceReuse census-crash-state mutants executed: found={found} (in {tries} tries)  \
         => crashed={crashed} failed={failed} success={success} other={other}"
    );
    println!(
        "DIAG3 verdict: {}",
        if crashed == 0 {
            "0 crashes — if ASAN_OPTIONS lacks abort_on_error this is the exit(1)/Failure(1) artifact, \
             NOT un-reachability; re-run with abort_on_error=1 (see module docs)"
        } else {
            "census-crash-state mutants really crash (expected with abort_on_error=1): #2 reaches the bug"
        }
    );
}

/// DIAGNOSTIC 4 (idea #4): WHY do the census crash-state `ReplaceReuse` mutants execute as `Failure`
/// while the hand-built `[group16, group16]` rekey trace crashes? By arithmetic (P(group16 source) ×
/// P(curve leaf target) ≈ 1/504 × 1/10 ≈ the measured E≈4.8k) they should BE that clean swap. This
/// dumps K of them plus the hand-built reference into `Q5_DUMP_DIR`, as Display text (to diff) and as
/// replayable `.trace` files (to get the exact rejection reason with `sshpuffin execute`), and reports
/// which steps differ from the seed and from the reference.
#[test]
#[ignore]
fn diagnose_malformed_splice() {
    use puffin::libafl::inputs::Input;

    let dir = std::env::var("Q5_DUMP_DIR").unwrap_or_else(|_| "/tmp/q5diag4".to_string());
    std::fs::create_dir_all(&dir).unwrap();
    let server = AgentName::first().next();
    let seed = seed_client_attacker_rekey_g16_fallback(server);
    let reference = seed_client_attacker_rekey_kex(server, RekeyKexOffer::G16G16);
    std::fs::write(format!("{dir}/reference_g16g16.txt"), format!("{reference}")).unwrap();
    reference.to_file(format!("{dir}/reference_g16g16.trace")).unwrap();
    std::fs::write(format!("{dir}/seed_fallback.txt"), format!("{seed}")).unwrap();
    seed.to_file(format!("{dir}/seed_fallback.trace")).unwrap();

    let c25519 = fn_algo_curve25519_sha256.name();
    let g16 = fn_algo_dh_group16_sha512.name();
    let config = MutationConfig {
        with_dy: true,
        with_bit_level: false,
        with_focus: false,
        ..MutationConfig::default()
    };
    let mut mutator = ReplaceReuseMutator::<SshState>::new(config);
    let mut state = create_state(0xC0FFEE);
    let k: usize = std::env::var("Q5_SAMPLES").ok().and_then(|s| s.parse().ok()).unwrap_or(5);

    let show = |t: &Trace<SshProtocolTypes>, i: usize| format!("{}", t.steps[i].action);
    let (mut found, mut tries) = (0usize, 0u64);
    while found < k && tries < 5_000_000 {
        tries += 1;
        let mut m = seed.clone();
        if !matches!(mutator.mutate(&mut state, &mut m), Ok(MutationResult::Mutated)) {
            continue;
        }
        if m.count_functions_by_name(c25519) == 0 && m.count_functions_by_name(g16) >= 2 {
            found += 1;
            let n = m.steps.len();
            let diff_seed: Vec<usize> = (0..n).filter(|&i| show(&m, i) != show(&seed, i)).collect();
            let diff_ref: Vec<usize> = (0..n.min(reference.steps.len()))
                .filter(|&i| show(&m, i) != show(&reference, i))
                .collect();
            println!(
                "DIAG4 mutant#{found} (try {tries}): steps={n} (ref {}) differ_from_seed={diff_seed:?} \
                 differ_from_reference={diff_ref:?}",
                reference.steps.len()
            );
            std::fs::write(format!("{dir}/mutant_{found}.txt"), format!("{m}")).unwrap();
            m.to_file(format!("{dir}/mutant_{found}.trace")).unwrap();
        }
    }
    println!("DIAG4 dumped {found} mutants (in {tries} tries) + reference/seed into {dir}");
}

/// DIAGNOSTIC 5 (idea #4, decisive): same harness, same logical mutant, three provenances —
/// in-memory (straight from the mutator), round-tripped (`deserialize(serialize(m))`) and loaded from
/// the `.trace` dumped by DIAG4 (same RNG seed → same mutants in the same order). If ONLY the
/// in-memory one fails, the mutator leaves state on the trace that serialization drops, i.e. the
/// fuzzer would execute something different from what it saves. `Debug` dumps (which may show what
/// `Display` hides) of mutant#1, its round-trip and the reference go to `Q5_DUMP_DIR`.
#[test]
#[ignore]
fn diagnose_inmemory_vs_roundtrip() {
    use puffin::libafl::inputs::Input;

    let dir = std::env::var("Q5_DUMP_DIR").unwrap_or_else(|_| "/tmp/q5diag4".to_string());
    let server = AgentName::first().next();
    let seed = seed_client_attacker_rekey_g16_fallback(server);
    let reference = seed_client_attacker_rekey_kex(server, RekeyKexOffer::G16G16);

    let mut registry = ssh_registry();
    registry.set_default_factory(PUT).unwrap();
    let spawner = Spawner::new(registry.clone());
    let runner = Runner::new(registry, spawner);
    let timeout = std::time::Duration::from_secs(10);
    let exec = |t: &Trace<SshProtocolTypes>| {
        let fr = ForkedRunner::new(&runner).with_timeout(timeout);
        fr.execute(t, &mut 0)
    };
    let rt = |t: &Trace<SshProtocolTypes>| {
        Trace::<SshProtocolTypes>::deserialize_postcard(&t.serialize_postcard().unwrap()).unwrap()
    };

    println!("DIAG5 reference  in-memory={:?}  round-trip={:?}", exec(&reference), exec(&rt(&reference)));

    let c25519 = fn_algo_curve25519_sha256.name();
    let g16 = fn_algo_dh_group16_sha512.name();
    let config = MutationConfig {
        with_dy: true,
        with_bit_level: false,
        with_focus: false,
        ..MutationConfig::default()
    };
    let mut mutator = ReplaceReuseMutator::<SshState>::new(config);
    let mut state = create_state(0xC0FFEE);
    let k: usize = std::env::var("Q5_SAMPLES").ok().and_then(|s| s.parse().ok()).unwrap_or(3);
    let (mut found, mut tries) = (0usize, 0u64);
    while found < k && tries < 5_000_000 {
        tries += 1;
        let mut m = seed.clone();
        if !matches!(mutator.mutate(&mut state, &mut m), Ok(MutationResult::Mutated)) {
            continue;
        }
        if m.count_functions_by_name(c25519) == 0 && m.count_functions_by_name(g16) >= 2 {
            found += 1;
            let m_rt = rt(&m);
            let from_file = Trace::<SshProtocolTypes>::from_file(format!("{dir}/mutant_{found}.trace"))
                .map(|t| exec(&t));
            println!(
                "DIAG5 mutant#{found} (try {tries}): in-memory={:?}  round-trip={:?}  from-file={:?}  \
                 debug(mem)==debug(round-trip): {}",
                exec(&m),
                exec(&m_rt),
                from_file,
                format!("{m:?}") == format!("{m_rt:?}")
            );
            if found == 1 {
                std::fs::write(format!("{dir}/mutant_1.debug"), format!("{m:#?}")).unwrap();
                std::fs::write(format!("{dir}/mutant_1_roundtrip.debug"), format!("{m_rt:#?}")).unwrap();
                std::fs::write(format!("{dir}/reference.debug"), format!("{reference:#?}")).unwrap();
            }
        }
    }
}
