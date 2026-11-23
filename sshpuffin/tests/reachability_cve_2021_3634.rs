//! Tier-2 Q5 (CVE-2021-3634) — quantify how many DY mutations the fuzzer needs to turn the honest
//! curve25519 rekey seed into the group16 rekey that triggers the heap overflow.
//!
//! Mirrors the tlspuffin reachability harness
//! (`tlspuffin/tests/vulnerabilities.rs::test_seed_only_mut_bitmut_cve_2022_38153`): a while/for
//! loop that rebuilds a *fresh* mutant from the seed and applies mutations, counting applications
//! until the wanted one lands. Here each mutant starts fresh from the on-path seed, so the
//! measurement is free of the two confounds that defeated the Q2/Q5 campaigns (coverage-guided
//! corpus self-dilution and the libafl LLMP early-exit).
//!
//! The crash-triggering mutation is a single STRUCTURAL symbol swap — `fn_algo_curve25519_sha256`
//! -> `fn_algo_dh_group16_sha512` on the rekey-KEXINIT kex name-list leaf — so the only mutator
//! that can produce it is `ReplaceMatchMutator` ("replace a function symbol with a type-compatible
//! one"). We run ONLY that mutator and count. Detection is by symbol census: the pristine seed has
//! exactly one `curve25519` (the rekey KEX slot) and zero `group16`, so after one ReplaceMatch,
//! `curve25519 == 0 && group16 == 1` means the KEX leaf became group16 — the wanted,
//! crash-triggering swap (its crash is proven separately by executing
//! `seed_probe_rekey_g16_ecdhmsg`).
//!
//! Run: `cargo test -p sshpuffin --test reachability_cve_2021_3634 -- --ignored --nocapture`
//! (needs a built libssh vendor; scope with VENDOR_DIR to libssh for a fast build).

#![cfg(has_libssh)]

use puffin::agent::AgentName;
use puffin::algebra::dynamic_function::DescribableFunction;
use puffin::fuzzer::mutations::{MutationConfig, ReplaceMatchMutator};
use puffin::libafl::corpus::InMemoryCorpus;
use puffin::libafl::mutators::{MutationResult, Mutator};
use puffin::libafl::prelude::StdState;
use puffin::libafl_bolts::bolts_prelude::{RomuDuoJrRand, StdRand};
use puffin::protocol::ProtocolTypes;
use puffin::trace::Trace;
use sshpuffin::protocol::SshProtocolTypes;
use sshpuffin::ssh::fn_impl::{fn_algo_curve25519_sha256, fn_algo_dh_group16_sha512};
use sshpuffin::ssh::seeds::seed_client_attacker_rekey;

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
