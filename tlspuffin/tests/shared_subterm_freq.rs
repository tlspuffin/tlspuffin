//! Measurement (design study, not a pass/fail test): how often do structurally-IDENTICAL,
//! variable-free, non-trivial sub-terms CO-OCCUR within a single trace?
//!
//! This decides the value of a "shared/linked payload" MakeMessage variant (bit-mutate a value at
//! ALL its occurrences for globally-consistent malformations). The win only exists if such
//! duplicate sub-terms are common; consistency enforced via variables/queries is NOT captured by
//! structural identity. Run: `cargo test -p tlspuffin --test shared_subterm_freq -- --nocapture`.

use std::collections::HashMap;

use puffin::algebra::{Term, TermType};
use puffin::trace::{Action, Trace};
use tlspuffin::protocol::TLSProtocolTypes;
use tlspuffin::put_registry::tls_registry;
use tlspuffin::tls::seeds::create_corpus;

/// A sub-term is "shareable" if it is non-trivial (size >= MIN_SIZE) and variable-free
/// (deterministic encoding -> identical term => identical bitstring, the sharing precondition).
const MIN_SIZE: usize = 2;

fn collect_shareable(recipe: &Term<TLSProtocolTypes>, out: &mut Vec<Term<TLSProtocolTypes>>) {
    for node in recipe.into_iter() {
        if node.size() >= MIN_SIZE && !node.has_variable() {
            out.push(node.clone());
        }
    }
}

/// Per trace: group shareable sub-terms by structural identity; a group of size >= 2 is a
/// "shareable class" (a value that occurs multiple times and could be linked).
fn analyze_trace(trace: &Trace<TLSProtocolTypes>) -> (usize, usize, usize, usize) {
    let mut nodes = Vec::new();
    for step in &trace.steps {
        if let Action::Input(input) = &step.action {
            collect_shareable(&input.recipe, &mut nodes);
        }
    }
    let mut classes: HashMap<Term<TLSProtocolTypes>, usize> = HashMap::new();
    for n in &nodes {
        *classes.entry(n.clone()).or_insert(0) += 1;
    }
    let shareable_classes = classes.values().filter(|&&c| c >= 2).count();
    let linked_positions: usize = classes.values().filter(|&&c| c >= 2).map(|&c| c).sum();
    let max_class = classes.values().copied().max().unwrap_or(0);
    (nodes.len(), shareable_classes, linked_positions, max_class)
}

#[test_log::test]
fn measure_shared_subterm_frequency() {
    let registry = tls_registry();
    let factory = registry.default();

    println!(
        "\n{:<42} | {:>9} | {:>9} | {:>9} | {:>9}",
        "seed trace", "shareable", "dup-class", "linked-pos", "max-class"
    );
    println!("{}", "-".repeat(92));

    let mut tot_traces = 0;
    let mut traces_with_dups = 0;
    let mut tot_classes = 0;
    let mut tot_linked = 0;
    for (trace, name) in create_corpus(factory) {
        let (shareable, classes, linked, maxc) = analyze_trace(&trace);
        tot_traces += 1;
        if classes > 0 {
            traces_with_dups += 1;
        }
        tot_classes += classes;
        tot_linked += linked;
        println!(
            "{:<42} | {:>9} | {:>9} | {:>9} | {:>9}",
            name, shareable, classes, linked, maxc
        );
    }
    println!("{}", "-".repeat(92));
    println!(
        "TOTALS: {} seed traces; {} have >=1 shareable dup-class ({:.0}%); {} dup-classes; {} linked positions; mean dup-classes/trace = {:.1}",
        tot_traces,
        traces_with_dups,
        100.0 * traces_with_dups as f64 / tot_traces.max(1) as f64,
        tot_classes,
        tot_linked,
        tot_classes as f64 / tot_traces.max(1) as f64,
    );
    println!(
        "INTERPRETATION: dup-class = a value (non-trivial, variable-free sub-term) occurring >=2x in one trace -> a shared-payload MakeMessage could bit-mutate it at all {} linked positions. High counts => the idea has frequent opportunities; near-zero => consistency is enforced via variables (not capturable by structural sharing).",
        tot_linked
    );
}
