use std::borrow::Cow;

use libafl::prelude::*;
use libafl_bolts::prelude::*;

use super::utils::{
    choose, choose_iter, choose_term, choose_term_filtered_mut, choose_term_path_filtered,
    find_all_sub_term_filtered, find_all_term_filtered, find_term, find_term_mut, reservoir_sample,
    Choosable, TermConstraints, TracePath,
};
use crate::algebra::atoms::Function;
use crate::algebra::signature::Signature;
use crate::algebra::{DYTerm, Subterms, Term, TermType};
use crate::fuzzer::term_zoo::TermZoo;
use crate::protocol::{ProtocolBehavior, ProtocolTypes};
use crate::put_registry::PutRegistry;
use crate::trace::{Action, Spawner, Trace, TraceContext};

#[derive(Clone, Copy, Debug)]
pub struct MutationConfig {
    pub fresh_zoo_after: u64,
    pub max_trace_length: usize,
    pub min_trace_length: usize,
    /// Below this term size we no longer mutate. Note that it is possible to reach
    /// smaller terms by having a mutation which removes all symbols in a single mutation.
    /// Above this term size we no longer mutate.
    pub term_constraints: TermConstraints,
    pub with_bit_level: bool,
    pub with_dy: bool,
    /// Focus on one payload at a time for a whole StdMutationalStage
    pub with_focus: bool,
    /// Relative weights for the scope at which a *replacement* mutation is applied, see
    /// [`ScopeWeights`] and [`MutationScope`].
    pub scope_weights: ScopeWeights,
}

impl Default for MutationConfig {
    //  TODO:EVAL: evaluate modif to this config
    fn default() -> Self {
        Self {
            fresh_zoo_after: 100000,
            max_trace_length: 15,
            min_trace_length: 2,
            term_constraints: TermConstraints::default(),
            with_bit_level: false,
            with_dy: true,
            with_focus: true,
            scope_weights: ScopeWeights::default(),
        }
    }
}

/// Relative weights for picking a [`MutationScope`] when applying a replacement mutation.
///
/// Setting them allows ablation studies and reproducing historical behaviours:
/// - `(1, 1, 1)` (default): uniform global / step / individual,
/// - `(1, 0, 1)`: the previous behaviour (global with probability 1/2, else individual),
/// - `(0, 0, 1)`: purely individual replacements (behaviour before global mutations existed).
#[derive(Clone, Copy, Debug)]
pub struct ScopeWeights {
    pub global: usize,
    pub step: usize,
    pub individual: usize,
}

impl Default for ScopeWeights {
    fn default() -> Self {
        Self {
            global: 1,
            step: 1,
            individual: 1,
        }
    }
}

impl ScopeWeights {
    #[must_use]
    pub const fn new(global: usize, step: usize, individual: usize) -> Self {
        Self {
            global,
            step,
            individual,
        }
    }

    /// Saturating, so that absurdly large weights keep a meaningful (if degenerate) distribution
    /// instead of overflowing: the dominant weight simply wins.
    const fn total(self) -> usize {
        self.global
            .saturating_add(self.step)
            .saturating_add(self.individual)
    }
}

/// Scope over which a chosen replacement is applied, see [`apply_scoped_mutation`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MutationScope {
    /// Replace *every* occurrence structurally equal to the chosen term, in the whole trace.
    Global,
    /// Replace every such occurrence, but only within the step of the chosen term.
    Step,
    /// Replace only the single chosen occurrence.
    Individual,
}

impl MutationScope {
    /// Draw a scope at random according to `weights`. Falls back to [`Self::Individual`] when all
    /// weights are zero.
    fn choose<R: Rand>(weights: ScopeWeights, rand: &mut R) -> Self {
        let total = weights.total();
        if total == 0 {
            return Self::Individual;
        }
        let draw = rand.between(0, total - 1);
        if draw < weights.global {
            Self::Global
        } else if draw < weights.global.saturating_add(weights.step) {
            Self::Step
        } else {
            Self::Individual
        }
    }
}

/// Apply `new_term` in place of the term at `to_mutate_path`, generalising the replacement to
/// structurally equal terms according to a randomly drawn [`MutationScope`].
///
/// This is the shared engine behind the *replacement* DY mutators (generate / replace-match /
/// replace-reuse): they all have the shape "pick a sub-term, compute a replacement for it, write it
/// back", so broadcasting that replacement to the other occurrences of the *same* term is
/// well-defined. Doing so collapses the cost of goals that require the same edit in several places
/// (e.g. turning every `fn_seq_2` of one action into `fn_seq_5`) from one lucky draw *per
/// occurrence* down to one lucky draw *per distinct sub-term*.
///
/// The generalisation is deliberately performed without any term constraint, including the
/// `max_term_size_explore` cutoff that bounds the *selection* of a term to mutate. Skipping a large
/// recipe here would silently turn "replace all occurrences" into a partial replacement, which is
/// precisely what a broader scope is meant to avoid; and the cost stays linear in the size of the
/// trace, i.e. the same order as the selection pass that already ran.
///
/// The chosen occurrence is always part of the targets, so that a broader scope is a strict
/// superset of [`MutationScope::Individual`] whatever the search returns.
// TODO: middle-ground scope: instead of the whole trace or the whole step, pick a position between
// the chosen term and the root of the recipe and replace all occurrences of the chosen term in that
// sub-term only.
pub fn apply_scoped_mutation<PT: ProtocolTypes, R: Rand>(
    trace: &mut Trace<PT>,
    to_mutate_path: &TracePath,
    representative: &Term<PT>,
    new_term: &Term<PT>,
    weights: ScopeWeights,
    rand: &mut R,
) -> MutationResult {
    let targets = scoped_targets(trace, to_mutate_path, representative, weights, rand);
    apply_to_targets(trace, &targets, new_term)
}

/// Replace the term at each of `targets` by `new_term`, see [`scoped_targets`].
pub fn apply_to_targets<PT: ProtocolTypes>(
    trace: &mut Trace<PT>,
    targets: &[TracePath],
    new_term: &Term<PT>,
) -> MutationResult {
    let mut mutated = false;
    for target in targets {
        if let Some(term_mut) = find_term_mut(trace, target) {
            term_mut.mutate(new_term.clone());
            mutated = true;
        }
    }

    if mutated {
        MutationResult::Mutated
    } else {
        MutationResult::Skipped
    }
}

/// Draw a [`MutationScope`] and return the occurrences to replace, see [`apply_scoped_mutation`].
///
/// This is exposed separately from [`apply_to_targets`] so that a caller can inspect *how many*
/// occurrences would be replaced before committing to the mutation: [`ReplaceReuseMutator`] needs
/// it to bound the number of payloads it introduces.
pub fn scoped_targets<PT: ProtocolTypes, R: Rand>(
    trace: &Trace<PT>,
    to_mutate_path: &TracePath,
    representative: &Term<PT>,
    weights: ScopeWeights,
    rand: &mut R,
) -> Vec<TracePath> {
    scoped_targets_with_cutoff(
        trace,
        to_mutate_path,
        representative,
        weights,
        rand,
        // no cutoff: we want *all* the occurrences, see the note above
        usize::MAX,
    )
}

/// [`scoped_targets`] with an explicit `max_term_size_explore` cutoff, so that tests can exercise
/// the case where the search for the other occurrences gives up.
fn scoped_targets_with_cutoff<PT: ProtocolTypes, R: Rand>(
    trace: &Trace<PT>,
    to_mutate_path: &TracePath,
    representative: &Term<PT>,
    weights: ScopeWeights,
    rand: &mut R,
    max_term_size_explore: usize,
) -> Vec<TracePath> {
    let scope = MutationScope::choose(weights, rand);
    let (chosen_step, _) = to_mutate_path;

    // the type shape is only compared first to speed up the comparison
    let filter = |term: &Term<PT>| {
        term.get_type_shape() == representative.get_type_shape() && term == representative
    };
    let constraints = TermConstraints {
        max_term_size_explore,
        ..TermConstraints::no_constraint()
    };

    let mut targets: Vec<TracePath> = match scope {
        // no search needed, the chosen occurrence is added below
        MutationScope::Individual => vec![],
        // only the recipe of the chosen step is explored, rather than filtering the whole trace
        MutationScope::Step => match trace.steps.get(*chosen_step).map(|step| &step.action) {
            Some(Action::Input(input)) => {
                find_all_sub_term_filtered(&input.recipe, filter, &constraints)
                    .into_iter()
                    .map(|term_path| (*chosen_step, term_path))
                    .collect()
            }
            _ => vec![],
        },
        MutationScope::Global => find_all_term_filtered(trace, filter, &constraints),
    };
    // the chosen occurrence is added last, make sure it is not replaced twice
    targets.retain(|path| path != to_mutate_path);
    targets.push(to_mutate_path.clone());

    log::debug!(
        "[Mutation] scope {scope:?} selected {} occurrence(s)",
        targets.len()
    );
    targets
}

impl MutationConfig {
    pub fn default_with_bit() -> Self {
        MutationConfig {
            with_bit_level: true,
            with_focus: false,
            ..Self::default()
        }
    }
}
pub type DyMutations<'harness, PT, PB, S> = tuple_list_type!(
// DY mutations
    RepeatMutator<S>,
    SkipMutator<S>,
    ReplaceReuseMutator<S>,
    ReplaceMatchMutator<S, PT>,
    RemoveAndLiftMutator<S>,
    GenerateMutator<'harness, S, PB>,
    SwapMutator<S>,
);

#[must_use]
pub fn dy_mutations<'harness, S, PT: ProtocolTypes, PB>(
    mutation_config: MutationConfig,
    signature: &'static Signature<PT>,
    put_registry: &'harness PutRegistry<PB>,
) -> DyMutations<'harness, PT, PB, S>
where
    S: HasCorpus<Trace<PT>> + HasMetadata + HasMaxSize + HasRand,
    PB: ProtocolBehavior<ProtocolTypes = PT>,
{
    let MutationConfig {
        fresh_zoo_after,
        max_trace_length,
        min_trace_length,
        term_constraints,
        with_dy,
        with_bit_level,
        scope_weights,
        ..
    } = mutation_config;

    tuple_list!(
        RepeatMutator::new(max_trace_length, with_dy),
        SkipMutator::new(min_trace_length, with_dy),
        ReplaceReuseMutator::new(term_constraints, with_dy, with_bit_level, scope_weights),
        ReplaceMatchMutator::new(term_constraints, signature, with_dy, scope_weights),
        RemoveAndLiftMutator::new(term_constraints, with_dy),
        GenerateMutator::new(
            0,
            fresh_zoo_after,
            term_constraints,
            None,
            signature,
            put_registry,
            with_dy,
            scope_weights
        ), /* Refresh zoo after 100000M mutations */
        SwapMutator::new(term_constraints, with_dy),
    )
}

/// SWAP: Swaps a sub-term with a different sub-term which is part of the trace

/// (such that types match).
///
/// Note: this mutation is deliberately *not* scoped (see [`MutationScope`]): it exchanges two
/// sub-terms, so "replace all equal occurrences" has no single well-defined replacement.
// TODO: we might later give it its own scoped variant: swap *all* occurrences of A with *all*
// occurrences of B (with probability 1/3), or only within the current step (with probability 1/3).
pub struct SwapMutator<S>
where
    S: HasRand,
{
    constraints: TermConstraints,
    phantom_s: std::marker::PhantomData<S>,
    with_dy: bool,
}

impl<S> SwapMutator<S>
where
    S: HasRand,
{
    #[must_use]
    pub const fn new(constraints: TermConstraints, with_dy: bool) -> Self {
        Self {
            constraints,
            phantom_s: std::marker::PhantomData,
            with_dy,
        }
    }
}

impl<S, PT: ProtocolTypes> Mutator<Trace<PT>, S> for SwapMutator<S>
where
    S: HasRand,
{
    fn mutate(&mut self, state: &mut S, trace: &mut Trace<PT>) -> Result<MutationResult, Error> {
        log::debug!("[DY] Start mutate with {}", self.name());
        if !self.with_dy {
            return Ok(MutationResult::Skipped);
        }
        let _a = BytesInsertMutator;
        let rand = state.rand_mut();
        if let Some((term_a, trace_path_a)) = choose(trace, &self.constraints, rand) {
            if let Some(trace_path_b) = choose_term_path_filtered(
                trace,
                |term: &Term<PT>| term.get_type_shape() == term_a.get_type_shape(),
                &self.constraints,
                rand,
            ) {
                let term_a_cloned = term_a.clone();
                if let Some(term_b_mut) = find_term_mut(trace, &trace_path_b) {
                    log::debug!(
                        "[Mutation] Mutate SwapMutator on terms\n{} and\n {}",
                        term_a_cloned,
                        term_b_mut
                    );
                    let term_b_cloned = term_b_mut.clone();
                    term_b_mut.mutate(term_a_cloned);
                    if let Some(trace_a_mut) = find_term_mut(trace, &trace_path_a) {
                        trace_a_mut.mutate(term_b_cloned);
                    }
                    return Ok(MutationResult::Mutated);
                }
            }
        }
        log::debug!("       Skipped {}", self.name());
        Ok(MutationResult::Skipped)
    }

    fn post_exec(&mut self, _state: &mut S, _new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}
impl<S> Named for SwapMutator<S>
where
    S: HasRand,
{
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("SwapMutator")
    }
}

/// REMOVE AND LIFT: Removes a sub-term from a term and attaches orphaned children to the parent

/// (such that types match). This only works if there is only a single child.
///
/// Note: this mutation is deliberately *not* scoped (see [`MutationScope`]): the replacement is a
/// grand-sub-term of the mutated term, i.e. position-dependent, so there is no single replacement
/// to broadcast.
// TODO: a scoped variant would instead apply the *same transformation* to all terms (which are
// `make_list` terms) that are equal to the impacted term *before* the RemoveAndLift.
// Note: this mutation will eventually be removed in favour of more scoped list-only mutations.
pub struct RemoveAndLiftMutator<S>
where
    S: HasRand,
{
    constraints: TermConstraints,
    phantom_s: std::marker::PhantomData<S>,
    with_dy: bool,
}

impl<S> RemoveAndLiftMutator<S>
where
    S: HasRand,
{
    #[must_use]
    pub const fn new(constraints: TermConstraints, with_dy: bool) -> Self {
        Self {
            constraints,
            phantom_s: std::marker::PhantomData,
            with_dy,
        }
    }
}

impl<S, PT: ProtocolTypes> Mutator<Trace<PT>, S> for RemoveAndLiftMutator<S>
where
    S: HasRand,
{
    fn mutate(&mut self, state: &mut S, trace: &mut Trace<PT>) -> Result<MutationResult, Error> {
        log::debug!("[DY] Start mutate with {}", self.name());
        if !self.with_dy {
            return Ok(MutationResult::Skipped);
        }
        let rand = state.rand_mut();
        let filter = |term: &Term<PT>| {
            term.is_symbolic() && // exclude terms with payloads since we aim to modify its internal structure
            match &term.term {
                DYTerm::Variable(_) => false,
                DYTerm::Application(_, subterms) =>
                    {
                        subterms
                            .find_subterm(|subterm| match &subterm.term {
                                DYTerm::Variable(_) => false,
                                DYTerm::Application(_, grand_subterms) => {
                                    grand_subterms.find_subterm_same_shape(subterm).is_some()
                                }
                            })
                            .is_some()
                    }
            }
        };
        if let Some(to_mutate) = choose_term_filtered_mut(trace, filter, &self.constraints, rand) {
            log::debug!(
                "[Mutation] Mutate RemoveAndLiftMutator on term\n{}",
                to_mutate
            );
            match &mut to_mutate.term {
                // TODO-bitlevel: maybe also SKIP if not(to_mutate.is_symbolic())
                DYTerm::Variable(_) => {
                    log::debug!("       Skipped {}", self.name());
                    Ok(MutationResult::Skipped)
                }
                DYTerm::Application(_, ref mut subterms) => {
                    if let Some(((subterm_index, _), grand_subterm)) = choose_iter(
                        subterms.filter_grand_subterms(|subterm, grand_subterm| {
                            subterm.get_type_shape() == grand_subterm.get_type_shape()
                        }),
                        rand,
                    ) {
                        let grand_subterm_cloned = grand_subterm.clone();
                        subterms.push(grand_subterm_cloned);
                        subterms.swap_remove(subterm_index);
                        return Ok(MutationResult::Mutated);
                    }
                    log::debug!("       Skipped {}", self.name());
                    Ok(MutationResult::Skipped)
                }
            }
        } else {
            log::debug!("       Skipped {}", self.name());
            Ok(MutationResult::Skipped)
        }
    }

    fn post_exec(&mut self, _state: &mut S, _new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}

impl<S> Named for RemoveAndLiftMutator<S>
where
    S: HasRand,
{
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("RemoveAndLiftMutator")
    }
}

/// REPLACE-MATCH: Replaces a function symbol with a different one (such that types match).
///
/// An example would be to replace a constant with another constant or the binary function
/// `fn_add` with `fn_sub`.
/// It can also replace any variable with a constant.
pub struct ReplaceMatchMutator<S, PT: ProtocolTypes>
where
    S: HasRand,
{
    constraints: TermConstraints,
    signature: &'static Signature<PT>,
    phantom_s: std::marker::PhantomData<S>,
    with_dy: bool,
    scope_weights: ScopeWeights,
}

impl<S, PT: ProtocolTypes> ReplaceMatchMutator<S, PT>
where
    S: HasRand,
{
    #[must_use]
    pub const fn new(
        constraints: TermConstraints,
        signature: &'static Signature<PT>,
        with_dy: bool,
        scope_weights: ScopeWeights,
    ) -> Self {
        Self {
            constraints: TermConstraints {
                must_be_symbolic: true, // forbid replacing function symbols in terms with payloads
                ..constraints
            },
            signature,
            phantom_s: std::marker::PhantomData,
            with_dy,
            scope_weights,
        }
    }
}

impl<S, PT: ProtocolTypes> Mutator<Trace<PT>, S> for ReplaceMatchMutator<S, PT>
where
    S: HasRand,
{
    fn mutate(&mut self, state: &mut S, trace: &mut Trace<PT>) -> Result<MutationResult, Error> {
        log::debug!("[DY] Start mutate with {}", self.name());
        if !self.with_dy {
            return Ok(MutationResult::Skipped);
        }
        let rand = state.rand_mut();
        let Some(to_mutate_path) =
            choose_term_path_filtered(trace, |_| true, &self.constraints, rand)
        else {
            log::debug!("       Skipped {}", self.name());
            return Ok(MutationResult::Skipped);
        };
        let Some(to_mutate) = find_term(trace, &to_mutate_path).cloned() else {
            log::debug!("       Skipped {}", self.name());
            return Ok(MutationResult::Skipped);
        };
        log::debug!("[Mutation] ReplaceMatchMutator on term\n{}", to_mutate);

        // Build the fully-formed replacement, of the same type as the chosen term.
        let new_term = match &to_mutate.term {
            DYTerm::Variable(variable) => {
                let Some((shape, dynamic_fn)) = self.signature.functions.choose_filtered(
                    |(shape, _)| variable.typ == shape.return_type && shape.is_constant(),
                    rand,
                ) else {
                    log::debug!("       Skipped {}", self.name());
                    return Ok(MutationResult::Skipped);
                };
                Term::from(DYTerm::Application(
                    Function::new(shape.clone(), dynamic_fn.clone()),
                    Vec::new(),
                ))
            }
            DYTerm::Application(func, _) => {
                let Some((shape, dynamic_fn)) = self.signature.functions.choose_filtered(
                    |(shape, _)| {
                        func.shape() != shape
                            && func.shape().return_type == shape.return_type
                            && func.shape().argument_types == shape.argument_types
                    },
                    rand,
                ) else {
                    log::debug!("       Skipped {}", self.name());
                    return Ok(MutationResult::Skipped);
                };
                // Only the function symbol changes, the sub-terms are kept.
                let mut new_term = to_mutate.clone();
                if let DYTerm::Application(new_func, _) = &mut new_term.term {
                    new_func.change_function(shape.clone(), dynamic_fn.clone());
                }
                new_term
            }
        };

        Ok(apply_scoped_mutation(
            trace,
            &to_mutate_path,
            &to_mutate,
            &new_term,
            self.scope_weights,
            rand,
        ))
    }

    fn post_exec(&mut self, _state: &mut S, _new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}

impl<S, PT: ProtocolTypes> Named for ReplaceMatchMutator<S, PT>
where
    S: HasRand,
{
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("ReplaceMatchMutator")
    }
}

/// REPLACE-REUSE: Replaces a sub-term with a different sub-term which is part of the trace
/// (such that types match). The new sub-term could come from another step which has a different
/// recipe term.
pub struct ReplaceReuseMutator<S>
where
    S: HasRand,
{
    constraints: TermConstraints,
    phantom_s: std::marker::PhantomData<S>,
    with_dy: bool,
    with_bit: bool,
    scope_weights: ScopeWeights,
}

impl<S> ReplaceReuseMutator<S>
where
    S: HasRand,
{
    #[must_use]
    pub const fn new(
        constraints: TermConstraints,
        with_dy: bool,
        with_bit: bool,
        scope_weights: ScopeWeights,
    ) -> Self {
        Self {
            constraints,
            phantom_s: std::marker::PhantomData,
            with_dy,
            with_bit,
            scope_weights,
        }
    }
}

impl<S, PT: ProtocolTypes> Mutator<Trace<PT>, S> for ReplaceReuseMutator<S>
where
    S: HasRand,
{
    fn mutate(&mut self, state: &mut S, trace: &mut Trace<PT>) -> Result<MutationResult, Error> {
        log::debug!("[DY] Start mutate with {}", self.name());
        if !self.with_dy {
            return Ok(MutationResult::Skipped);
        }
        let rand = state.rand_mut();
        let (trace_nb_payloads, nb_terms) = if self.with_bit {
            (trace.all_payloads().len(), trace.steps.len())
        } else {
            (0, 0)
        };
        if let Some(replacement) = choose_term(trace, &self.constraints, rand).cloned() {
            if let Some(to_replace_path) = choose_term_path_filtered(
                trace,
                |term: &Term<PT>| term.get_type_shape() == replacement.get_type_shape(),
                &self.constraints,
                rand,
            ) {
                let Some(to_replace) = find_term(trace, &to_replace_path).cloned() else {
                    log::debug!("       Skipped {}", self.name());
                    return Ok(MutationResult::Skipped);
                };
                // the scope is drawn first: a broader scope replaces several occurrences, and each
                // of them contributes to the payload budget checked below
                let targets = scoped_targets(
                    trace,
                    &to_replace_path,
                    &to_replace,
                    self.scope_weights,
                    rand,
                );
                if self.with_bit {
                    let nb_payloads = trace_nb_payloads
                        + targets.len() * replacement.all_payloads().len()
                        - targets.len() * to_replace.all_payloads().len();
                    let no_more_new_payloads = nb_payloads / std::cmp::max(1, nb_terms)
                        > self.constraints.threshold_max_payloads_per_term;
                    if no_more_new_payloads {
                        log::debug!("[ReplaceReuseMutator] Skipped as the chosen replacement would yield too many payloads.");
                        log::debug!("       Skipped {}", self.name());
                        return Ok(MutationResult::Skipped);
                    }
                }
                log::debug!(
                    "[Mutation] Mutate ReplaceReuseMutator on terms\n {} and\n{}",
                    to_replace,
                    replacement
                );
                return Ok(apply_to_targets(trace, &targets, &replacement));
            }
        }
        log::debug!("       Skipped {}", self.name());
        Ok(MutationResult::Skipped)
    }

    fn post_exec(&mut self, _state: &mut S, _new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}

impl<S> Named for ReplaceReuseMutator<S>
where
    S: HasRand,
{
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("ReplaceReuseMutator")
    }
}

/// SKIP:  Removes an input step
pub struct SkipMutator<S>
where
    S: HasRand,
{
    min_trace_length: usize,
    phantom_s: std::marker::PhantomData<S>,
    with_dy: bool,
}

impl<S> SkipMutator<S>
where
    S: HasRand,
{
    #[must_use]
    pub const fn new(min_trace_length: usize, with_dy: bool) -> Self {
        Self {
            min_trace_length,
            phantom_s: std::marker::PhantomData,
            with_dy,
        }
    }
}
impl<S, PT: ProtocolTypes> Mutator<Trace<PT>, S> for SkipMutator<S>
where
    S: HasRand,
{
    fn mutate(&mut self, state: &mut S, trace: &mut Trace<PT>) -> Result<MutationResult, Error> {
        log::debug!("[DY] Start mutate with {}", self.name());
        if !self.with_dy {
            return Ok(MutationResult::Skipped);
        }
        let steps = &mut trace.steps;
        let length = steps.len();
        if length <= self.min_trace_length {
            log::debug!("       Skipped {}", self.name());
            return Ok(MutationResult::Skipped);
        }
        if length == 0 {
            log::debug!("       Skipped {}", self.name());
            return Ok(MutationResult::Skipped);
        }
        let remove_index = state.rand_mut().between(0, length - 1);
        log::debug!("[Mutation] Mutate SkipMutator on step {remove_index}");
        steps.remove(remove_index);
        Ok(MutationResult::Mutated)
    }

    fn post_exec(&mut self, _state: &mut S, _new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}
impl<S> Named for SkipMutator<S>
where
    S: HasRand,
{
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("SkipMutator")
    }
}

/// REPEAT: Repeats an input which is already part of the trace
pub struct RepeatMutator<S>
where
    S: HasRand,
{
    max_trace_length: usize,
    phantom_s: std::marker::PhantomData<S>,
    with_dy: bool,
}

impl<S> RepeatMutator<S>
where
    S: HasRand,
{
    #[must_use]
    pub const fn new(max_trace_length: usize, with_dy: bool) -> Self {
        Self {
            max_trace_length,
            phantom_s: std::marker::PhantomData,
            with_dy,
        }
    }
}
impl<S, PT: ProtocolTypes> Mutator<Trace<PT>, S> for RepeatMutator<S>
where
    S: HasRand,
{
    fn mutate(&mut self, state: &mut S, trace: &mut Trace<PT>) -> Result<MutationResult, Error> {
        log::debug!("[DY] Start mutate with {}", self.name());
        if !self.with_dy {
            return Ok(MutationResult::Skipped);
        }
        let steps = &trace.steps;
        let length = steps.len();
        if length >= self.max_trace_length {
            log::debug!("       Skipped {}", self.name());
            return Ok(MutationResult::Skipped);
        }
        if length == 0 {
            log::debug!("       Skipped {}", self.name());
            return Ok(MutationResult::Skipped);
        }
        let insert_index = state.rand_mut().between(0, length);
        let Some(step) = state.rand_mut().choose(steps) else {
            return Ok(MutationResult::Skipped);
        };
        log::debug!("[Mutation] Mutate RepeatMutator on step {insert_index}");
        trace.steps.insert(insert_index, step.clone());
        Ok(MutationResult::Mutated)
    }

    fn post_exec(&mut self, _state: &mut S, _new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}
impl<S> Named for RepeatMutator<S>
where
    S: HasRand,
{
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("RepeatMutator")
    }
}

/// GENERATE: Generates a previously-unseen term using a term zoo
pub struct GenerateMutator<'a, S, PB: ProtocolBehavior>
where
    S: HasRand,
{
    mutation_counter: u64,
    refresh_zoo_after: u64,
    constraints: TermConstraints,
    zoo: Option<TermZoo<PB>>,
    signature: &'static Signature<PB::ProtocolTypes>,
    put_registry: &'a PutRegistry<PB>,
    phantom_s: std::marker::PhantomData<S>,
    with_dy: bool,
    scope_weights: ScopeWeights,
}
impl<'a, S, PB: ProtocolBehavior> GenerateMutator<'a, S, PB>
where
    S: HasRand,
{
    #[must_use]
    pub const fn new(
        mutation_counter: u64,
        refresh_zoo_after: u64,
        constraints: TermConstraints,
        zoo: Option<TermZoo<PB>>,
        signature: &'static Signature<PB::ProtocolTypes>,
        put_registry: &'a PutRegistry<PB>,
        with_dy: bool,
        scope_weights: ScopeWeights,
    ) -> Self {
        Self {
            mutation_counter,
            refresh_zoo_after,
            constraints,
            zoo,
            signature,
            put_registry,
            phantom_s: std::marker::PhantomData,
            with_dy,
            scope_weights,
        }
    }
}
impl<'a, S, PB: ProtocolBehavior> Mutator<Trace<PB::ProtocolTypes>, S>
    for GenerateMutator<'a, S, PB>
where
    S: HasRand,
{
    fn mutate(
        &mut self,
        state: &mut S,
        trace: &mut Trace<PB::ProtocolTypes>,
    ) -> Result<MutationResult, Error> {
        log::debug!("[DY] Start mutate with {}", self.name());
        if !self.with_dy {
            return Ok(MutationResult::Skipped);
        }
        let rand = state.rand_mut();
        let (to_mutate_path, to_mutate, new_term) = {
            if let Some((to_mutate, to_mutate_path)) =
                reservoir_sample(trace, |_| true, &self.constraints, rand)
            {
                log::debug!("[Mutation] Mutate GenerateMutator on term\n{}", to_mutate);
                self.mutation_counter += 1;
                let zoo = if self.mutation_counter % self.refresh_zoo_after == 0 {
                    log::debug!("[Mutation] Mutate GenerateMutator: refresh zoo");
                    let spawner = Spawner::new(self.put_registry.clone());
                    let ctx = TraceContext::new(spawner); // zoo generate symbolic terms
                    self.zoo.insert(TermZoo::generate(
                        &ctx,
                        self.signature,
                        rand,
                        self.constraints.zoo_gen_how_many,
                        self.constraints.zoo_max_depth,
                    ))
                } else {
                    self.zoo.get_or_insert_with(|| {
                        let spawner = Spawner::new(self.put_registry.clone());
                        let ctx = TraceContext::new(spawner); // zoo generate symbolic terms
                        TermZoo::generate(
                            &ctx,
                            self.signature,
                            rand,
                            self.constraints.zoo_gen_how_many,
                            self.constraints.zoo_max_depth,
                        )
                    })
                };
                if let Some(new_term) = zoo.choose_filtered(
                    |term| {
                        // We seek for a different term with a matching type
                        to_mutate.get_type_shape() == term.get_type_shape() && *to_mutate != **term
                    },
                    rand,
                ) {
                    log::debug!(
                        "Found to_mutate and new_term: {}\n ----------------\n{}",
                        to_mutate,
                        new_term
                    );
                    // clone so that the immutable borrow of `trace` ends here
                    (to_mutate_path, to_mutate.clone(), new_term.clone())
                } else {
                    return Ok(MutationResult::Skipped);
                }
            } else {
                return Ok(MutationResult::Skipped);
            }
        };

        // Apply the replacement at a randomly drawn scope (global / step / individual)
        Ok(apply_scoped_mutation(
            trace,
            &to_mutate_path,
            &to_mutate,
            &new_term,
            self.scope_weights,
            rand,
        ))
    }

    fn post_exec(&mut self, _state: &mut S, _new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}

impl<'a, S, PB: ProtocolBehavior> Named for GenerateMutator<'a, S, PB>
where
    S: HasRand,
{
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("GenerateMutator")
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};

    use libafl::corpus::InMemoryCorpus;
    use libafl::mutators::{MutationResult, Mutator};
    use libafl::state::StdState;
    use libafl_bolts::rands::{RomuDuoJrRand, StdRand};

    use super::*;
    use crate::agent::AgentName;
    use crate::algebra::dynamic_function::DescribableFunction;
    use crate::algebra::test_signature::{TestTrace, *};
    use crate::algebra::DYTerm;
    use crate::fuzzer::utils::{choose_term_path, TracePath};
    use crate::term;
    use crate::trace::{Action, InputAction, Step};

    fn create_state(
    ) -> StdState<InMemoryCorpus<TestTrace>, TestTrace, RomuDuoJrRand, InMemoryCorpus<TestTrace>>
    {
        let rand = StdRand::with_seed(1235);
        let corpus: InMemoryCorpus<TestTrace> = InMemoryCorpus::new();
        StdState::new(rand, corpus, InMemoryCorpus::new(), &mut (), &mut ()).unwrap()
    }

    /// Checks whether repeat can repeat the last step
    #[test_log::test]
    fn test_repeat_mutator() {
        let mut state = create_state();

        let mut mutator = RepeatMutator::new(15, true);

        fn check_is_encrypt12(step: &Step<TestProtocolTypes>) -> bool {
            if let Action::Input(input) = &step.action {
                if input.recipe.name() == fn_encrypt12.name() {
                    return true;
                }
            }
            false
        }

        loop {
            let mut trace = setup_simple_trace();
            mutator.mutate(&mut state, &mut trace).unwrap();

            let length = trace.steps.len();
            if let Some(last) = trace.steps.get(length - 1) {
                if check_is_encrypt12(last) {
                    if let Some(step) = trace.steps.get(length - 2) {
                        if check_is_encrypt12(step) {
                            break;
                        }
                    }
                }
            }
        }
    }

    /// The defining behaviour of each scope, on a trace that contains the *same* sub-term several
    /// times inside one step and also in another step:
    /// - `Individual` replaces exactly the chosen occurrence,
    /// - `Step` replaces every occurrence of the chosen step, and only those,
    /// - `Global` replaces every occurrence of the whole trace.
    #[test_log::test]
    fn test_scope_extent() {
        let mut rand = StdRand::with_seed(11);

        // a term that appears 3 times in step 0 and 2 times in step 1
        let duplicated: Term<TestProtocolTypes> = term! { fn_signature_algorithm_extension };
        let recipe_a: Term<TestProtocolTypes> = term! {
            fn_client_extensions_append(
                (fn_client_extensions_append(
                    (fn_client_extensions_append(
                        fn_client_extensions_new,
                        fn_signature_algorithm_extension
                    )),
                    fn_signature_algorithm_extension
                )),
                fn_signature_algorithm_extension
            )
        };
        let recipe_b: Term<TestProtocolTypes> = term! {
            fn_client_extensions_append(
                (fn_client_extensions_append(
                    fn_client_extensions_new,
                    fn_signature_algorithm_extension
                )),
                fn_signature_algorithm_extension
            )
        };
        let build_trace = || Trace {
            steps: vec![
                Step {
                    agent: AgentName::first(),
                    action: Action::Input(InputAction {
                        recipe: recipe_a.clone(),
                        precomputations: vec![],
                    }),
                },
                Step {
                    agent: AgentName::first(),
                    action: Action::Input(InputAction {
                        recipe: recipe_b.clone(),
                        precomputations: vec![],
                    }),
                },
            ],
            ..setup_simple_trace()
        };
        let replacement: Term<TestProtocolTypes> = term! { fn_ec_point_formats_extension };

        // count the occurrences of `duplicated` left in each step
        let remaining = |trace: &Trace<TestProtocolTypes>| {
            (0..2)
                .map(|step| match &trace.steps[step].action {
                    Action::Input(input) => (&input.recipe)
                        .into_iter()
                        .filter(|t| **t == duplicated)
                        .count(),
                    Action::Output(_) => 0,
                })
                .collect::<Vec<_>>()
        };

        let chosen_path: TracePath = (0, vec![1]); // outermost duplicated term of step 0
        let sanity = build_trace();
        assert_eq!(remaining(&sanity), vec![3, 2], "test fixture");

        for (weights, expected, label) in [
            (ScopeWeights::new(0, 0, 1), vec![2, 2], "individual"),
            (ScopeWeights::new(0, 1, 0), vec![0, 2], "step"),
            (ScopeWeights::new(1, 0, 0), vec![0, 0], "global"),
        ] {
            let mut trace = build_trace();
            let targets = scoped_targets(&trace, &chosen_path, &duplicated, weights, &mut rand);
            assert_eq!(
                apply_to_targets(&mut trace, &targets, &replacement),
                MutationResult::Mutated,
                "{label}: should have mutated"
            );
            assert_eq!(
                remaining(&trace),
                expected,
                "{label}: unexpected extent of the replacement (per-step occurrences left)"
            );
        }
    }

    /// Whatever the scope, the *chosen* occurrence is always replaced. In particular a broader
    /// scope must not silently skip the mutation when the search for the other occurrences finds
    /// nothing, which happens for recipes above `max_term_size_explore`.
    #[test_log::test]
    fn test_scoped_mutation_always_mutates_chosen_occurrence() {
        let mut rand = StdRand::with_seed(7);

        for weights in [
            ScopeWeights::new(1, 0, 0), // global only
            ScopeWeights::new(0, 1, 0), // step only
            ScopeWeights::new(0, 0, 1), // individual only
            ScopeWeights::default(),
        ] {
            for max_term_size_explore in [usize::MAX, 0] {
                // `0` makes the search for the other occurrences give up immediately, emulating a
                // recipe that is too large to explore
                let mut trace = setup_simple_trace();
                let path = choose_term_path_filtered(
                    &trace,
                    |_| true,
                    &TermConstraints::default(),
                    &mut rand,
                )
                .unwrap();
                let chosen = find_term(&trace, &path).unwrap().clone();

                // any different term of the same type is a valid replacement here
                let Some(replacement) = trace
                    .steps
                    .iter()
                    .filter_map(|step| match &step.action {
                        Action::Input(input) => Some(&input.recipe),
                        Action::Output(_) => None,
                    })
                    .flat_map(|recipe| recipe.into_iter())
                    .find(|term| {
                        term.get_type_shape() == chosen.get_type_shape() && **term != chosen
                    })
                    .cloned()
                else {
                    continue; // no valid replacement in this trace, nothing to assert
                };

                let targets = scoped_targets_with_cutoff(
                    &trace,
                    &path,
                    &chosen,
                    weights,
                    &mut rand,
                    max_term_size_explore,
                );
                let result = apply_to_targets(&mut trace, &targets, &replacement);

                assert_eq!(
                    result,
                    MutationResult::Mutated,
                    "weights {weights:?} with cutoff {max_term_size_explore} should have mutated"
                );
                assert_eq!(
                    find_term(&trace, &path).unwrap(),
                    &replacement,
                    "weights {weights:?} with cutoff {max_term_size_explore}: the chosen \
                     occurrence must carry the replacement"
                );
            }
        }
    }

    /// The scope drawn by [`MutationScope::choose`] must follow the configured weights: a zeroed
    /// weight is never drawn, and `(0, 0, 0)` degrades gracefully to `Individual`.
    #[test_log::test]
    fn test_scope_weights() {
        let mut rand = StdRand::with_seed(42);

        let draw = |w: ScopeWeights, rand: &mut _| {
            let mut seen = std::collections::HashSet::new();
            for _ in 0..200 {
                seen.insert(MutationScope::choose(w, rand));
            }
            seen
        };

        // uniform: all three scopes must show up
        let all = draw(ScopeWeights::default(), &mut rand);
        assert_eq!(all.len(), 3, "uniform weights should draw all three scopes");

        // (1, 0, 1): the historical behaviour, never per-step
        let no_step = draw(ScopeWeights::new(1, 0, 1), &mut rand);
        assert!(!no_step.contains(&MutationScope::Step));
        assert!(no_step.contains(&MutationScope::Global));
        assert!(no_step.contains(&MutationScope::Individual));

        // (0, 0, 1): purely individual replacements
        let only_individual = draw(ScopeWeights::new(0, 0, 1), &mut rand);
        assert_eq!(only_individual, HashSet::from([MutationScope::Individual]));

        // degenerate weights fall back to Individual instead of panicking
        let zeroed = draw(ScopeWeights::new(0, 0, 0), &mut rand);
        assert_eq!(zeroed, HashSet::from([MutationScope::Individual]));
    }

    #[test_log::test]
    fn test_replace_match_mutator() {
        let _server = AgentName::first();
        let mut state = create_state();
        let mut mutator = ReplaceMatchMutator::new(
            TermConstraints::default(),
            &TEST_SIGNATURE,
            true,
            ScopeWeights::default(),
        );

        loop {
            let mut trace = setup_simple_trace();
            mutator.mutate(&mut state, &mut trace).unwrap();

            if let Some(last) = trace.steps.iter().last() {
                match &last.action {
                    Action::Input(input) => match &input.recipe.term {
                        DYTerm::Variable(_) => {}
                        DYTerm::Application(_, subterms) => {
                            if let Some(last_subterm) = subterms.iter().last() {
                                if last_subterm.name() == fn_seq_1.name() {
                                    break;
                                }
                            }
                        }
                    },
                    Action::Output(_) => {}
                }
            }
        }
    }

    #[test_log::test]
    fn test_remove_lift_mutator() {
        // Should remove an extension
        let mut state = create_state();
        let _server = AgentName::first();
        let mut mutator = RemoveAndLiftMutator::new(TermConstraints::default(), true);

        // Returns the amount of extensions in the trace
        fn sum_extension_appends(trace: &TestTrace) -> usize {
            trace.count_functions_by_name(fn_client_extensions_append.name())
        }

        loop {
            let mut trace = setup_simple_trace();
            let before_mutation = sum_extension_appends(&trace);
            let result = mutator.mutate(&mut state, &mut trace).unwrap();

            if result == MutationResult::Mutated {
                let after_mutation = sum_extension_appends(&trace);
                if after_mutation < before_mutation {
                    // extension removed
                    break;
                }
            }
        }
    }

    #[test_log::test]
    fn test_replace_reuse_mutator() {
        let mut state = create_state();
        let _server = AgentName::first();
        let mut mutator = ReplaceReuseMutator::new(
            TermConstraints::default(),
            true,
            true,
            ScopeWeights::default(),
        );

        fn count_client_hello(trace: &TestTrace) -> usize {
            trace.count_functions_by_name(fn_client_hello.name())
        }

        fn count_finished(trace: &TestTrace) -> usize {
            trace.count_functions_by_name(fn_finished.name())
        }

        loop {
            let mut trace = setup_simple_trace();
            let result = mutator.mutate(&mut state, &mut trace).unwrap();

            if result == MutationResult::Mutated {
                let client_hellos = count_client_hello(&trace);
                let finishes = count_finished(&trace);
                if client_hellos == 2 && finishes == 0 {
                    // finished replaced by client_hello
                    break;
                }
            }
        }
    }

    #[test_log::test]
    fn test_skip_mutator() {
        let mut state = create_state();
        let _server = AgentName::first();
        let mut mutator = SkipMutator::new(2, true);

        loop {
            let mut trace = setup_simple_trace();
            let before_len = trace.steps.len();
            mutator.mutate(&mut state, &mut trace).unwrap();

            if before_len - 1 == trace.steps.len() {
                break;
            }
        }
    }

    #[test_log::test]
    fn test_swap_mutator() {
        let mut state = create_state();
        let mut mutator = SwapMutator::new(TermConstraints::default(), true);

        loop {
            let mut trace = setup_simple_trace();
            mutator.mutate(&mut state, &mut trace).unwrap();

            let is_first_not_ch = if let Some(first) = trace.steps.first() {
                match &first.action {
                    Action::Input(input) => Some(input.recipe.name() != fn_client_hello.name()),
                    Action::Output(_) => None,
                }
            } else {
                None
            };

            let is_next_not_fn_client_key_exchange = if let Some(next) = trace.steps.get(1) {
                match &next.action {
                    Action::Input(input) => {
                        Some(input.recipe.name() != fn_client_key_exchange.name())
                    }
                    Action::Output(_) => None,
                }
            } else {
                None
            };

            if let Some(first) = is_first_not_ch {
                if let Some(second) = is_next_not_fn_client_key_exchange {
                    if first && second {
                        break;
                    }
                }
            }
        }
    }

    #[test_log::test]
    fn test_find_term() {
        let mut rand = StdRand::with_seed(45);
        let mut trace = setup_simple_trace();
        let term_size = trace.count_functions();

        let mut stats: HashSet<TracePath> = HashSet::new();

        for _ in 0..10000 {
            let path = choose_term_path(&trace, &TermConstraints::default(), &mut rand).unwrap();
            find_term_mut(&mut trace, &path).unwrap();
            stats.insert(path);
        }

        assert_eq!(term_size, stats.len());
    }

    #[test_log::test]
    fn test_reservoir_sample_randomness() {
        /// https://rust-lang-nursery.github.io/rust-cookbook/science/mathematics/statistics.html#standard-deviation
        fn std_deviation(data: &[u32]) -> Option<f32> {
            fn mean(data: &[u32]) -> Option<f32> {
                let sum = data.iter().sum::<u32>() as f32;
                let count = data.len();

                match count {
                    positive if positive > 0 => Some(sum / count as f32),
                    _ => None,
                }
            }

            match (mean(data), data.len()) {
                (Some(data_mean), count) if count > 0 => {
                    let variance = data
                        .iter()
                        .map(|value| {
                            let diff = data_mean - (*value as f32);

                            diff * diff
                        })
                        .sum::<f32>()
                        / count as f32;

                    Some(variance.sqrt())
                }
                _ => None,
            }
        }

        let trace = setup_simple_trace();
        let term_size = trace.count_functions();

        let mut rand = StdRand::with_seed(45);
        let mut stats: HashMap<u32, u32> = HashMap::new();

        for _ in 0..10000 {
            let term = choose(&trace, &TermConstraints::default(), &mut rand).unwrap();

            let id = term.0.resistant_id();

            let count: u32 = *stats.get(&id).unwrap_or(&0);
            stats.insert(id, count + 1);
        }

        let std_dev =
            std_deviation(stats.values().cloned().collect::<Vec<u32>>().as_slice()).unwrap();
        /*        println!("{:?}", std_dev);
        println!("{:?}", stats);*/

        assert!(std_dev < 30.0);
        assert_eq!(term_size, stats.len());
    }
}
