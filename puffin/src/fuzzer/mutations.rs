use std::borrow::Cow;

use libafl::corpus::HasCurrentCorpusId;
use libafl::prelude::*;
use libafl_bolts::prelude::*;

use super::utils::{
    choose, choose_filtered, choose_iter, choose_term, choose_term_filtered_mut,
    choose_term_path_filtered, find_all_sub_term_filtered, find_all_term_filtered, find_term,
    find_term_mut, reservoir_sample, Choosable, TermConstraints, TracePath,
};
use crate::algebra::atoms::{Function, Variable};
use crate::algebra::dynamic_function::DynamicFunctionShape;
use crate::algebra::signature::Signature;
use crate::algebra::{DYTerm, Subterms, Term, TermType};
use crate::fuzzer::observed_knowledge::with_observed_knowledge;
use crate::fuzzer::term_zoo::TermZoo;
use crate::protocol::{ProtocolBehavior, ProtocolTypes};
use crate::put_registry::PutRegistry;
use crate::trace::{Action, Query, Source, Spawner, Trace, TraceContext};

#[derive(Clone, Copy, Debug)]
pub struct MutationConfig {
    pub fresh_zoo_after: u64,
    pub max_result_trace_length: usize,
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
    /// Relative probability of each [`ListMutator`] sub-mutation.
    pub list_mutation_weights: ListMutationWeights,
}

impl Default for MutationConfig {
    //  TODO:EVAL: evaluate modif to this config
    fn default() -> Self {
        Self {
            fresh_zoo_after: 100000,
            max_result_trace_length: 20,
            min_trace_length: 2,
            term_constraints: TermConstraints::default(),
            with_bit_level: false,
            with_dy: true,
            with_focus: true,
            scope_weights: ScopeWeights::default(),
            list_mutation_weights: ListMutationWeights::default(),
        }
    }
}

/// Relative weights for picking a [`MutationScope`] when applying a replacement mutation.
///
/// The default weights the scope inverse to its breadth (`global:1, step:2, individual:3`) so that
/// surgical edits dominate. Setting them allows ablation studies and reproducing historical
/// behaviours, e.g. `(0, 0, 1)` is purely individual replacements (behaviour before global
/// mutations existed).
#[derive(Clone, Copy, Debug)]
pub struct ScopeWeights {
    pub global: usize,
    pub step: usize,
    pub individual: usize,
}

impl Default for ScopeWeights {
    fn default() -> Self {
        Self {
            // Weights INVERSE to the semantic breadth of the scope: a Global replace rewrites the
            // matched sub-term EVERYWHERE in the trace (broadest, most destructive for structured
            // inputs), Step within one step, Individual a single occurrence (most surgical). For
            // grammar/DY fuzzing we want surgical edits to dominate, so global is the least likely.
            // (AFL-style broad stacking suits flat byte inputs, not deep protocol structures.)
            global: 1,
            step: 2,
            individual: 3,
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
/// The generalisation is deliberately performed without any term constraint: skipping a large
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
    config: &MutationConfig,
    rand: &mut R,
) -> MutationResult {
    let targets = scoped_targets(trace, to_mutate_path, representative, config, rand);
    apply_to_targets(
        trace,
        &targets,
        new_term,
        representative,
        config.with_bit_level,
        &config.term_constraints,
    )
}

/// Returns `true` iff replacing a term of size `representative_size` by one of size `new_size` at
/// every path in `targets` keeps each affected single step recipe within
/// `constraints.max_result_term_size`.
///
/// **Precondition: the input `trace` is already within the caps.** This is a loop invariant, not
/// something re-checked here: hand-written seeds are authored within the caps, and every
/// replacement mutation is reject-whole, so a trace that reached the corpus is always `<=
/// max_result_term_size`. The size-neutral fast path below relies on it — a shrinking or
/// size-neutral replacement is accepted in O(1) precisely because it cannot push an *already
/// bounded* trace over a cap. The one way to break the invariant is to configure a result cap
/// *below* the size of an already-imported seed: such a seed is out of bounds before any mutation,
/// and a neutral replacement will (correctly, per this contract) keep it that way. Enforcing caps
/// against oversized inputs is a corpus-boundary concern, out of scope for the mutator.
///
/// Efficiency (why we don't recompute every step's size):
/// - a mutation that does not grow the trace (`new_size <= representative_size`) can never exceed a
///   cap, so we accept in O(1) without touching any size;
/// - otherwise we only look at the **affected steps** (those containing a target) — never all steps
///   — recomputing each such step's recipe size once, and derive the new whole-trace size as
///   `old_trace_size + n_targets * delta`. `old_trace_size` is read from the (already bounded, `<=
///   already-bounded) trace, so it is cheap.
fn replacement_within_caps<PT: ProtocolTypes>(
    trace: &Trace<PT>,
    targets: &[TracePath],
    representative_size: usize,
    new_size: usize,
    constraints: &TermConstraints,
) -> bool {
    if new_size <= representative_size {
        return true; // shrink or size-neutral: cannot exceed any cap
    }
    let delta = new_size - representative_size;

    // Per-affected-step check: count targets per step, only recompute those steps' sizes.
    let mut per_step: std::collections::HashMap<usize, usize> = std::collections::HashMap::new();
    for (step_index, _) in targets {
        *per_step.entry(*step_index).or_insert(0) += 1;
    }
    for (step_index, count) in &per_step {
        let cur = match trace.steps.get(*step_index).map(|s| &s.action) {
            Some(Action::Input(input)) => input.recipe.size(),
            _ => 0,
        };
        if cur + count * delta > constraints.max_result_term_size {
            return false;
        }
    }

    // We intentionally cap only the per-step recipe size here. Whole-trace growth is bounded by the
    // number of steps (`max_result_trace_length`, enforced when steps are added) times this cap,
    // which is enough; we therefore avoid the extra whole-trace `Trace::size()` recomputation.
    true
}

/// Returns `true` iff replacing a term carrying `representative_payloads` payloads by one carrying
/// `new_payloads`, at every path in `targets`, keeps each *affected* step recipe within
/// `constraints.threshold_max_payloads_per_term`.
///
/// The budget is enforced **per term** (per step recipe), not as an average over the whole trace:
/// a broad scope that rewrites several occurrences within a single recipe is charged the full
/// growth for that recipe, so one dense recipe cannot hide behind many payload-free ones. Mirrors
/// [`replacement_within_caps`]: only a growing replacement (`new_payloads >
/// representative_payloads`) can exceed the budget, so a payload-neutral or shrinking replacement
/// is accepted in O(1) without inspecting any recipe. Enforced uniformly for every replacement
/// mutator via [`apply_to_targets`] (previously only [`ReplaceReuseMutator`] checked it, and only
/// against a trace-wide average).
fn payloads_within_caps<PT: ProtocolTypes>(
    trace: &Trace<PT>,
    targets: &[TracePath],
    representative_payloads: usize,
    new_payloads: usize,
    constraints: &TermConstraints,
) -> bool {
    if new_payloads <= representative_payloads {
        return true; // no payload growth: cannot exceed the budget
    }
    let delta = new_payloads - representative_payloads;

    // Per-affected-step check: count targets per step, only inspect those steps' recipes. `cur`
    // already includes the payloads of the occurrences about to be replaced, so the projected
    // recipe payload count is `cur + count * delta`.
    let mut per_step: std::collections::HashMap<usize, usize> = std::collections::HashMap::new();
    for (step_index, _) in targets {
        *per_step.entry(*step_index).or_insert(0) += 1;
    }
    for (step_index, count) in &per_step {
        let cur = match trace.steps.get(*step_index).map(|s| &s.action) {
            Some(Action::Input(input)) => input.recipe.count_payloads(),
            _ => 0,
        };
        if cur + count * delta > constraints.threshold_max_payloads_per_term {
            return false;
        }
    }
    true
}

/// Replace the term at each of `targets` (each currently structurally equal to `representative`) by
/// `new_term`, enforcing the result-size caps (`constraints.max_result_{term,trace}_size`) and,
/// when `with_bit` is set, the per-term payload budget
/// (`constraints.threshold_max_payloads_per_term`). If applying to all targets would exceed a cap,
/// the mutation is rejected wholesale (returns [`MutationResult::Skipped`]) so the "replace all
/// equal occurrences" atomicity is preserved. See `replacement_within_caps` and
/// `payloads_within_caps`.
///
/// `with_bit` mirrors whether bit-level mutations are enabled: when they are not, no term carries a
/// payload, so the whole payload accounting is skipped without even walking `new_term`.
pub fn apply_to_targets<PT: ProtocolTypes>(
    trace: &mut Trace<PT>,
    targets: &[TracePath],
    new_term: &Term<PT>,
    representative: &Term<PT>,
    with_bit: bool,
    constraints: &TermConstraints,
) -> MutationResult {
    if !replacement_within_caps(
        trace,
        targets,
        representative.size(),
        new_term.size(),
        constraints,
    ) {
        log::debug!("[Mutation] rejected: would exceed result-size caps");
        return MutationResult::Skipped;
    }
    // Payloads only exist under bit-level mutations; when those are off, skip the accounting
    // entirely (no `new_term` walk). Even under bit-level, only a replacement that *adds* payloads
    // can exceed the budget, so a payload-free `new_term` short-circuits before the per-recipe
    // walks.
    if with_bit {
        let new_payloads = new_term.count_payloads();
        if new_payloads > 0
            && !payloads_within_caps(
                trace,
                targets,
                representative.count_payloads(),
                new_payloads,
                constraints,
            )
        {
            log::debug!("[Mutation] rejected: would exceed per-term payload budget");
            return MutationResult::Skipped;
        }
    }

    // A broader scope can reach the source of a deconstructor; such a target keeps its term when
    // `new_term` would not be a valid source there (see `is_deconstructible`).
    let valid_anywhere = is_deconstructible(new_term);

    let mut mutated = false;
    for target in targets {
        if !valid_anywhere && is_deconstructor_source(trace, target) {
            log::debug!("[Mutation] target skipped: invalid deconstructor source at {target:?}");
            continue;
        }
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

/// Draw a [`MutationScope`] and return *all* the occurrences to replace, see
/// [`apply_scoped_mutation`]. The search is unbounded (finds every structurally-equal occurrence);
/// runaway is prevented at *application* time by the result-size caps in [`apply_to_targets`], not
/// by cutting the search short.
///
/// Exposed separately from [`apply_to_targets`] so a caller can inspect *how many* occurrences
/// would be replaced before committing: [`ReplaceReuseMutator`] needs it to bound the payloads it
/// adds.
pub fn scoped_targets<PT: ProtocolTypes, R: Rand>(
    trace: &Trace<PT>,
    to_mutate_path: &TracePath,
    representative: &Term<PT>,
    config: &MutationConfig,
    rand: &mut R,
) -> Vec<TracePath> {
    let scope = MutationScope::choose(config.scope_weights, rand);
    let (chosen_step, _) = to_mutate_path;

    // the type shape is only compared first to speed up the comparison
    let filter = |term: &Term<PT>| {
        term.get_type_shape() == representative.get_type_shape() && term == representative
    };
    // The result-size caps enforced in `apply_to_targets` bound growth, so the search for the
    // other occurrences is itself unconstrained.
    let constraints = TermConstraints::no_constraint();

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
    MakeDeconstructorMutator<S>,
    MakeKnowledgeQueryMutator<S>,
    GenerateMutator<'harness, S, PB>,
    SwapMutator<S>,
    ListMutator<'harness, S, PB>,
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
        max_result_trace_length,
        min_trace_length,
        term_constraints,
        with_dy,
        list_mutation_weights,
        ..
    } = mutation_config;

    tuple_list!(
        RepeatMutator::new(max_result_trace_length, with_dy),
        SkipMutator::new(min_trace_length, with_dy),
        ReplaceReuseMutator::new(mutation_config),
        ReplaceMatchMutator::new(mutation_config, signature),
        RemoveAndLiftMutator::new(term_constraints, with_dy),
        MakeDeconstructorMutator::new(term_constraints, with_dy),
        MakeKnowledgeQueryMutator::new(term_constraints, with_dy),
        GenerateMutator::new(
            0,
            fresh_zoo_after,
            None,
            signature,
            put_registry,
            mutation_config,
        ), /* Refresh zoo after 100000M mutations */
        SwapMutator::new(term_constraints, with_dy),
        ListMutator::new(
            0,
            fresh_zoo_after,
            term_constraints,
            None,
            signature,
            put_registry,
            list_mutation_weights,
            with_dy,
        ),
    )
}

/// Largest `n` in the `2^n` elements a run adds or drops: 1, 2, 4, 8, 16 or 32.
const MAX_RUN_EXPONENT: u32 = 5;

/// One of the edits [`ListMutator`] performs on the list it picked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ListMutation {
    /// Insert `2^n` copies of a zoo-generated element at a random position.
    Insert,
    /// Drop `2^n` elements from a random position.
    Pop,
    /// Add `2^n` further copies of an element already in the list, beside it.
    Repeat,
    /// Drop every element.
    Empty,
}

/// Relative probability of each [`ListMutator`] sub-mutation. A weight of `0` disables it, and an
/// all-zero set disables the mutator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ListMutationWeights {
    pub insert: usize,
    pub pop: usize,
    pub repeat: usize,
    pub empty: usize,
}

impl Default for ListMutationWeights {
    fn default() -> Self {
        // `insert` is the reach the mutator exists to add; `empty` discards what the rest built.
        Self {
            insert: 4,
            pop: 3,
            repeat: 2,
            empty: 1,
        }
    }
}

impl ListMutationWeights {
    fn weighted(self) -> [(usize, ListMutation); 4] {
        [
            (self.insert, ListMutation::Insert),
            (self.pop, ListMutation::Pop),
            (self.repeat, ListMutation::Repeat),
            (self.empty, ListMutation::Empty),
        ]
    }

    /// Draws a sub-mutation proportionally to the weights, or `None` when they are all zero.
    pub fn choose<R: Rand>(self, rand: &mut R) -> Option<ListMutation> {
        let total: usize = self.weighted().iter().map(|(weight, _)| weight).sum();
        if total == 0 {
            return None;
        }

        let mut draw = rand.between(0, total - 1);
        for (weight, mutation) in self.weighted() {
            if draw < weight {
                return Some(mutation);
            }
            draw -= weight;
        }
        None // unreachable: `draw < total` and the weights sum to `total`
    }
}

/// `2^n` elements for `n` in `0..=`[`MAX_RUN_EXPONENT`], capped to fit in `room`: the elements the
/// term-size budget still affords when growing, what follows the start index when dropping.
///
/// Capping the exponent rather than the count keeps a run a power of two at the boundaries too.
fn power_of_two_run<R: Rand>(room: usize, rand: &mut R) -> usize {
    if room == 0 {
        return 0;
    }
    let max_exponent = MAX_RUN_EXPONENT.min(room.ilog2());
    1 << rand.between(0, max_exponent as usize)
}

/// How many `element_size`-node elements a list of `list_size` nodes can still take without going
/// past `max_term_size`, the budget every mutator already selects under.
fn room_for(list_size: usize, element_size: usize, max_term_size: usize) -> usize {
    max_term_size.saturating_sub(list_size) / element_size.max(1)
}

/// Whether `term` is a [`DYTerm::List`] the sub-mutation applies to. Non-symbolic terms are
/// excluded: restructuring under a payload moves the bytes it was located against.
fn is_mutable_list<PT: ProtocolTypes>(term: &Term<PT>, mutation: ListMutation) -> bool {
    let DYTerm::List(_, elements) = &term.term else {
        return false;
    };
    if !term.is_symbolic() {
        return false;
    }
    // Growth is bounded by `max_term_size` once the element size is known, not here.
    match mutation {
        ListMutation::Insert => true,
        ListMutation::Repeat | ListMutation::Pop | ListMutation::Empty => !elements.is_empty(),
    }
}

/// LIST: Picks one [`DYTerm::List`] in the trace and edits its elements in place.
///
/// Nothing else grows or shrinks a flat list one element at a time -- `GenerateMutator` can only
/// swap in a whole zoo-generated one -- which the cons-shaped chain it replaced got for free from
/// the ordinary term mutations. [`ListMutationWeights`] decides how often each edit is used.
pub struct ListMutator<'a, S, PB: ProtocolBehavior>
where
    S: HasRand,
{
    mutation_counter: u64,
    refresh_zoo_after: u64,
    constraints: TermConstraints,
    zoo: Option<TermZoo<PB>>,
    signature: &'static Signature<PB::ProtocolTypes>,
    put_registry: &'a PutRegistry<PB>,
    weights: ListMutationWeights,
    phantom_s: std::marker::PhantomData<S>,
    with_dy: bool,
}

impl<'a, S, PB: ProtocolBehavior> ListMutator<'a, S, PB>
where
    S: HasRand,
{
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        mutation_counter: u64,
        refresh_zoo_after: u64,
        constraints: TermConstraints,
        zoo: Option<TermZoo<PB>>,
        signature: &'static Signature<PB::ProtocolTypes>,
        put_registry: &'a PutRegistry<PB>,
        weights: ListMutationWeights,
        with_dy: bool,
    ) -> Self {
        Self {
            mutation_counter,
            refresh_zoo_after,
            constraints,
            zoo,
            signature,
            put_registry,
            weights,
            phantom_s: std::marker::PhantomData,
            with_dy,
        }
    }

    /// The zoo to draw elements from, regenerated every `refresh_zoo_after` mutations.
    fn zoo<R: Rand>(&mut self, rand: &mut R) -> &TermZoo<PB> {
        self.mutation_counter += 1;
        let refresh = self.mutation_counter % self.refresh_zoo_after == 0;

        if refresh || self.zoo.is_none() {
            let ctx = TraceContext::new(Spawner::new(self.put_registry.clone()));
            let zoo = TermZoo::generate(
                &ctx,
                self.signature,
                rand,
                self.constraints.zoo_gen_how_many,
                self.constraints.zoo_max_depth,
            );
            self.zoo.insert(zoo)
        } else {
            self.zoo.as_ref().unwrap()
        }
    }
}

impl<S, PB: ProtocolBehavior> Mutator<Trace<PB::ProtocolTypes>, S> for ListMutator<'_, S, PB>
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

        // Drawn before the list: each sub-mutation has its own precondition, so the search can
        // take it into account instead of picking a list the draw cannot apply to.
        let Some(mutation) = self.weights.choose(rand) else {
            log::debug!(
                "       Skipped {}: every sub-mutation weight is zero",
                self.name()
            );
            return Ok(MutationResult::Skipped);
        };

        let filter = |term: &Term<PB::ProtocolTypes>| is_mutable_list(term, mutation);
        let Some(path) = choose_term_path_filtered(trace, filter, &self.constraints, rand) else {
            log::debug!(
                "       Skipped {}: no list to apply {mutation:?} to",
                self.name()
            );
            return Ok(MutationResult::Skipped);
        };

        // `Insert` reaches the zoo, which needs the trace unborrowed: read the type, pick, mutate.
        let element = if mutation == ListMutation::Insert {
            let Some(list) = find_term(trace, &path) else {
                return Ok(MutationResult::Skipped);
            };
            let DYTerm::List(typ, _) = &list.term else {
                return Ok(MutationResult::Skipped);
            };
            let Some(element_type) = self.signature.list_element_type(typ).cloned() else {
                return Ok(MutationResult::Skipped);
            };

            let Some(element) = self
                .zoo(rand)
                .choose_filtered(|term| *term.get_type_shape() == element_type, rand)
                .cloned()
            else {
                log::debug!(
                    "       Skipped {}: the zoo holds no {} to insert",
                    self.name(),
                    element_type.name
                );
                return Ok(MutationResult::Skipped);
            };
            Some(element)
        } else {
            None
        };

        let Some(to_mutate) = find_term_mut(trace, &path) else {
            return Ok(MutationResult::Skipped);
        };
        log::debug!("[Mutation] Mutate ListMutator [{mutation:?}] on term\n{to_mutate}");
        let max_term_size = self.constraints.max_term_size;
        let list_size = to_mutate.size();

        // `insert_element` needs the whole term, so `Insert` runs before the elements are borrowed.
        if let Some(element) = element {
            let DYTerm::List(_, elements) = &to_mutate.term else {
                return Ok(MutationResult::Skipped);
            };
            let index = rand.between(0, elements.len());
            let copies = power_of_two_run(room_for(list_size, element.size(), max_term_size), rand);
            for _ in 0..copies {
                // Drawn by type, so this cannot reject; report rather than panic if that changes.
                if let Err(e) = to_mutate.insert_element(index, element.clone()) {
                    log::warn!("[ListMutator] Insert rejected: {e}");
                    return Ok(MutationResult::Skipped);
                }
            }
            return Ok(if copies == 0 {
                MutationResult::Skipped
            } else {
                MutationResult::Mutated
            });
        }

        let DYTerm::List(_, elements) = &mut to_mutate.term else {
            return Ok(MutationResult::Skipped);
        };

        match mutation {
            // Handled above, where the whole term is still available.
            ListMutation::Insert => return Ok(MutationResult::Skipped),
            ListMutation::Pop => {
                let index = rand.between(0, elements.len() - 1);
                let run = power_of_two_run(elements.len() - index, rand);
                elements.drain(index..index + run);
            }
            ListMutation::Repeat => {
                let index = rand.between(0, elements.len() - 1);
                let element = elements[index].clone();
                let room = room_for(list_size, element.size(), max_term_size);
                let copies = power_of_two_run(room, rand);
                if copies == 0 {
                    return Ok(MutationResult::Skipped);
                }
                for _ in 0..copies {
                    elements.insert(index, element.clone());
                }
            }
            ListMutation::Empty => elements.clear(),
        }

        Ok(MutationResult::Mutated)
    }

    fn post_exec(&mut self, _state: &mut S, _new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}

impl<S, PB: ProtocolBehavior> Named for ListMutator<'_, S, PB>
where
    S: HasRand,
{
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("ListMutator")
    }
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
                let step_a_size = match &trace.steps[trace_path_a.0].action {
                    crate::trace::Action::Input(input) => input.recipe.size(),
                    crate::trace::Action::Output(_) => 0,
                };
                let step_b_size = match &trace.steps[trace_path_b.0].action {
                    crate::trace::Action::Input(input) => input.recipe.size(),
                    crate::trace::Action::Output(_) => 0,
                };

                let term_a_cloned = term_a.clone();
                let term_a_size = term_a.size();
                // Swapping must not install an invalid source under a deconstructor.
                let term_b_is_deconstructible =
                    find_term(trace, &trace_path_b).is_some_and(is_deconstructible);
                if (is_deconstructor_source(trace, &trace_path_a) && !term_b_is_deconstructible)
                    || (is_deconstructor_source(trace, &trace_path_b)
                        && !is_deconstructible(&term_a_cloned))
                {
                    log::debug!("       Skipped {}", self.name());
                    return Ok(MutationResult::Skipped);
                }

                if let Some(term_b_mut) = find_term_mut(trace, &trace_path_b) {
                    let term_b_size = term_b_mut.size();

                    // Post-mutation hard cap of 500 to prevent runaway growth while allowing
                    // natural overshoot (pre-PR 472 behavior).
                    if step_b_size + term_a_size <= 500 + term_b_size
                        && step_a_size + term_b_size <= 500 + term_a_size
                    {
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
                    } else {
                        log::debug!("[SwapMutator] Skipped as it would exceed max_term_size.");
                    }
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
                // A deconstructor has a single boxed sub-term and does not support the
                // lift-and-remove operation, so it is excluded from this mutation.
                DYTerm::Variable(_) | DYTerm::Deconstructor(..) => false,
                // Dropping one element is what removing a node and lifting its same-type child
                // used to do to a cons-shaped list.
                DYTerm::List(_, elements) => !elements.is_empty(),
                DYTerm::Application(_, subterms) =>
                    {
                        subterms
                            .find_subterm(|subterm| match &subterm.term {
                                DYTerm::Variable(_) | DYTerm::Deconstructor(..) => false,
                                DYTerm::Application(_, grand_subterms)
                                | DYTerm::List(_, grand_subterms) => {
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
                DYTerm::Variable(_) | DYTerm::Deconstructor(..) => {
                    log::debug!("       Skipped {}", self.name());
                    Ok(MutationResult::Skipped)
                }
                DYTerm::List(_, ref mut elements) if !elements.is_empty() => {
                    let index = rand.below_or_zero(elements.len());
                    elements.remove(index);
                    Ok(MutationResult::Mutated)
                }
                DYTerm::List(..) => {
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

/// Upper bound (inclusive) on the counter randomly chosen when creating a deconstructor: it selects
/// the n-th matching sub-value of the source.
const MAX_DECONSTRUCTOR_COUNTER: usize = 3;

/// Whether a term is an admissible *source* for a [`DYTerm::Deconstructor`].
///
/// A deconstructor only pays off when the sub-values of its source are not already spelled out in
/// the recipe, which is the case for exactly three kinds of source:
/// - an opaque function symbol (like encryption), whose concretization hides its arguments,
/// - a variable, whose concretization comes from the PUT,
/// - another deconstructor, whose result is itself extracted from one of the above.
///
/// Over a transparent application, extraction could only yield a value that the recipe already
/// contains as a sub-term, so building a deconstructor there is forbidden.
pub fn is_deconstructible<PT: ProtocolTypes>(term: &Term<PT>) -> bool {
    match &term.term {
        DYTerm::Variable(_) | DYTerm::Deconstructor(..) => true,
        DYTerm::Application(func, _) => func.is_opaque(),
        DYTerm::List(..) => false,
    }
}

/// Whether `trace_path` designates the source sub-term of a [`DYTerm::Deconstructor`], that is a
/// position where only [`is_deconstructible`] terms may be installed.
fn is_deconstructor_source<PT: ProtocolTypes>(
    trace: &Trace<PT>,
    (step_index, term_path): &TracePath,
) -> bool {
    let Some((_, parent_path)) = term_path.split_last() else {
        return false; // the root of a recipe has no parent
    };
    find_term(trace, &(*step_index, parent_path.to_vec()))
        .is_some_and(|parent| matches!(&parent.term, DYTerm::Deconstructor(..)))
}

/// Whether the function symbol named by `shape` is declared opaque in `signature`.
fn is_opaque_shape<PT: ProtocolTypes>(
    signature: &Signature<PT>,
    shape: &DynamicFunctionShape<PT>,
) -> bool {
    signature
        .attrs_by_name
        .get(shape.name)
        .is_some_and(|attrs| attrs.is_opaque)
}

/// MAKE DECONSTRUCTOR: wraps a sub-term of type `T` into a [`DYTerm::Deconstructor`] that extracts
/// a `T` out of another sub-term (the *source*) taken from the trace. The source is restricted to
/// the terms accepted by [`is_deconstructible`]: an opaque symbol, a variable or another
/// deconstructor.
///
/// The wrapping is speculative: at execution time the deconstructor extracts a value of type `T`
/// from the source's evaluation, which may or may not contain one. When it does not, evaluation
/// fails gracefully (`Error::Term`) and the trace is discarded, so no invariant is broken.
pub struct MakeDeconstructorMutator<S>
where
    S: HasRand,
{
    constraints: TermConstraints,
    phantom_s: std::marker::PhantomData<S>,
    with_dy: bool,
}

impl<S> MakeDeconstructorMutator<S>
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

impl<S, PT: ProtocolTypes> Mutator<Trace<PT>, S> for MakeDeconstructorMutator<S>
where
    S: HasRand,
{
    fn mutate(&mut self, state: &mut S, trace: &mut Trace<PT>) -> Result<MutationResult, Error> {
        log::debug!("[DY] Start mutate with {}", self.name());
        if !self.with_dy {
            return Ok(MutationResult::Skipped);
        }
        let rand = state.rand_mut();
        // Pick the source sub-term first (cloned so we can reborrow the trace mutably below). Only
        // sources whose sub-values are not already available in the recipe are worth deconstructing
        // (see [`is_deconstructible`]).
        if let Some(source) = choose_filtered(
            trace,
            &self.constraints,
            |term: &Term<PT>| is_deconstructible(term),
            rand,
        )
        .map(|(source, _)| source.clone())
        {
            // Pick a symbolic, non-deconstructor target to wrap; its type becomes the
            // deconstructor's result type.
            if let Some(to_wrap) = choose_term_filtered_mut(
                trace,
                |term: &Term<PT>| {
                    term.is_symbolic() && !matches!(&term.term, DYTerm::Deconstructor(..))
                },
                &self.constraints,
                rand,
            ) {
                let typ = to_wrap.get_type_shape().clone();
                let counter = rand.between(0, MAX_DECONSTRUCTOR_COUNTER) as u16;
                log::debug!(
                    "[Mutation] MakeDeconstructorMutator: wrap\n{to_wrap}\ninto a deconstructor of type {typ} over source\n{source}"
                );
                to_wrap.mutate(Term::from(DYTerm::Deconstructor(
                    typ,
                    Box::new(source),
                    Query {
                        source: None,
                        matcher: None,
                        counter,
                        is_claim: false,
                    },
                )));
                return Ok(MutationResult::Mutated);
            }
        }
        log::debug!("       Skipped {}", self.name());
        Ok(MutationResult::Skipped)
    }

    fn post_exec(&mut self, _state: &mut S, _new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}

impl<S> Named for MakeDeconstructorMutator<S>
where
    S: HasRand,
{
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("MakeDeconstructorMutator")
    }
}

/// One created query in `GENERALIZE_SOURCE_ONE_IN` drops its source, matching the knowledge of
/// every source: used to add variability.
const GENERALIZE_SOURCE_ONE_IN: usize = 4;

/// The sources that can already hold knowledge when the recipe of `step_index` is evaluated: the
/// agent of any step that has run (`Step::execute` reads its outbound messages, input step
/// included), and the label of any precomputation already evaluated, `step_index`'s own included.
/// Prior traces count as preceding steps.
fn query_sources<PT: ProtocolTypes>(trace: &Trace<PT>, step_index: usize) -> Vec<Source> {
    let prior_steps = || {
        trace
            .prior_traces
            .iter()
            .flat_map(|prior| prior.steps.iter())
    };

    let mut sources: Vec<Source> = vec![];
    let push = |sources: &mut Vec<Source>, source: Source| {
        if !sources.contains(&source) {
            sources.push(source);
        }
    };

    for step in prior_steps().chain(trace.steps.iter().take(step_index)) {
        push(&mut sources, Source::Agent(step.agent));
    }
    for step in prior_steps().chain(trace.steps.iter().take(step_index + 1)) {
        if let Action::Input(input) = &step.action {
            for precomputation in &input.precomputations {
                push(&mut sources, Source::Label(precomputation.label.clone()));
            }
        }
    }

    sources
}

/// MAKE KNOWLEDGE QUERY: replaces a sub-term of type `T` with a fresh knowledge query, that is a
/// [`DYTerm::Variable`] of type `T` reading a value the attacker learned during the execution
/// instead of a value the recipe builds itself.
///
/// The query is drawn from the knowledge the mutated entry's own execution produced
/// ([`crate::fuzzer::observed_knowledge`]), restricted to what is readable at that position, so a
/// type that never appeared as knowledge is never queried at all.
///
/// It stays speculative: the mutated trace may no longer produce that knowledge, in which case
/// evaluation fails gracefully (`Error::Term`).
pub struct MakeKnowledgeQueryMutator<S>
where
    S: HasRand,
{
    constraints: TermConstraints,
    phantom_s: std::marker::PhantomData<S>,
    with_dy: bool,
}

impl<S> MakeKnowledgeQueryMutator<S>
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

impl<S, PT: ProtocolTypes> Mutator<Trace<PT>, S> for MakeKnowledgeQueryMutator<S>
where
    S: HasRand + HasCurrentCorpusId,
{
    fn mutate(&mut self, state: &mut S, trace: &mut Trace<PT>) -> Result<MutationResult, Error> {
        log::debug!("[DY] Start mutate with {}", self.name());
        if !self.with_dy {
            return Ok(MutationResult::Skipped);
        }
        // A variable is an admissible deconstructor source ([`is_deconstructible`]), so the query
        // may be installed anywhere, including at the source position of a deconstructor. Only
        // symbolic terms are replaced, so that a payload is never silently dropped.
        let Some(to_replace_path) = choose_term_path_filtered(
            trace,
            |term: &Term<PT>| term.is_symbolic(),
            &self.constraints,
            state.rand_mut(),
        ) else {
            log::debug!("       Skipped {}", self.name());
            return Ok(MutationResult::Skipped);
        };

        let Some(to_replace) = find_term(trace, &to_replace_path) else {
            log::debug!("       Skipped {}", self.name());
            return Ok(MutationResult::Skipped);
        };
        let typ = to_replace.get_type_shape().clone();

        // Without a combination readable at this step the query could only be a guess.
        let parent = state.current_corpus_id().ok().flatten();
        let reachable = query_sources(trace, to_replace_path.0);
        let rand = state.rand_mut();
        let Some(observation) = with_observed_knowledge::<PT, _>(|pools| {
            pools
                .observations(parent, typ.clone().into())
                .unwrap_or_default()
                .iter()
                .filter(|observation| {
                    observation.available_from <= to_replace_path.0
                        && reachable.contains(&observation.source)
                })
                .cloned()
                .collect::<Vec<_>>()
                .choose(rand)
                .cloned()
        }) else {
            log::debug!("[MakeKnowledgeQueryMutator] Skipped as no execution ever produced a knowledge of type {typ} reachable from this step.");
            log::debug!("       Skipped {}", self.name());
            return Ok(MutationResult::Skipped);
        };

        let query = Query {
            source: (rand.below_or_zero(GENERALIZE_SOURCE_ONE_IN) != 0)
                .then_some(observation.source),
            matcher: observation.matcher,
            counter: rand.below_or_zero(observation.multiplicity as usize) as u16,
            is_claim: false,
        };

        let Some(to_replace) = find_term_mut(trace, &to_replace_path) else {
            log::debug!("       Skipped {}", self.name());
            return Ok(MutationResult::Skipped);
        };
        // Re-querying exactly the same knowledge would leave the trace unchanged.
        if matches!(&to_replace.term, DYTerm::Variable(variable) if variable.query == query) {
            log::debug!("[MakeKnowledgeQueryMutator] Skipped as the drawn query is the one already made by the term.");
            log::debug!("       Skipped {}", self.name());
            return Ok(MutationResult::Skipped);
        }

        log::debug!(
            "[Mutation] MakeKnowledgeQueryMutator: replace\n{to_replace}\nwith the knowledge query {query}/{typ}"
        );
        to_replace.mutate(Term::from(DYTerm::Variable(Variable::new(typ, query))));
        Ok(MutationResult::Mutated)
    }

    fn post_exec(&mut self, _state: &mut S, new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        with_observed_knowledge::<PT, _>(|pools| pools.commit(new_corpus_id));
        Ok(())
    }
}

impl<S> Named for MakeKnowledgeQueryMutator<S>
where
    S: HasRand,
{
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("MakeKnowledgeQueryMutator")
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
    config: MutationConfig,
    signature: &'static Signature<PT>,
    phantom_s: std::marker::PhantomData<S>,
}

impl<S, PT: ProtocolTypes> ReplaceMatchMutator<S, PT>
where
    S: HasRand,
{
    #[must_use]
    pub const fn new(config: MutationConfig, signature: &'static Signature<PT>) -> Self {
        Self {
            config: MutationConfig {
                term_constraints: TermConstraints {
                    // forbid replacing function symbols in terms with payloads
                    must_be_symbolic: true,
                    ..config.term_constraints
                },
                ..config
            },
            signature,
            phantom_s: std::marker::PhantomData,
        }
    }
}

impl<S, PT: ProtocolTypes> Mutator<Trace<PT>, S> for ReplaceMatchMutator<S, PT>
where
    S: HasRand,
{
    fn mutate(&mut self, state: &mut S, trace: &mut Trace<PT>) -> Result<MutationResult, Error> {
        log::debug!("[DY] Start mutate with {}", self.name());
        if !self.config.with_dy {
            return Ok(MutationResult::Skipped);
        }
        let rand = state.rand_mut();
        let Some(to_mutate_path) =
            choose_term_path_filtered(trace, |_| true, &self.config.term_constraints, rand)
        else {
            log::debug!("       Skipped {}", self.name());
            return Ok(MutationResult::Skipped);
        };
        let Some(to_mutate) = find_term(trace, &to_mutate_path).cloned() else {
            log::debug!("       Skipped {}", self.name());
            return Ok(MutationResult::Skipped);
        };
        log::debug!("[Mutation] ReplaceMatchMutator on term\n{}", to_mutate);

        // At the source position of a deconstructor, only an opaque symbol may replace the current
        // symbol, since a variable becoming a transparent application (or an opaque symbol becoming
        // a transparent one) would break [`is_deconstructible`].
        let must_stay_opaque = is_deconstructor_source(trace, &to_mutate_path);
        let signature = self.signature;

        // Build the fully-formed replacement, of the same type as the chosen term.
        let new_term = match &to_mutate.term {
            DYTerm::Variable(variable) => {
                let Some((shape, dynamic_fn)) = signature.functions.choose_filtered(
                    |(shape, _)| {
                        variable.typ == shape.return_type
                            && shape.is_constant()
                            && (!must_stay_opaque || is_opaque_shape(signature, shape))
                    },
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
                let Some((shape, dynamic_fn)) = signature.functions.choose_filtered(
                    |(shape, _)| {
                        func.shape() != shape
                            && func.shape().return_type == shape.return_type
                            && func.shape().argument_types == shape.argument_types
                            && (!must_stay_opaque || is_opaque_shape(signature, shape))
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
            // Neither a deconstructor nor a list has a function symbol to replace.
            DYTerm::Deconstructor(..) | DYTerm::List(..) => {
                log::debug!("       Skipped {}", self.name());
                return Ok(MutationResult::Skipped);
            }
        };

        Ok(apply_scoped_mutation(
            trace,
            &to_mutate_path,
            &to_mutate,
            &new_term,
            &self.config,
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
    config: MutationConfig,
    phantom_s: std::marker::PhantomData<S>,
}

impl<S> ReplaceReuseMutator<S>
where
    S: HasRand,
{
    #[must_use]
    pub const fn new(config: MutationConfig) -> Self {
        Self {
            config,
            phantom_s: std::marker::PhantomData,
        }
    }
}

impl<S, PT: ProtocolTypes> Mutator<Trace<PT>, S> for ReplaceReuseMutator<S>
where
    S: HasRand,
{
    fn mutate(&mut self, state: &mut S, trace: &mut Trace<PT>) -> Result<MutationResult, Error> {
        log::debug!("[DY] Start mutate with {}", self.name());
        if !self.config.with_dy {
            return Ok(MutationResult::Skipped);
        }
        let rand = state.rand_mut();
        if let Some(replacement) = choose_term(trace, &self.config.term_constraints, rand).cloned()
        {
            if let Some(to_replace_path) = choose_term_path_filtered(
                trace,
                |term: &Term<PT>| term.get_type_shape() == replacement.get_type_shape(),
                &self.config.term_constraints,
                rand,
            ) {
                // Never turn the source of a deconstructor into a term we would not have been
                // allowed to build a deconstructor over in the first place.
                if is_deconstructor_source(trace, &to_replace_path)
                    && !is_deconstructible(&replacement)
                {
                    log::debug!("       Skipped {}", self.name());
                    return Ok(MutationResult::Skipped);
                }
                let Some(to_replace) = find_term(trace, &to_replace_path).cloned() else {
                    log::debug!("       Skipped {}", self.name());
                    return Ok(MutationResult::Skipped);
                };
                // the scope is drawn first: a broader scope replaces several occurrences, and each
                // of them contributes to the payload budget checked below
                let targets =
                    scoped_targets(trace, &to_replace_path, &to_replace, &self.config, rand);
                // The per-term payload budget (threshold_max_payloads_per_term) is enforced
                // wholesale in `apply_to_targets`, uniformly across all replacement mutators, and
                // skipped entirely when bit-level mutations are off (`self.with_bit`).
                log::debug!(
                    "[Mutation] Mutate ReplaceReuseMutator on terms\n {} and\n{}",
                    to_replace,
                    replacement
                );
                return Ok(apply_to_targets(
                    trace,
                    &targets,
                    &replacement,
                    &to_replace,
                    self.config.with_bit_level,
                    &self.config.term_constraints,
                ));
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
    max_result_trace_length: usize,
    phantom_s: std::marker::PhantomData<S>,
    with_dy: bool,
}

impl<S> RepeatMutator<S>
where
    S: HasRand,
{
    #[must_use]
    pub const fn new(max_result_trace_length: usize, with_dy: bool) -> Self {
        Self {
            max_result_trace_length,
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
        if length >= self.max_result_trace_length {
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
        let step = step.clone();
        log::debug!("[Mutation] Mutate RepeatMutator on step {insert_index}");
        trace.steps.insert(insert_index, step);
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
    config: MutationConfig,
    zoo: Option<TermZoo<PB>>,
    signature: &'static Signature<PB::ProtocolTypes>,
    put_registry: &'a PutRegistry<PB>,
    phantom_s: std::marker::PhantomData<S>,
}
impl<'a, S, PB: ProtocolBehavior> GenerateMutator<'a, S, PB>
where
    S: HasRand,
{
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        mutation_counter: u64,
        refresh_zoo_after: u64,
        zoo: Option<TermZoo<PB>>,
        signature: &'static Signature<PB::ProtocolTypes>,
        put_registry: &'a PutRegistry<PB>,
        config: MutationConfig,
    ) -> Self {
        Self {
            mutation_counter,
            refresh_zoo_after,
            config,
            zoo,
            signature,
            put_registry,
            phantom_s: std::marker::PhantomData,
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
        if !self.config.with_dy {
            return Ok(MutationResult::Skipped);
        }
        let rand = state.rand_mut();
        let (to_mutate_path, to_mutate, new_term) = {
            if let Some((to_mutate, to_mutate_path)) =
                reservoir_sample(trace, |_| true, &self.config.term_constraints, rand)
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
                        self.config.term_constraints.zoo_gen_how_many,
                        self.config.term_constraints.zoo_max_depth,
                    ))
                } else {
                    self.zoo.get_or_insert_with(|| {
                        let spawner = Spawner::new(self.put_registry.clone());
                        let ctx = TraceContext::new(spawner); // zoo generate symbolic terms
                        TermZoo::generate(
                            &ctx,
                            self.signature,
                            rand,
                            self.config.term_constraints.zoo_gen_how_many,
                            self.config.term_constraints.zoo_max_depth,
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
            &self.config,
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
    use std::any::TypeId;
    use std::collections::{HashMap, HashSet};

    use libafl::corpus::InMemoryCorpus;
    use libafl::mutators::{MutationResult, Mutator};
    use libafl::state::StdState;
    use libafl_bolts::rands::{RomuDuoJrRand, StdRand};

    use super::*;
    use crate::agent::{AgentDescriptor, AgentName};
    use crate::algebra::dynamic_function::{DescribableFunction, TypeShape};
    use crate::algebra::test_signature::{TestTrace, *};
    use crate::algebra::{AnyMatcher, DYTerm};
    use crate::fuzzer::observed_knowledge::clear_observed_knowledge;
    use crate::fuzzer::utils::{choose_term_path, TracePath};
    use crate::put::{PutDescriptor, PutOptions};
    use crate::put_registry::Factory;
    use crate::term;
    use crate::trace::{Action, InputAction, OutputAction, Source, Step};

    type TestState =
        StdState<InMemoryCorpus<TestTrace>, TestTrace, RomuDuoJrRand, InMemoryCorpus<TestTrace>>;

    fn create_state() -> TestState {
        let rand = StdRand::with_seed(1235);
        let corpus: InMemoryCorpus<TestTrace> = InMemoryCorpus::new();
        StdState::new(rand, corpus, InMemoryCorpus::new(), &mut (), &mut ()).unwrap()
    }

    /// A registry whose PUT is never spawned; the zoo only needs a `TraceContext`.
    fn test_put_registry() -> PutRegistry<TestProtocolBehavior> {
        fn dummy_factory() -> Box<dyn Factory<TestProtocolBehavior>> {
            Box::new(TestFactory)
        }

        PutRegistry::<TestProtocolBehavior>::new(
            [("teststub", dummy_factory())],
            PutDescriptor::new("teststub", PutOptions::empty()),
        )
    }

    /// A `ListMutator` restricted to the one sub-mutation under test.
    fn list_mutator<S: HasRand>(
        weights: ListMutationWeights,
        registry: &PutRegistry<TestProtocolBehavior>,
    ) -> ListMutator<'_, S, TestProtocolBehavior> {
        ListMutator::new(
            0,
            100_000,
            TermConstraints::default(),
            None,
            &TEST_SIGNATURE,
            registry,
            weights,
            true,
        )
    }

    fn only(mutation: ListMutation) -> ListMutationWeights {
        let zero = ListMutationWeights {
            insert: 0,
            pop: 0,
            repeat: 0,
            empty: 0,
        };
        match mutation {
            ListMutation::Insert => ListMutationWeights { insert: 1, ..zero },
            ListMutation::Pop => ListMutationWeights { pop: 1, ..zero },
            ListMutation::Repeat => ListMutationWeights { repeat: 1, ..zero },
            ListMutation::Empty => ListMutationWeights { empty: 1, ..zero },
        }
    }

    /// The lengths of every [`DYTerm::List`] in the trace, in traversal order.
    fn list_lengths(trace: &TestTrace) -> Vec<usize> {
        trace
            .steps
            .iter()
            .filter_map(|step| match &step.action {
                Action::Input(input) => Some(&input.recipe),
                Action::Output(_) => None,
            })
            .flat_map(|recipe| recipe.into_iter())
            .filter_map(|term| match &term.term {
                DYTerm::List(_, elements) => Some(elements.len()),
                _ => None,
            })
            .collect()
    }

    /// Runs `mutator` on fresh traces until it reports `Mutated`; returns list lengths before
    /// and after.
    fn mutate_until_applied<M>(mutator: &mut M, state: &mut TestState) -> (Vec<usize>, Vec<usize>)
    where
        M: Mutator<TestTrace, TestState>,
    {
        for _ in 0..200 {
            let mut trace = setup_simple_trace();
            let before = list_lengths(&trace);
            if mutator.mutate(state, &mut trace).unwrap() == MutationResult::Mutated {
                return (before, list_lengths(&trace));
            }
        }
        panic!("the mutation never applied in 200 attempts");
    }

    #[test_log::test]
    fn test_list_mutator_insert_lengthens_a_list() {
        let mut state = create_state();
        let registry = test_put_registry();
        let mut mutator = list_mutator(only(ListMutation::Insert), &registry);

        let (before, after) = mutate_until_applied(&mut mutator, &mut state);
        let grown = after.iter().sum::<usize>() - before.iter().sum::<usize>();
        assert!(
            is_power_of_two_run(grown),
            "insert must add a power-of-two run of at most {}, added {grown}: {before:?} -> \
             {after:?}",
            1 << MAX_RUN_EXPONENT
        );
    }

    fn is_power_of_two_run(moved: usize) -> bool {
        moved.is_power_of_two() && moved <= 1 << MAX_RUN_EXPONENT
    }

    #[test_log::test]
    fn test_list_mutator_pop_shortens_a_list() {
        let mut state = create_state();
        let registry = test_put_registry();
        let mut mutator = list_mutator(only(ListMutation::Pop), &registry);

        let (before, after) = mutate_until_applied(&mut mutator, &mut state);
        let dropped = before.iter().sum::<usize>() - after.iter().sum::<usize>();
        assert!(
            is_power_of_two_run(dropped),
            "pop must drop a power-of-two run of at most {}, dropped {dropped}: {before:?} -> \
             {after:?}",
            1 << MAX_RUN_EXPONENT
        );
    }

    #[test_log::test]
    fn test_list_mutator_repeat_duplicates_an_element() {
        let mut state = create_state();
        let registry = test_put_registry();
        let mut mutator = list_mutator(only(ListMutation::Repeat), &registry);

        for _ in 0..50 {
            let mut trace = setup_simple_trace();
            let before = list_lengths(&trace);
            if mutator.mutate(&mut state, &mut trace).unwrap() != MutationResult::Mutated {
                continue;
            }
            let after = list_lengths(&trace);
            let grown: usize = after.iter().sum::<usize>() - before.iter().sum::<usize>();
            assert!(
                is_power_of_two_run(grown),
                "repeat must add a power-of-two run of at most {}, added {grown}: {before:?} -> \
                 {after:?}",
                1 << MAX_RUN_EXPONENT
            );

            // Every copy must be an element the list already held.
            for term in trace
                .steps
                .iter()
                .filter_map(|step| match &step.action {
                    Action::Input(input) => Some(&input.recipe),
                    Action::Output(_) => None,
                })
                .flat_map(|recipe| recipe.into_iter())
            {
                if let DYTerm::List(_, elements) = &term.term {
                    if elements.len() > 1 {
                        let repeated = elements.windows(2).any(|pair| pair[0] == pair[1]);
                        assert!(repeated, "repeat must leave adjacent equal elements");
                        return;
                    }
                }
            }
            return;
        }
        panic!("repeat never applied in 50 attempts");
    }

    #[test_log::test]
    fn test_list_mutator_empty_clears_a_list() {
        let mut state = create_state();
        let registry = test_put_registry();
        let mut mutator = list_mutator(only(ListMutation::Empty), &registry);

        let (before, after) = mutate_until_applied(&mut mutator, &mut state);
        assert!(
            after.iter().sum::<usize>() < before.iter().sum::<usize>(),
            "empty must drop elements: {before:?} -> {after:?}"
        );
        assert!(
            after.contains(&0),
            "empty must leave a list with no element: {before:?} -> {after:?}"
        );
    }

    /// A run is always `2^n`, and the whole `n` range is reachable.
    #[test_log::test]
    fn test_run_is_a_power_of_two_over_the_whole_range() {
        let mut rand = StdRand::with_seed(0x9_0e70);
        let mut seen = HashSet::new();

        for _ in 0..2_000 {
            let run = power_of_two_run(1 << MAX_RUN_EXPONENT, &mut rand);
            assert!(
                is_power_of_two_run(run),
                "{run} is not a power-of-two run of at most {}",
                1 << MAX_RUN_EXPONENT
            );
            seen.insert(run);
        }
        assert_eq!(
            seen,
            (0..=MAX_RUN_EXPONENT).map(|n| 1usize << n).collect(),
            "every exponent in 0..={MAX_RUN_EXPONENT} must be reachable"
        );
    }

    /// With little room the exponent shrinks so the run still fits, and stays a power of two.
    #[test_log::test]
    fn test_run_shrinks_against_the_room_available() {
        let mut rand = StdRand::with_seed(0xca9);

        for room in [1, 3, 7, 31, 63] {
            for _ in 0..200 {
                let run = power_of_two_run(room, &mut rand);
                assert!(run.is_power_of_two());
                assert!(
                    run <= room,
                    "a run of {run} does not fit in {room} elements"
                );
            }
        }
        // No room at all: nothing to move.
        assert_eq!(power_of_two_run(0, &mut rand), 0);
    }

    /// `Pop` removes at a random position, not always the last one.
    #[test_log::test]
    fn test_list_mutator_pop_removes_at_a_random_position() {
        let mut state = create_state();
        let registry = test_put_registry();
        let mut mutator = list_mutator(only(ListMutation::Pop), &registry);

        /// The longest list of the trace: six distinct ClientHello extensions.
        fn longest_list(trace: &TestTrace) -> Vec<String> {
            trace
                .steps
                .iter()
                .filter_map(|step| match &step.action {
                    Action::Input(input) => Some(&input.recipe),
                    Action::Output(_) => None,
                })
                .flat_map(|recipe| recipe.into_iter())
                .filter_map(|term| match &term.term {
                    DYTerm::List(_, elements) => Some(elements),
                    _ => None,
                })
                .max_by_key(|elements| elements.len())
                .map(|elements| elements.iter().map(ToString::to_string).collect())
                .unwrap_or_default()
        }

        let mut dropped_positions = HashSet::new();
        for _ in 0..200 {
            let mut trace = setup_simple_trace();
            let before = longest_list(&trace);
            if mutator.mutate(&mut state, &mut trace).unwrap() != MutationResult::Mutated {
                continue;
            }
            let after = longest_list(&trace);
            if after.len() >= before.len() {
                continue; // a shorter list elsewhere was the one picked
            }
            // First differing position is where the dropped run started.
            let position = before
                .iter()
                .zip(after.iter())
                .position(|(b, a)| b != a)
                .unwrap_or(after.len());
            dropped_positions.insert(position);
        }

        assert!(
            dropped_positions.len() > 1,
            "pop must not always drop the same position, saw {dropped_positions:?}"
        );
    }

    /// A sub-mutation with weight `0` is never drawn, and the others are drawn in proportion.
    #[test_log::test]
    fn test_list_mutation_weights_control_the_draw() {
        let mut rand = StdRand::with_seed(0x1157);

        let weights = ListMutationWeights {
            insert: 3,
            pop: 1,
            repeat: 0,
            empty: 0,
        };
        let mut insert = 0;
        let mut pop = 0;
        for _ in 0..4_000 {
            match weights.choose(&mut rand).unwrap() {
                ListMutation::Insert => insert += 1,
                ListMutation::Pop => pop += 1,
                drawn => panic!("{drawn:?} has weight 0 and must never be drawn"),
            }
        }
        // 3:1 over 4000 draws, loose enough not to flake but tight enough to reject 2000/2000.
        assert!(
            (2700..3300).contains(&insert),
            "expected about 3000 inserts out of 4000, got {insert} (pop: {pop})"
        );

        assert_eq!(
            ListMutationWeights {
                insert: 0,
                pop: 0,
                repeat: 0,
                empty: 0,
            }
            .choose(&mut rand),
            None,
            "all-zero weights must disable the mutator"
        );
    }

    /// Growth is bounded by `max_term_size`, the budget every mutator selects under, not by a
    /// list-specific cap.
    #[test_log::test]
    fn test_list_growth_is_bounded_by_the_term_size_budget() {
        // One-node elements, so the budget is spent one node per element.
        let element: TestTerm = term! { fn_signature_algorithm_extension };
        assert_eq!(element.size(), 1);

        let list: TestTerm = Term::from(DYTerm::List(
            TypeShape::of::<Vec<ClientExtension>>(),
            vec![element.clone(); 10],
        ));
        // The list node itself counts, so 11 nodes of a 300-node budget leaves room for 289.
        assert_eq!(list.size(), 11);
        assert_eq!(room_for(list.size(), element.size(), 300), 289);

        // A fatter element buys fewer copies out of the same budget.
        assert_eq!(room_for(list.size(), 17, 300), 17);
        // A list already at the budget takes nothing more.
        assert_eq!(room_for(300, 1, 300), 0);
        assert_eq!(room_for(400, 1, 300), 0);
    }

    /// An empty list may only grow; the three shrinking edits would be no-ops on it.
    #[test_log::test]
    fn test_list_mutator_preconditions() {
        let empty: TestTerm = Term::from(DYTerm::List(
            TypeShape::of::<Vec<ClientExtension>>(),
            vec![],
        ));
        assert!(is_mutable_list(&empty, ListMutation::Insert));
        assert!(!is_mutable_list(&empty, ListMutation::Pop));
        assert!(!is_mutable_list(&empty, ListMutation::Repeat));
        assert!(!is_mutable_list(&empty, ListMutation::Empty));
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
            [
                fn_signature_algorithm_extension,
                fn_signature_algorithm_extension,
                fn_signature_algorithm_extension
            ] / Vec<ClientExtension>
        };
        let recipe_b: Term<TestProtocolTypes> = term! {
            [
                fn_signature_algorithm_extension,
                fn_signature_algorithm_extension
            ] / Vec<ClientExtension>
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
            let targets = scoped_targets(
                &trace,
                &chosen_path,
                &duplicated,
                &MutationConfig {
                    scope_weights: weights,
                    ..MutationConfig::default()
                },
                &mut rand,
            );
            assert_eq!(
                apply_to_targets(
                    &mut trace,
                    &targets,
                    &replacement,
                    &duplicated,
                    true,
                    &TermConstraints::no_constraint(),
                ),
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

    /// The payload budget (`threshold_max_payloads_per_term`) is enforced **per term** (per step
    /// recipe), not as a trace-wide average: concentrating the payload growth of a broad scope in a
    /// single recipe is rejected wholesale, even when the same growth spread over the whole trace
    /// would stay under budget on average. Payload-neutral or shrinking replacements are always
    /// accepted. Exercises [`payloads_within_caps`] directly (the guard folded into
    /// [`apply_to_targets`]).
    #[test_log::test]
    fn test_payload_budget_is_per_term_not_average() {
        let trace = setup_simple_trace();
        let step = trace
            .steps
            .iter()
            .position(|s| matches!(s.action, Action::Input(_)))
            .expect("the fixture has at least one input step");
        // baseline payloads already in that recipe (0 for a symbolic seed, but read it to stay
        // robust if the fixture changes)
        let base = match &trace.steps[step].action {
            Action::Input(input) => input.recipe.count_payloads(),
            Action::Output(_) => unreachable!(),
        };

        // one growing replacement (+1 payload) for each of four occurrences, all in ONE recipe
        let concentrated: Vec<TracePath> = (0..4).map(|i| (step, vec![i])).collect();
        let single: Vec<TracePath> = vec![(step, vec![0])];
        // budget leaves room for +3 payloads in a single recipe
        let constraints = TermConstraints {
            threshold_max_payloads_per_term: base + 3,
            ..TermConstraints::no_constraint()
        };

        // per-term: this recipe would reach base + 4 > base + 3 -> reject the whole mutation. A
        // trace-wide average (4 payloads over several steps) would have stayed under budget; that
        // dilution is exactly what this check no longer allows.
        assert!(
            !payloads_within_caps(&trace, &concentrated, base, base + 1, &constraints),
            "four +1-payload replacements in one recipe must exceed the per-term budget"
        );
        // a single occurrence only reaches base + 1 <= base + 3 -> accepted
        assert!(
            payloads_within_caps(&trace, &single, base, base + 1, &constraints),
            "a single growing replacement stays within the per-term budget"
        );
        // payload-neutral and shrinking replacements are accepted regardless of scope width
        assert!(payloads_within_caps(
            &trace,
            &concentrated,
            7,
            7,
            &constraints
        ));
        assert!(payloads_within_caps(
            &trace,
            &concentrated,
            9,
            2,
            &constraints
        ));
    }

    /// `Term::count_payloads` is the alloc-free equivalent of `all_payloads().len()`: it must agree
    /// with it node-for-node, both in the all-symbolic case (0) and once a payload is attached.
    #[test_log::test]
    fn test_count_payloads_matches_all_payloads_len() {
        let trace = setup_simple_trace();
        for step in &trace.steps {
            let Action::Input(input) = &step.action else {
                continue;
            };
            // every sub-term of the recipe: the two traversals must return the same count
            for sub in &input.recipe {
                assert_eq!(sub.count_payloads(), sub.all_payloads().len());
            }
            // and once a payload is attached at the root, both see exactly one
            let mut with_payload = input.recipe.clone();
            with_payload.add_payload(vec![0u8; 4]);
            assert_eq!(
                with_payload.count_payloads(),
                with_payload.all_payloads().len()
            );
            assert_eq!(with_payload.count_payloads(), 1);
        }
    }

    /// The result-size caps are reject-whole: a *growing* replacement that would push either the
    /// affected step recipe over `max_result_term_size` is refused. The size-neutral / shrinking
    /// fast path is accepted in
    /// O(1) even when the input already exceeds the caps — that is the documented bounded-input
    /// precondition of [`replacement_within_caps`] (a cap set below an imported seed is a
    /// corpus-boundary misconfiguration, not the mutator's job to repair).
    #[test_log::test]
    fn test_replacement_within_caps_rejects_growth() {
        let trace = setup_simple_trace();
        let step = trace
            .steps
            .iter()
            .position(|s| matches!(s.action, Action::Input(_)))
            .expect("the fixture has at least one input step");
        let cur = match &trace.steps[step].action {
            Action::Input(input) => input.recipe.size(),
            Action::Output(_) => unreachable!(),
        };
        let targets: Vec<TracePath> = vec![(step, vec![0])]; // one target in this step

        // representative_size/new_size only fix the delta (+5 here); `cur` is read from the recipe.
        let (repr, new) = (1, 6);

        // generous caps: +5 fits in both -> accepted
        let generous = TermConstraints {
            max_result_term_size: cur + 100,
            ..TermConstraints::no_constraint()
        };
        assert!(replacement_within_caps(
            &trace, &targets, repr, new, &generous
        ));

        // per-step cap allows only +2 in this recipe -> +5 rejected
        let tight_step = TermConstraints {
            max_result_term_size: cur + 2,
            ..TermConstraints::no_constraint()
        };
        assert!(!replacement_within_caps(
            &trace,
            &targets,
            repr,
            new,
            &tight_step
        ));

        // NOTE: we no longer enforce a whole-trace node cap here — growth is bounded by the
        // per-step recipe cap times the number of steps (`max_result_trace_length`).

        // documented precondition: with the caps set *below* the already-imported seed, a
        // size-neutral or shrinking replacement is still accepted (the input is out of bounds
        // before any mutation; the mutator does not retroactively enforce the cap).
        let below_seed = TermConstraints {
            max_result_term_size: 0,
            ..TermConstraints::no_constraint()
        };
        assert!(replacement_within_caps(&trace, &targets, 4, 4, &below_seed)); // neutral
        assert!(replacement_within_caps(&trace, &targets, 9, 2, &below_seed)); // shrink
    }

    /// Whatever the scope, the *chosen* occurrence is always replaced. In particular a broader
    /// scope must not silently skip the mutation when the search for the other occurrences finds
    /// nothing.
    #[test_log::test]
    fn test_scoped_mutation_always_mutates_chosen_occurrence() {
        let mut rand = StdRand::with_seed(7);

        for weights in [
            ScopeWeights::new(1, 0, 0), // global only
            ScopeWeights::new(0, 1, 0), // step only
            ScopeWeights::new(0, 0, 1), // individual only
            ScopeWeights::default(),
        ] {
            let mut trace = setup_simple_trace();
            let path =
                choose_term_path_filtered(&trace, |_| true, &TermConstraints::default(), &mut rand)
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
                .find(|term| term.get_type_shape() == chosen.get_type_shape() && **term != chosen)
                .cloned()
            else {
                continue; // no valid replacement in this trace, nothing to assert
            };

            let targets = scoped_targets(
                &trace,
                &path,
                &chosen,
                &MutationConfig {
                    scope_weights: weights,
                    ..MutationConfig::default()
                },
                &mut rand,
            );
            let result = apply_to_targets(
                &mut trace,
                &targets,
                &replacement,
                &chosen,
                true,
                &TermConstraints::no_constraint(),
            );

            assert_eq!(
                result,
                MutationResult::Mutated,
                "weights {weights:?} should have mutated"
            );
            assert_eq!(
                find_term(&trace, &path).unwrap(),
                &replacement,
                "weights {weights:?}: the chosen occurrence must carry the replacement"
            );
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
        let mut mutator =
            ReplaceMatchMutator::new(MutationConfig::default_with_bit(), &TEST_SIGNATURE);

        loop {
            let mut trace = setup_simple_trace();
            mutator.mutate(&mut state, &mut trace).unwrap();

            if let Some(last) = trace.steps.iter().last() {
                match &last.action {
                    Action::Input(input) => match &input.recipe.term {
                        DYTerm::Variable(_) | DYTerm::Deconstructor(..) => {}
                        DYTerm::Application(_, subterms) | DYTerm::List(_, subterms) => {
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
            trace
                .steps
                .iter()
                .filter_map(|step| match &step.action {
                    Action::Input(input) => Some(&input.recipe),
                    Action::Output(_) => None,
                })
                .flat_map(|recipe| recipe.into_iter())
                .map(|term| match &term.term {
                    DYTerm::List(_, elements) => elements.len(),
                    _ => 0,
                })
                .sum()
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
        let mut mutator = ReplaceReuseMutator::new(MutationConfig::default_with_bit());

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

    /// Counts every deconstructor node appearing in the recipes of a trace.
    fn count_deconstructors(trace: &TestTrace) -> usize {
        trace
            .steps
            .iter()
            .filter_map(|step| match &step.action {
                Action::Input(input) => Some(&input.recipe),
                Action::Output(_) => None,
            })
            .map(|recipe| {
                recipe
                    .into_iter()
                    .filter(|t| matches!(&t.term, DYTerm::Deconstructor(..)))
                    .count()
            })
            .sum()
    }

    /// Returns whether every deconstructor of the trace is applied on a valid source, that is an
    /// opaque symbol, a variable or another deconstructor.
    fn all_deconstructor_sources_valid(trace: &TestTrace) -> bool {
        trace
            .steps
            .iter()
            .filter_map(|step| match &step.action {
                Action::Input(input) => Some(&input.recipe),
                Action::Output(_) => None,
            })
            .all(|recipe| {
                recipe.into_iter().all(|t| match &t.term {
                    DYTerm::Deconstructor(_, source, _) => is_deconstructible(source),
                    DYTerm::Variable(_) | DYTerm::Application(..) | DYTerm::List(..) => true,
                })
            })
    }

    /// Builds a variable term, the simplest valid deconstructor source.
    fn variable_term() -> TestTerm {
        Term::from(DYTerm::Variable(Signature::new_var(
            TypeShape::of::<Vec<u8>>(),
            Some(Source::Agent(AgentName::first())),
            None,
            0,
            false,
        )))
    }

    /// [`setup_simple_trace`] contains neither a variable nor an opaque symbol (the test signature
    /// declares no attribute), hence no valid deconstructor source: add a step whose recipe is a
    /// variable to provide one.
    fn setup_trace_with_variable() -> TestTrace {
        let mut trace = setup_simple_trace();
        trace.steps.push(Step {
            agent: AgentName::first(),
            action: Action::Input(InputAction {
                precomputations: vec![],
                recipe: variable_term(),
            }),
        });
        trace
    }

    #[test_log::test]
    fn test_make_deconstructor_mutator() {
        let mut state = create_state();
        let mut mutator = MakeDeconstructorMutator::new(TermConstraints::default(), true);

        // A single successful mutation should introduce exactly one deconstructor.
        let mut introduced = false;
        for _ in 0..50 {
            let mut trace = setup_trace_with_variable();
            if let Ok(MutationResult::Mutated) = mutator.mutate(&mut state, &mut trace) {
                assert!(count_deconstructors(&trace) >= 1);
                assert!(all_deconstructor_sources_valid(&trace));
                introduced = true;
                break;
            }
        }
        assert!(
            introduced,
            "MakeDeconstructorMutator never produced a deconstructor"
        );
    }

    /// Every sub-term of [`setup_simple_trace`] is a transparent application, whose sub-values are
    /// already spelled out in the recipe: there is nothing worth deconstructing there.
    #[test_log::test]
    fn test_make_deconstructor_mutator_needs_a_valid_source() {
        let mut state = create_state();
        let mut mutator = MakeDeconstructorMutator::new(TermConstraints::default(), true);

        for _ in 0..50 {
            let mut trace = setup_simple_trace();
            assert_eq!(
                mutator.mutate(&mut state, &mut trace).unwrap(),
                MutationResult::Skipped
            );
            assert_eq!(count_deconstructors(&trace), 0);
        }
    }

    /// Collects the query of every variable of a trace, together with the index of the step whose
    /// recipe holds it.
    fn all_queries(trace: &TestTrace) -> Vec<(usize, Query<AnyMatcher>)> {
        trace
            .steps
            .iter()
            .enumerate()
            .filter_map(|(step_index, step)| match &step.action {
                Action::Input(input) => Some((step_index, &input.recipe)),
                Action::Output(_) => None,
            })
            .flat_map(|(step_index, recipe)| {
                recipe.into_iter().filter_map(move |term| match &term.term {
                    DYTerm::Variable(variable) => Some((step_index, variable.query.clone())),
                    DYTerm::Application(..) | DYTerm::Deconstructor(..) | DYTerm::List(..) => None,
                })
            })
            .collect()
    }

    /// [`setup_simple_trace`] with one step per agent, so that the sources a knowledge query may
    /// draw from differ from step to step. It holds no variable, hence every query found after a
    /// mutation was created by that mutation.
    fn setup_multi_agent_trace() -> TestTrace {
        let mut trace = setup_simple_trace();
        let mut agent = AgentName::first();
        for step in &mut trace.steps {
            step.agent = agent;
            trace.descriptors.push(AgentDescriptor::from_name(agent));
            agent = agent.next();
        }
        // Give the first agent an output step, so that it can be a source.
        trace
            .steps
            .insert(1, OutputAction::new_step(AgentName::first()));
        trace
    }

    /// Records what an execution producing `multiplicity` values of `T` would.
    fn observe<T: 'static>(
        source: &Source,
        matcher: Option<AnyMatcher>,
        multiplicity: usize,
        available_from: usize,
    ) {
        with_observed_knowledge::<TestProtocolTypes, _>(|observed| {
            observed.record((0..multiplicity).map(|_| {
                (
                    TypeId::of::<T>(),
                    source.clone(),
                    matcher.clone(),
                    available_from,
                )
            }));
        });
    }

    /// Source, matcher and counter all come from one observation, and the source has to have
    /// produced something before the mutated step.
    #[test_log::test]
    fn test_make_knowledge_query_mutator() {
        let mut state = create_state();
        let mut mutator = MakeKnowledgeQueryMutator::new(TermConstraints::default(), true);

        clear_observed_knowledge::<TestProtocolTypes>();
        let first = Source::Agent(AgentName::first());
        observe::<HandshakeMessage>(&first, None, 2, 1);
        observe::<u32>(&first, Some(AnyMatcher), 1, 1);

        let mut introduced = false;
        for _ in 0..200 {
            let mut trace = setup_multi_agent_trace();
            assert!(all_queries(&trace).is_empty());
            if let Ok(MutationResult::Mutated) = mutator.mutate(&mut state, &mut trace) {
                let queries = all_queries(&trace);
                assert!(!queries.is_empty(), "the mutation created no query");
                for (step_index, query) in queries {
                    assert!(!query.is_claim, "a knowledge query never reads the claims");
                    assert!(
                        query.counter < 2,
                        "counter {} exceeds the observed multiplicity",
                        query.counter
                    );
                    if let Some(Source::Agent(agent)) = query.source {
                        let spoke_earlier = trace.steps[..step_index].iter().any(|step| {
                            step.agent == agent && matches!(step.action, Action::Output(_))
                        });
                        assert!(
                            spoke_earlier,
                            "queried agent {agent} produced no knowledge before step {step_index}"
                        );
                    }
                }
                introduced = true;
            }
        }
        assert!(
            introduced,
            "MakeKnowledgeQueryMutator never created a query"
        );
    }

    /// Nothing is queried out of a pool holding no type the trace uses.
    #[test_log::test]
    fn test_make_knowledge_query_mutator_only_queries_observed_types() {
        let mut state = create_state();
        let mut mutator = MakeKnowledgeQueryMutator::new(TermConstraints::default(), true);

        for pool in ["empty", "unrelated type"] {
            clear_observed_knowledge::<TestProtocolTypes>();
            if pool == "unrelated type" {
                // `HmacKey` appears in the test signature but not in the fixture.
                observe::<HmacKey>(&Source::Agent(AgentName::first()), None, 4, 1);
            }

            for _ in 0..200 {
                let mut trace = setup_multi_agent_trace();
                assert_eq!(
                    mutator.mutate(&mut state, &mut trace).unwrap(),
                    MutationResult::Skipped,
                    "a query was created out of a {pool} pool"
                );
                assert!(all_queries(&trace).is_empty());
            }
        }
    }

    /// A query is never placed before the step where its knowledge becomes readable.
    #[test_log::test]
    fn test_make_knowledge_query_mutator_respects_the_step_the_knowledge_appears_at() {
        let mut state = create_state();
        let mut mutator = MakeKnowledgeQueryMutator::new(TermConstraints::default(), true);

        clear_observed_knowledge::<TestProtocolTypes>();
        let available_from = setup_multi_agent_trace().steps.len() - 1;
        observe::<HandshakeMessage>(&Source::Agent(AgentName::first()), None, 2, available_from);

        let mut introduced = false;
        for _ in 0..200 {
            let mut trace = setup_multi_agent_trace();
            if mutator.mutate(&mut state, &mut trace).unwrap() == MutationResult::Mutated {
                for (step_index, query) in all_queries(&trace) {
                    assert!(
                        step_index >= available_from,
                        "a query was created at step {step_index}, before its knowledge exists                          (from step {available_from} on): {query}"
                    );
                }
                introduced = true;
            }
        }
        assert!(introduced, "no query was created at all");
    }

    /// Matcher and counter are the ones the knowledge was observed under.
    #[test_log::test]
    fn test_make_knowledge_query_mutator_draws_matcher_and_counter_from_the_pool() {
        let mut state = create_state();
        let mut mutator = MakeKnowledgeQueryMutator::new(TermConstraints::default(), true);

        clear_observed_knowledge::<TestProtocolTypes>();
        observe::<HandshakeMessage>(&Source::Agent(AgentName::first()), Some(AnyMatcher), 3, 1);

        let mut counters = HashSet::new();
        for _ in 0..200 {
            let mut trace = setup_multi_agent_trace();
            if mutator.mutate(&mut state, &mut trace).unwrap() == MutationResult::Mutated {
                for (_, query) in all_queries(&trace) {
                    assert_eq!(query.matcher, Some(AnyMatcher));
                    assert!(query.counter < 3);
                    counters.insert(query.counter);
                }
            }
        }
        assert!(
            counters.len() > 1,
            "the counter should vary over the observed multiplicity, saw {counters:?}"
        );
    }

    /// The restriction is also an invariant of the other DY mutators: none of them may replace the
    /// source of an existing deconstructor with a transparent application.
    #[test_log::test]
    fn test_dy_mutators_preserve_deconstructor_sources() {
        let mut state = create_state();
        let mut swap = SwapMutator::new(TermConstraints::default(), true);
        let mut replace_reuse = ReplaceReuseMutator::new(MutationConfig::default());
        let mut make_query = MakeKnowledgeQueryMutator::new(TermConstraints::default(), true);
        let mut replace_match =
            ReplaceMatchMutator::new(MutationConfig::default(), &TEST_SIGNATURE);

        // A trace with a step deconstructing a variable, i.e. a valid source that the other
        // mutators could otherwise overwrite with a transparent application: the untouched
        // client-hello recipe holds `fn_empty_bytes_vec`, a transparent application of the very
        // type of that source.
        let make_trace = || {
            let mut trace = setup_simple_trace();
            let source = variable_term();
            assert_eq!(
                source.get_type_shape(),
                term! { fn_empty_bytes_vec }.get_type_shape(),
                "the fixture needs a same-typed transparent application to tempt the mutators"
            );
            let deconstructor = Term::from(DYTerm::Deconstructor(
                source.get_type_shape().clone(),
                Box::new(source),
                Query {
                    source: None,
                    matcher: None,
                    counter: 0,
                    is_claim: false,
                },
            ));
            trace.steps.push(Step {
                agent: AgentName::first(),
                action: Action::Input(InputAction {
                    precomputations: vec![],
                    recipe: deconstructor,
                }),
            });
            trace
        };

        for _ in 0..200 {
            let mut trace = make_trace();
            swap.mutate(&mut state, &mut trace).unwrap();
            assert!(all_deconstructor_sources_valid(&trace));

            let mut trace = make_trace();
            replace_reuse.mutate(&mut state, &mut trace).unwrap();
            assert!(all_deconstructor_sources_valid(&trace));

            let mut trace = make_trace();
            replace_match.mutate(&mut state, &mut trace).unwrap();
            assert!(all_deconstructor_sources_valid(&trace));

            let mut trace = make_trace();
            make_query.mutate(&mut state, &mut trace).unwrap();
            assert!(all_deconstructor_sources_valid(&trace));
        }
    }

    /// A [`DYTerm::Deconstructor`] node is a regular typed sub-term, so the generic
    /// [`ReplaceReuseMutator`] can select it and replace it with another same-typed sub-term reused
    /// from the trace (there is no dedicated "unwrap" mutator: replacement handles it). Here the
    /// deconstructor result type is the one of a term appearing in the trace, so replacing it with
    /// that term removes it.
    #[test_log::test]
    fn test_replace_reuse_mutator_replaces_deconstructor() {
        let mut state = create_state();

        // Add to the trace a step whose recipe is a deconstructor over a variable (a valid source)
        // and whose result type is the one of `fn_protocol_version12`, which the untouched
        // client-hello recipe provides as a same-typed non-deconstructor replacement.
        let make_trace = || {
            let mut trace = setup_simple_trace();
            let result_type = term! { fn_protocol_version12 }.get_type_shape().clone();
            let deconstructor = Term::from(DYTerm::Deconstructor(
                result_type,
                Box::new(variable_term()),
                Query {
                    source: None,
                    matcher: None,
                    counter: 0,
                    is_claim: false,
                },
            ));
            trace.steps.push(Step {
                agent: AgentName::first(),
                action: Action::Input(InputAction {
                    precomputations: vec![],
                    recipe: deconstructor,
                }),
            });
            assert_eq!(count_deconstructors(&trace), 1);
            trace
        };

        let mut mutator = ReplaceReuseMutator::new(MutationConfig::default());

        // Over enough trials, ReplaceReuseMutator eventually selects the deconstructor node and
        // replaces it with a same-typed non-deconstructor term, removing the deconstructor.
        let mut replaced = false;
        for _ in 0..200 {
            let mut trace = make_trace();
            if let Ok(MutationResult::Mutated) = mutator.mutate(&mut state, &mut trace) {
                if count_deconstructors(&trace) == 0 {
                    replaced = true;
                    break;
                }
            }
        }
        assert!(
            replaced,
            "ReplaceReuseMutator never replaced the deconstructor with a same-typed term"
        );
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
