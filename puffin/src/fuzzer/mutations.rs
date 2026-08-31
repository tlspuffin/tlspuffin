use std::borrow::Cow;

use libafl::corpus::HasCurrentCorpusId;
use libafl::prelude::*;
use libafl_bolts::prelude::*;

use super::utils::{
    choose, choose_filtered, choose_iter, choose_term, choose_term_filtered_mut, choose_term_path,
    choose_term_path_filtered, find_all_term_filtered, find_term, find_term_mut, reservoir_sample,
    Choosable, TermConstraints, TracePath,
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
        }
    }
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
        ..
    } = mutation_config;

    tuple_list!(
        RepeatMutator::new(max_trace_length, with_dy),
        SkipMutator::new(min_trace_length, with_dy),
        ReplaceReuseMutator::new(term_constraints, with_dy, with_bit_level),
        ReplaceMatchMutator::new(term_constraints, signature, with_dy),
        RemoveAndLiftMutator::new(term_constraints, with_dy),
        MakeDeconstructorMutator::new(term_constraints, with_dy),
        MakeKnowledgeQueryMutator::new(term_constraints, with_dy),
        GenerateMutator::new(
            0,
            fresh_zoo_after,
            term_constraints,
            None,
            signature,
            put_registry,
            with_dy
        ), /* Refresh zoo after 100000M mutations */
        SwapMutator::new(term_constraints, with_dy),
    )
}

/// SWAP: Swaps a sub-term with a different sub-term which is part of the trace

/// (such that types match).
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
                DYTerm::Application(_, subterms) =>
                    {
                        subterms
                            .find_subterm(|subterm| match &subterm.term {
                                DYTerm::Variable(_) | DYTerm::Deconstructor(..) => false,
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
                DYTerm::Variable(_) | DYTerm::Deconstructor(..) => {
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
    constraints: TermConstraints,
    signature: &'static Signature<PT>,
    phantom_s: std::marker::PhantomData<S>,
    with_dy: bool,
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
    ) -> Self {
        Self {
            constraints: TermConstraints {
                must_be_symbolic: true, // forbid replacing function symbols in terms with payloads
                ..constraints
            },
            signature,
            phantom_s: std::marker::PhantomData,
            with_dy,
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
        let signature = self.signature;
        if let Some(to_mutate_path) = choose_term_path(trace, &self.constraints, rand) {
            // At the source position of a deconstructor, only an opaque symbol may replace the
            // current symbol, since a variable becoming a transparent application (or an opaque
            // symbol becoming a transparent one) would break [`is_deconstructible`].
            let must_stay_opaque = is_deconstructor_source(trace, &to_mutate_path);
            let Some(to_mutate) = find_term_mut(trace, &to_mutate_path) else {
                log::debug!("       Skipped {}", self.name());
                return Ok(MutationResult::Skipped);
            };
            log::debug!("[Mutation] ReplaceMatchMutator on term\n{}", to_mutate);
            match &mut to_mutate.term {
                DYTerm::Variable(variable) => {
                    if let Some((shape, dynamic_fn)) = signature.functions.choose_filtered(
                        |(shape, _)| {
                            variable.typ == shape.return_type
                                && shape.is_constant()
                                && (!must_stay_opaque || is_opaque_shape(signature, shape))
                        },
                        rand,
                    ) {
                        to_mutate.mutate(Term::from(DYTerm::Application(
                            Function::new(shape.clone(), dynamic_fn.clone()),
                            Vec::new(),
                        )));
                        Ok(MutationResult::Mutated)
                    } else {
                        log::debug!("       Skipped {}", self.name());
                        Ok(MutationResult::Skipped)
                    }
                }
                DYTerm::Application(func_mut, _) => {
                    if let Some((shape, dynamic_fn)) = signature.functions.choose_filtered(
                        |(shape, _)| {
                            func_mut.shape() != shape
                                && func_mut.shape().return_type == shape.return_type
                                && func_mut.shape().argument_types == shape.argument_types
                                && (!must_stay_opaque || is_opaque_shape(signature, shape))
                        },
                        rand,
                    ) {
                        func_mut.change_function(shape.clone(), dynamic_fn.clone());
                        Ok(MutationResult::Mutated)
                    } else {
                        log::debug!("       Skipped {}", self.name());
                        Ok(MutationResult::Skipped)
                    }
                }
                // A deconstructor has no function symbol to replace.
                DYTerm::Deconstructor(..) => {
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
}

impl<S> ReplaceReuseMutator<S>
where
    S: HasRand,
{
    #[must_use]
    pub const fn new(constraints: TermConstraints, with_dy: bool, with_bit: bool) -> Self {
        Self {
            constraints,
            phantom_s: std::marker::PhantomData,
            with_dy,
            with_bit,
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
                // Never turn the source of a deconstructor into a term we would not have been
                // allowed to build a deconstructor over in the first place.
                if is_deconstructor_source(trace, &to_replace_path)
                    && !is_deconstructible(&replacement)
                {
                    log::debug!("[ReplaceReuseMutator] Skipped as the chosen replacement is not a valid deconstructor source.");
                    log::debug!("       Skipped {}", self.name());
                    return Ok(MutationResult::Skipped);
                }
                let Some(to_replace) = find_term_mut(trace, &to_replace_path) else {
                    log::debug!("       Skipped {}", self.name());
                    return Ok(MutationResult::Skipped);
                };
                if self.with_bit {
                    let nb_payloads = trace_nb_payloads + replacement.all_payloads().len()
                        - to_replace.all_payloads().len();
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
                to_replace.mutate(replacement);
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
                    (to_mutate_path, to_mutate, new_term)
                } else {
                    return Ok(MutationResult::Skipped);
                }
            } else {
                return Ok(MutationResult::Skipped);
            }
        };

        // Apply mutation globally with probability 1/2
        if rand.between(0, 1) == 0 {
            // Apply globally
            let mut mutated = false;
            for trace_path in find_all_term_filtered(
                trace,
                |term: &Term<PB::ProtocolTypes>| {
                    *term.get_type_shape() == *to_mutate.get_type_shape() // supposed to speed up comparison
                        && *term == *to_mutate
                },
                // We seek for all matches, independently of the term constraints, except for the
                // max_term_size_explore constraint for efficiency reasons
                &TermConstraints {
                    max_term_size_explore: TermConstraints::default().max_term_size_explore,
                    ..TermConstraints::no_constraint()
                },
            ) {
                // Skip the matches sitting under a deconstructor when the generated term would
                // not be a valid source there.
                if is_deconstructor_source(trace, &trace_path) && !is_deconstructible(new_term) {
                    log::debug!(
                        "[GenerateMutator] [Global] skipping a match: the generated term is not a valid deconstructor source: {:?}",
                        trace_path
                    );
                    continue;
                }
                if let Some(term_mut) = find_term_mut(trace, &trace_path) {
                    log::debug!(
                        "[GenerateMutator] [Global] we found a match and do the replacement: {:?}",
                        trace_path
                    );
                    term_mut.mutate(new_term.clone());
                    mutated = true;
                } else {
                    log::debug!("[GenerateMutator::mutate] Could not find term to mutate");
                }
            }
            if mutated {
                Ok(MutationResult::Mutated)
            } else {
                Ok(MutationResult::Skipped)
            }
        } else {
            // Apply locally, only once
            if is_deconstructor_source(trace, &to_mutate_path) && !is_deconstructible(new_term) {
                log::debug!(
                    "[GenerateMutator] [Local] skipped: the generated term is not a valid deconstructor source"
                );
                return Ok(MutationResult::Skipped);
            }
            if let Some(term_mut) = find_term_mut(trace, &to_mutate_path) {
                log::debug!(
                    "[GenerateMutator] [Local] replacement at: {:?}",
                    to_mutate_path
                );
                term_mut.mutate(new_term.clone());
                Ok(MutationResult::Mutated)
            } else {
                log::debug!("[GenerateMutator::mutate] Could not find term to mutate");
                Ok(MutationResult::Skipped)
            }
        }
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
    use crate::term;
    use crate::trace::{Action, InputAction, OutputAction, Source, Step};

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

    #[test_log::test]
    fn test_replace_match_mutator() {
        let _server = AgentName::first();
        let mut state = create_state();
        let mut mutator =
            ReplaceMatchMutator::new(TermConstraints::default(), &TEST_SIGNATURE, true);

        loop {
            let mut trace = setup_simple_trace();
            mutator.mutate(&mut state, &mut trace).unwrap();

            if let Some(last) = trace.steps.iter().last() {
                match &last.action {
                    Action::Input(input) => match &input.recipe.term {
                        DYTerm::Variable(_) | DYTerm::Deconstructor(..) => {}
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
        let mut mutator = ReplaceReuseMutator::new(TermConstraints::default(), true, true);

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
                    DYTerm::Variable(_) | DYTerm::Application(..) => true,
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
                    DYTerm::Application(..) | DYTerm::Deconstructor(..) => None,
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
        let mut replace_reuse = ReplaceReuseMutator::new(TermConstraints::default(), true, false);
        let mut make_query = MakeKnowledgeQueryMutator::new(TermConstraints::default(), true);
        let mut replace_match =
            ReplaceMatchMutator::new(TermConstraints::default(), &TEST_SIGNATURE, true);

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

        let mut mutator = ReplaceReuseMutator::new(TermConstraints::default(), true, false);

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
