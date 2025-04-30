use anyhow::Result;
use libafl::prelude::*;
use libafl_bolts::prelude::*;

use super::utils::{
    choose, choose_filtered, choose_iter, choose_term, choose_term_filtered_mut, choose_term_mut,
    choose_term_path_filtered, find_term_mut, Choosable, TermConstraints, TracePath,
};
use crate::algebra::atoms::Function;
use crate::algebra::signature::Signature;
use crate::algebra::{DYTerm, Subterms, Term, TermType};
use crate::fuzzer::bit_mutations::{
    havoc_mutations_dy, BitFlipMutatorDY, ByteAddMutatorDY, ByteDecMutatorDY, ByteFlipMutatorDY,
    ByteIncMutatorDY, ByteInterestingMutatorDY, ByteNegMutatorDY, ByteRandMutatorDY,
    BytesCopyMutatorDY, BytesDeleteMutatorDY, BytesExpandMutatorDY, BytesInsertCopyMutatorDY,
    BytesInsertMutatorDY, BytesRandInsertMutatorDY, BytesRandSetMutatorDY, BytesSetMutatorDY,
    BytesSwapMutatorDY, CrossoverInsertMutatorDY, CrossoverReplaceMutatorDY, DwordAddMutatorDY,
    DwordInterestingMutatorDY, QwordAddMutatorDY, SpliceMutatorDY, WordAddMutatorDY,
    WordInterestingMutatorDY,
};
use crate::fuzzer::term_zoo::TermZoo;
use crate::protocol::{ProtocolBehavior, ProtocolTypes};
use crate::put_registry::PutRegistry;
use crate::trace::{Spawner, Trace, TraceContext};

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
}

impl Default for MutationConfig {
    //  TODO:EVAL: evaluate modif to this config
    fn default() -> Self {
        Self {
            fresh_zoo_after: 100000,
            max_trace_length: 15,
            min_trace_length: 2,
            term_constraints: TermConstraints::default(),
            with_bit_level: true,
            with_dy: true,
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
// MakeMessage
    MakeMessage<'harness, S,PB>,
// Bit-level mutations
// -> Type of the mutations that compose the Havoc mutator (copied and pasted from above)
    BitFlipMutatorDY<S>,
    ByteFlipMutatorDY<S>,
    ByteIncMutatorDY<S>,
    ByteDecMutatorDY<S>,
    ByteNegMutatorDY<S>,
    ByteRandMutatorDY<S>,
    ByteAddMutatorDY<S>,
    WordAddMutatorDY<S>,
    DwordAddMutatorDY<S>,
    QwordAddMutatorDY<S>,
    ByteInterestingMutatorDY<S>,
    WordInterestingMutatorDY<S>,
    DwordInterestingMutatorDY<S>,
    BytesDeleteMutatorDY<S>,
    BytesDeleteMutatorDY<S>,
    BytesDeleteMutatorDY<S>,
    BytesDeleteMutatorDY<S>,
    BytesExpandMutatorDY<S>,
    BytesInsertMutatorDY<S>,
    BytesRandInsertMutatorDY<S>,
    BytesSetMutatorDY<S>,
    BytesRandSetMutatorDY<S>,
    BytesCopyMutatorDY<S>,
    BytesInsertCopyMutatorDY<S>,
    BytesSwapMutatorDY<S>,
    CrossoverInsertMutatorDY<S>,
    CrossoverReplaceMutatorDY<S>,
    SpliceMutatorDY<S>,
);

pub(crate) fn remove_prefix_and_type(str: &str) -> &str {
    str.splitn(2, '<').collect::<Vec<&str>>()[0]
        .split(':')
        .collect::<Vec<&str>>()
        .last()
        .unwrap()
}

/// Normalize a vector of probabilities
pub fn normalize_proba(v: &mut Vec<f32>) {
    let sum: f32 = v.iter().sum();
    if sum == 0.0 {
        panic!("Division by 0!");
    }
    for i in v.iter_mut() {
        *i /= sum;
    }
}

/// Compute probabilities for the mutations
pub fn proba_mutations(with_bit_level: bool, with_dy: bool, nb_executions: usize) -> Vec<f32> {
    let dy_over_bit_level = // probability to pick dy over bit-level mutations
        if !with_bit_level {
            1f32
        } else if !with_dy {
            0f32
        } else if nb_executions > 1000 {
            0.2 + 0.8 * 1000f32 / nb_executions as f32 // 1000->10 000 executions, transitioning p=1->p=0.2
        } else {
            1f32 // only DY before 1000 executions
        };
    let number_of_dy_mutations = 7;
    let number_of_bit_mutations = 28;
    let proba_dy = if with_dy {
        dy_over_bit_level / number_of_dy_mutations as f32
    } else {
        0f32
    };
    let mut probabilities_dy = vec![proba_dy; number_of_dy_mutations];
    let proba_bit = if with_bit_level {
        (1f32 - dy_over_bit_level) / number_of_bit_mutations as f32
    } else {
        0f32
    };
    let proba_make_message = proba_bit; // 28 times less likely than other bit-level mutations
                                        // (since unique versus 28 bit-level mutations)

    let probabilities_bit = vec![proba_bit; number_of_bit_mutations];
    probabilities_dy.push(proba_make_message);
    probabilities_dy.extend(probabilities_bit);
    normalize_proba(&mut probabilities_dy);
    assert_eq!(probabilities_dy.len(), 36);
    probabilities_dy
    // vec![
    //     0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.2, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
    //     0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
    // ]
    // vec![
    //     0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.4, 0.6, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
    //     0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
    // ]
}

#[must_use]
pub fn trace_mutations<'harness, S, PT: ProtocolTypes, PB>(
    min_trace_length: usize,
    max_trace_length: usize,
    constraints: TermConstraints,
    fresh_zoo_after: u64,
    with_bit_level: bool,
    with_dy: bool,
    signature: &'static Signature<PT>,
    put_registry: &'harness PutRegistry<PB>,
) -> DyMutations<'harness, PT, PB, S>
where
    S: HasCorpus + HasMetadata + HasMaxSize + HasRand,
    PB: ProtocolBehavior<ProtocolTypes = PT>,
{
    tuple_list!(
        RepeatMutator::new(max_trace_length, with_dy),
        SkipMutator::new(min_trace_length, with_dy),
        ReplaceReuseMutator::new(constraints, with_dy),
        ReplaceMatchMutator::new(constraints, signature, with_dy),
        RemoveAndLiftMutator::new(constraints, with_dy),
        GenerateMutator::new(
            0,
            fresh_zoo_after,
            constraints,
            None,
            signature,
            put_registry,
            with_dy
        ), // Refresh zoo after 100000M mutations
        SwapMutator::new(constraints, with_dy),
        MakeMessage::new(constraints, put_registry, with_bit_level, with_dy),
    )
    .merge(havoc_mutations_dy(with_bit_level))
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
    fn mutate(
        &mut self,
        state: &mut S,
        trace: &mut Trace<PT>,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        log::info!("[DY] Start mutate with {}", self.name());
        if !self.with_dy {
            return Ok(MutationResult::Skipped);
        }
        let _a = BytesInsertMutator;
        let rand = state.rand_mut();
        if let Some((term_a, trace_path_a)) = choose(trace, self.constraints, rand) {
            if let Some(trace_path_b) = choose_term_path_filtered(
                trace,
                |term: &Term<PT>| term.get_type_shape() == term_a.get_type_shape(),
                // TODO-bitlevel: maybe also check that both terms are .is_symbolic()
                self.constraints,
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
        log::info!("       Skipped {}", self.name());
        Ok(MutationResult::Skipped)
    }
}
impl<S> Named for SwapMutator<S>
where
    S: HasRand,
{
    fn name(&self) -> &str {
        remove_prefix_and_type(std::any::type_name::<Self>())
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
    fn mutate(
        &mut self,
        state: &mut S,
        trace: &mut Trace<PT>,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        log::info!("[DY] Start mutate with {}", self.name());
        if !self.with_dy {
            return Ok(MutationResult::Skipped);
        }
        let rand = state.rand_mut();
        let filter = |term: &Term<PT>| match &term.term {
            DYTerm::Variable(_) => false,
            DYTerm::Application(_, subterms) =>
            // TODO-bitlevel: maybe add: term.is_symbolic() &&
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
        };
        if let Some(to_mutate) = choose_term_filtered_mut(trace, filter, self.constraints, rand) {
            log::debug!(
                "[Mutation] Mutate RemoveAndLiftMutator on term\n{}",
                to_mutate
            );
            match &mut to_mutate.term {
                // TODO-bitlevel: maybe also SKIP if not(to_mutate.is_symbolic())
                DYTerm::Variable(_) => {
                    log::info!("       Skipped {}", self.name());
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
                    log::info!("       Skipped {}", self.name());
                    Ok(MutationResult::Skipped)
                }
            }
        } else {
            log::info!("       Skipped {}", self.name());
            Ok(MutationResult::Skipped)
        }
    }
}

impl<S> Named for RemoveAndLiftMutator<S>
where
    S: HasRand,
{
    fn name(&self) -> &str {
        remove_prefix_and_type(std::any::type_name::<Self>())
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
            constraints,
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
    fn mutate(
        &mut self,
        state: &mut S,
        trace: &mut Trace<PT>,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        log::info!("[DY] Start mutate with {}", self.name());
        if !self.with_dy {
            return Ok(MutationResult::Skipped);
        }
        let rand = state.rand_mut();
        if let Some(to_mutate) = choose_term_mut(trace, self.constraints, rand) {
            log::debug!("[Mutation] ReplaceMatchMutator on term\n{}", to_mutate);
            match &mut to_mutate.term {
                // TODO-bitlevel: maybe also SKIP if not(to_mutate.is_symbolic())
                DYTerm::Variable(variable) => {
                    if let Some((shape, dynamic_fn)) = self.signature.functions.choose_filtered(
                        |(shape, _)| variable.typ == shape.return_type && shape.is_constant(),
                        rand,
                    ) {
                        to_mutate.mutate(Term::from(DYTerm::Application(
                            Function::new(shape.clone(), dynamic_fn.clone()),
                            Vec::new(),
                        )));
                        Ok(MutationResult::Mutated)
                    } else {
                        log::info!("       Skipped {}", self.name());
                        Ok(MutationResult::Skipped)
                    }
                }
                DYTerm::Application(func_mut, _) => {
                    if let Some((shape, dynamic_fn)) = self.signature.functions.choose_filtered(
                        |(shape, _)| {
                            func_mut.shape() != shape
                                && func_mut.shape().return_type == shape.return_type
                                && func_mut.shape().argument_types == shape.argument_types
                        },
                        rand,
                    ) {
                        func_mut.change_function(shape.clone(), dynamic_fn.clone());
                        Ok(MutationResult::Mutated)
                    } else {
                        log::info!("       Skipped {}", self.name());
                        Ok(MutationResult::Skipped)
                    }
                }
            }
        } else {
            log::info!("       Skipped {}", self.name());
            Ok(MutationResult::Skipped)
        }
    }
}

impl<S, PT: ProtocolTypes> Named for ReplaceMatchMutator<S, PT>
where
    S: HasRand,
{
    fn name(&self) -> &str {
        remove_prefix_and_type(std::any::type_name::<Self>())
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
}

impl<S> ReplaceReuseMutator<S>
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

impl<S, PT: ProtocolTypes> Mutator<Trace<PT>, S> for ReplaceReuseMutator<S>
where
    S: HasRand,
{
    fn mutate(
        &mut self,
        state: &mut S,
        trace: &mut Trace<PT>,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        log::info!("[DY] Start mutate with {}", self.name());
        if !self.with_dy {
            return Ok(MutationResult::Skipped);
        }
        let rand = state.rand_mut();
        if let Some(replacement) = choose_term(trace, self.constraints, rand).cloned() {
            if let Some(to_replace) = choose_term_filtered_mut(
                trace,
                |term: &Term<PT>| term.get_type_shape() == replacement.get_type_shape(),
                self.constraints,
                rand,
            ) {
                log::debug!(
                    "[Mutation] Mutate ReplaceReuseMutator on terms\n {} and\n{}",
                    to_replace,
                    replacement
                );
                to_replace.mutate(replacement);
                return Ok(MutationResult::Mutated);
            }
        }
        log::info!("       Skipped {}", self.name());
        Ok(MutationResult::Skipped)
    }
}

impl<S> Named for ReplaceReuseMutator<S>
where
    S: HasRand,
{
    fn name(&self) -> &str {
        remove_prefix_and_type(std::any::type_name::<Self>())
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
    fn mutate(
        &mut self,
        state: &mut S,
        trace: &mut Trace<PT>,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        log::info!("[DY] Start mutate with {}", self.name());
        if !self.with_dy {
            return Ok(MutationResult::Skipped);
        }
        let steps = &mut trace.steps;
        let length = steps.len();
        if length <= self.min_trace_length {
            log::info!("       Skipped {}", self.name());
            return Ok(MutationResult::Skipped);
        }
        if length == 0 {
            log::info!("       Skipped {}", self.name());
            return Ok(MutationResult::Skipped);
        }
        let remove_index = state.rand_mut().between(0, (length - 1) as u64) as usize;
        log::debug!("[Mutation] Mutate SkipMutator on step {remove_index}");
        steps.remove(remove_index);
        Ok(MutationResult::Mutated)
    }
}
impl<S> Named for SkipMutator<S>
where
    S: HasRand,
{
    fn name(&self) -> &str {
        remove_prefix_and_type(std::any::type_name::<Self>())
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
    fn mutate(
        &mut self,
        state: &mut S,
        trace: &mut Trace<PT>,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        log::info!("[DY] Start mutate with {}", self.name());
        if !self.with_dy {
            return Ok(MutationResult::Skipped);
        }
        let steps = &trace.steps;
        let length = steps.len();
        if length >= self.max_trace_length {
            log::info!("       Skipped {}", self.name());
            return Ok(MutationResult::Skipped);
        }
        if length == 0 {
            log::info!("       Skipped {}", self.name());
            return Ok(MutationResult::Skipped);
        }
        let insert_index = state.rand_mut().between(0, length as u64) as usize;
        let step = state.rand_mut().choose(steps).clone();
        log::debug!("[Mutation] Mutate RepeatMutator on step {insert_index}");
        trace.steps.insert(insert_index, step);
        Ok(MutationResult::Mutated)
    }
}
impl<S> Named for RepeatMutator<S>
where
    S: HasRand,
{
    fn name(&self) -> &str {
        remove_prefix_and_type(std::any::type_name::<Self>())
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
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        log::info!("[DY] Start mutate with {}", self.name());
        if !self.with_dy {
            return Ok(MutationResult::Skipped);
        }
        let rand = state.rand_mut();
        if let Some(to_mutate) = choose_term_mut(trace, self.constraints, rand) {
            log::debug!("[Mutation] Mutate GenerateMutator on term\n{}", to_mutate);
            self.mutation_counter += 1;
            let zoo = if self.mutation_counter % self.refresh_zoo_after == 0 {
                log::debug!("[Mutation] Mutate GenerateMutator: refresh zoo");
                let spawner = Spawner::new(self.put_registry.clone());
                let ctx = TraceContext::new(spawner);
                // TODO: ? Maybe remove some that cannot be evaluated!
                // TODO: we should quantify whether this would be costly or not --> Maybe don't do
                // it!
                self.zoo.insert(TermZoo::generate(
                    &ctx,
                    self.signature,
                    rand,
                    self.constraints.zoo_gen_how_many,
                ))
            } else {
                self.zoo.get_or_insert_with(|| {
                    let spawner = Spawner::new(self.put_registry.clone());
                    let ctx = TraceContext::new(spawner);
                    TermZoo::generate(
                        &ctx,
                        self.signature,
                        rand,
                        self.constraints.zoo_gen_how_many,
                    )
                })
            };
            if let Some(term) = zoo.choose_filtered(
                |term| to_mutate.get_type_shape() == term.get_type_shape(),
                rand,
            ) {
                to_mutate.mutate(term.clone());
                Ok(MutationResult::Mutated)
            } else {
                log::info!("       Skipped {}", self.name());
                Ok(MutationResult::Skipped)
            }
        } else {
            log::info!("       Skipped {}", self.name());
            Ok(MutationResult::Skipped)
        }
    }
}

impl<'a, S, PB: ProtocolBehavior> Named for GenerateMutator<'a, S, PB>
where
    S: HasRand,
{
    fn name(&self) -> &str {
        remove_prefix_and_type(std::any::type_name::<Self>())
    }
}

// *************************************************************************************************
// ***** Start bit-level Mutations

/// MAKE MESSAGE : transforms a sub term into a message which can then be mutated using havoc
pub struct MakeMessage<'a, S, PB>
where
    S: HasRand,
{
    with_bit_level: bool,
    constraints: TermConstraints,
    phantom_s: (std::marker::PhantomData<S>, std::marker::PhantomData<PB>),
    put_registry: &'a PutRegistry<PB>,
    with_dy: bool,
}

impl<'a, S, PB> MakeMessage<'a, S, PB>
where
    S: HasRand,
{
    #[must_use]
    pub const fn new(
        constraints: TermConstraints,
        put_registry: &'a PutRegistry<PB>,
        with_bit_level: bool,
        with_dy: bool,
    ) -> Self {
        Self {
            with_bit_level,
            constraints,
            phantom_s: (std::marker::PhantomData, std::marker::PhantomData),
            put_registry,
            with_dy,
        }
    }
}

/// `MakeMessage` on the term at path `path` in `tr`.
fn make_message_term<PT: ProtocolTypes, PB: ProtocolBehavior<ProtocolTypes = PT>>(
    tr: &mut Trace<PT>,
    path: &TracePath,
    ctx: &mut TraceContext<PB>,
) -> Result<(), anyhow::Error>
where
    PB: ProtocolBehavior<ProtocolTypes = PT>,
{
    // Only execute shorter trace: trace[0..step_index])
    // execute the PUT on the first step_index steps and store the resulting trace context
    tr.execute_until_step(ctx, path.0, &mut 0).err().map(|e| {
        // 20% to 50% MakeMessage mutations fail, so this is a bit costly :(
        // TODO: we could memoize the recipe evaluation in a Option<ConcreteMessage> and use that
        log::debug!("mutation::MakeMessage trace is not executable until step {},\
            could only happen if this mutation is scheduled with other mutations that create a non-executable trace.\
            Error: {e}", path.0);
        log::trace!("{}", &tr);
        log::info!("       Skipped MakeMessage");
        Ok::<MutationResult, Error>(MutationResult::Skipped)
    });

    let t = find_term_mut(tr, path).expect("make_message_term - Should never happen.");
    // We get payload_0 by symbolically evaluating the term! (and not full eval with potential
    // payloads in sub-terms). This because, doing differently would dramatically complexify the
    // computation of replace_payloads. See terms.rs. Also, one could argue the mutations of the
    // strict sub-terms could have been done on the larger term in the first place.
    t.make_payload(ctx)?;
    Ok(())
}

impl<'a, S, PT: ProtocolTypes, PB: ProtocolBehavior<ProtocolTypes = PT>> Mutator<Trace<PT>, S>
    for MakeMessage<'a, S, PB>
where
    S: HasRand,
    PB: ProtocolBehavior<ProtocolTypes = PT>,
{
    fn mutate(
        &mut self,
        state: &mut S,
        trace: &mut Trace<PT>,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        log::info!("[Bit] Start mutate with {}", self.name());
        if !self.with_bit_level {
            log::debug!("[Mutation-bit] Mutate MakeMessage skipped because bit-level mutations are disabled");
            return Ok(MutationResult::Skipped);
        }
        let nb_payloads = trace.all_payloads().len();
        let nb_terms = trace.steps.len();
        let no_more_new_payloads = nb_payloads / std::cmp::max(1, nb_terms)
            > self.constraints.threshold_max_payloads_per_term;
        if no_more_new_payloads {
            log::debug!("[MakeMessage] on a trace with too many payloads: {trace}")
        } else {
            log::debug!("[MakeMessage] Do a regular MakeMessage")
        }
        let rand = state.rand_mut();
        let mut constraints_make_message = TermConstraints {
            must_be_symbolic: true, /* we exclude non-symbolic terms, which were already mutated
                                     * with MakeMessage */
            no_payload_in_subterm: false, /* change to true to exclude picking a term with a
                                           * payload in a sub-term */
            must_payload_in_subterm: no_more_new_payloads, /* change to true when there are too
                                                            * many payloads already */
            not_inside_list: true, /* true means we are not picking terms inside list (like
                                    * fn_append in the middle) */
            // we set it to true since it would otherwise be redundant with picking each of the item
            // as mutated term
            weighted_depth: false, /* true means we select a sub-term by giving higher-priority
                                    * to deeper sub-terms */
            // TODO: set two lasts to false now as they allow to find more case. TODO: fix reservori
            // sampling and set this to true (as well as in
            // integration_test/term_zoo.rs)
            ..self.constraints
        };
        if !self.with_dy {
            constraints_make_message.must_be_root = true;
        }
        // choose a random sub term
        if let Some((chosen_term, (step_index, term_path))) =
            choose_filtered(trace, constraints_make_message, |t| !t.is_no_bit(), rand)
        {
            log::debug!("[Mutation-bit] Mutate MakeMessage on term\n{}", chosen_term);
            let spawner = Spawner::new(self.put_registry.clone());
            // log::trace!("Using self.put_registry {:?} to compute ctx",
            // self.put_registry.default().name());
            let mut ctx = TraceContext::new(spawner);
            match make_message_term(trace, &(step_index, term_path), &mut ctx) {
                // TODO: possibly we would need to make sure the mutated trace can be executed (if
                // not directly dropped by the feedback loop once executed).
                // TODO: maybe check we get the same by reading /encoding
                Ok(()) => {
                    log::debug!("mutation::MakeMessage successful!");
                    Ok(MutationResult::Mutated)
                }
                Err(e) => {
                    log::debug!("mutation::MakeMessage failed due to {e}");
                    log::info!("       Skipped {}", self.name());
                    Ok(MutationResult::Skipped)
                }
            }
        } else {
            log::debug!(
                "mutation::MakeMessage failed to choose term in trace:\n {}",
                &trace
            );
            log::info!("       Skipped {}", self.name());
            Ok(MutationResult::Skipped)
        }
    }
}

impl<'a, S, PB> Named for MakeMessage<'a, S, PB>
where
    PB: ProtocolBehavior,
    S: HasRand,
{
    fn name(&self) -> &str {
        remove_prefix_and_type(std::any::type_name::<Self>())
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
    use crate::trace::{Action, Step};

    fn create_state(
    ) -> StdState<TestTrace, InMemoryCorpus<TestTrace>, RomuDuoJrRand, InMemoryCorpus<TestTrace>>
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
            mutator.mutate(&mut state, &mut trace, 0).unwrap();

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
            mutator.mutate(&mut state, &mut trace, 0).unwrap();

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
            let result = mutator.mutate(&mut state, &mut trace, 0).unwrap();

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
        let mut mutator = ReplaceReuseMutator::new(TermConstraints::default(), true);

        fn count_client_hello(trace: &TestTrace) -> usize {
            trace.count_functions_by_name(fn_client_hello.name())
        }

        fn count_finished(trace: &TestTrace) -> usize {
            trace.count_functions_by_name(fn_finished.name())
        }

        loop {
            let mut trace = setup_simple_trace();
            let result = mutator.mutate(&mut state, &mut trace, 0).unwrap();

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
            mutator.mutate(&mut state, &mut trace, 0).unwrap();

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
            mutator.mutate(&mut state, &mut trace, 0).unwrap();

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
            let path = choose_term_path(&trace, TermConstraints::default(), &mut rand).unwrap();
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
            let term = choose(&trace, TermConstraints::default(), &mut rand).unwrap();

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
