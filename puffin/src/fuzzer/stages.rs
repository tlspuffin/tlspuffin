use std::fmt;
use std::fmt::Debug;
use std::marker::PhantomData;

use libafl::prelude::mutational::MutatedTransform;
use libafl::prelude::*;
use libafl_bolts::prelude::*;

/// A [`Mutator`] that schedules one of the embedded mutations on each call.
pub struct FocusScheduledMutator<I, MT, MtPre, MtPost, S>
where
    MT: MutatorsTuple<I, S>,
    MtPre: MutatorsTuple<I, S>,
    MtPost: MutatorsTuple<I, S>,
    S: HasRand,
{
    name: String,
    mutations_core: MT,
    mutations_pre: MtPre,
    mutations_post: MtPost,
    max_stack_pow: u64,
    phantom: PhantomData<(I, S)>,
}

impl<I, MT, MtPre, MtPost, S> Debug for FocusScheduledMutator<I, MT, MtPre, MtPost, S>
where
    MT: MutatorsTuple<I, S>,
    MtPre: MutatorsTuple<I, S>,
    MtPost: MutatorsTuple<I, S>,
    S: HasRand,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "FocusScheduledMutator with {} core mutations, {} pre-mutations, {} post-mutations, for Input type {}",
            self.mutations_core.len(),
            self.mutations_pre.len(),
            self.mutations_post.len(),
            core::any::type_name::<I>()
        )
    }
}

impl<I, MT, MtPre, MtPost, S> Named for FocusScheduledMutator<I, MT, MtPre, MtPost, S>
where
    MT: MutatorsTuple<I, S>,
    MtPre: MutatorsTuple<I, S>,
    MtPost: MutatorsTuple<I, S>,
    S: HasRand,
{
    fn name(&self) -> &str {
        &self.name
    }
}

impl<I, MT, MtPre, MtPost, S> Mutator<I, S> for FocusScheduledMutator<I, MT, MtPre, MtPost, S>
where
    MT: MutatorsTuple<I, S>,
    MtPre: MutatorsTuple<I, S>,
    MtPost: MutatorsTuple<I, S>,
    S: HasRand,
{
    #[inline]
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut I,
        stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        self.scheduled_mutate(state, input, stage_idx)
    }
}

impl<I, MT, MtPre, MtPost, S> ComposedByMutations<I, MT, S>
    for FocusScheduledMutator<I, MT, MtPre, MtPost, S>
where
    MT: MutatorsTuple<I, S>,
    MtPre: MutatorsTuple<I, S>,
    MtPost: MutatorsTuple<I, S>,
    S: HasRand,
{
    /// Get the mutations: we use a custom selection instead of the default
    fn mutations(&self) -> &MT {
        panic!("[FocusScheduledMutator] mutations - mutations - should never be used");
    }

    /// Get the mutations (mutable): we use a custom selection instead of the default
    fn mutations_mut(&mut self) -> &mut MT {
        panic!("[FocusScheduledMutator] mutations - mutations_mut - should never be used");
    }
}

impl<I, MT, MtPre, MtPost, S> ScheduledMutator<I, MT, S>
    for FocusScheduledMutator<I, MT, MtPre, MtPost, S>
where
    MT: MutatorsTuple<I, S>,
    MtPre: MutatorsTuple<I, S>,
    MtPost: MutatorsTuple<I, S>,
    S: HasRand,
{
    /// Compute the number of iterations used to apply stacked mutations
    fn iterations(&self, state: &mut S, _: &I) -> u64 {
        1 << (1 + state.rand_mut().below(self.max_stack_pow))
    }

    /// Get the next mutation to apply (base implementation)
    fn schedule(&self, _: &mut S, _: &I) -> MutationId {
        panic!("[FocusScheduledMutator] mutations - schedule - should never be used");
    }

    /// New default implementation for mutate.
    /// Implementations must forward `mutate()` to this method
    fn scheduled_mutate(
        &mut self,
        state: &mut S,
        input: &mut I,
        stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        let mut r = MutationResult::Skipped;
        let num = self.iterations(state, input);
        log::debug!(
            "FocusScheduledMutator:num: {},  stage_idx: {}, max_stack_pow: {}",
            num,
            stage_idx,
            self.max_stack_pow
        );
        // Pre-mutation: schedule exactly once
        // Note: the pre mutations will recognize this stage_idx and there is a certain probability
        // that the mutation won't be applied. However, a payload path will always be chosen and
        // stored in the input metadata for the later, HAVOC, and ReadMessage mutations.
        let idx = self.schedule_pre(state, input);
        log::debug!("FocusScheduledMutator: PRE idx: {}", idx);
        let outcome = self
            .mutations_pre_mut()
            .get_and_mutate(idx, state, input, stage_idx)?;
        if outcome == MutationResult::Mutated {
            r = MutationResult::Mutated;
        }

        // Core mutations
        for _ in 0..num {
            let idx = self.schedule_core(state, input);
            log::debug!(
                "FocusScheduledMutator: CORE idx: {}, stage_idx: {stage_idx}",
                idx
            );
            let outcome = self
                .mutations_core_mut()
                .get_and_mutate(idx, state, input, stage_idx)?;
            if outcome == MutationResult::Mutated {
                r = MutationResult::Mutated;
            }
        }

        // Post-mutation: schedule exactly once
        // Note: the post mutations will recognize this stage_idx and there is a certain probability
        // that the mutation won't be applied, so we can skip it
        let idx = self.schedule_post(state, input);
        log::debug!("FocusScheduledMutator: POST idx: {}", idx);
        let outcome = self
            .mutations_post_mut()
            .get_and_mutate(idx, state, input, stage_idx)?;
        if outcome == MutationResult::Mutated {
            r = MutationResult::Mutated;
        }

        Ok(r)
    }
}

impl<I, MT, MtPre, MtPost, S> FocusScheduledMutator<I, MT, MtPre, MtPost, S>
where
    MT: MutatorsTuple<I, S>,
    MtPre: MutatorsTuple<I, S>,
    MtPost: MutatorsTuple<I, S>,
    S: HasRand,
{
    /// Create a new [`libafl::mutators::StdScheduledMutator`] instance specifying mutations
    pub fn new(mutations_pre: MtPre, mutations_core: MT, mutations_post: MtPost) -> Self {
        FocusScheduledMutator {
            name: format!(
                "FocusScheduledMutator[{};{};{}]",
                mutations_pre.names().join(", "),
                mutations_core.names().join(", "),
                mutations_post.names().join(", ")
            ),
            mutations_core,
            mutations_pre,
            mutations_post,
            max_stack_pow: 7,
            phantom: PhantomData,
        }
    }

    /// Create a new [`libafl::mutators::StdScheduledMutator`] instance specifying mutations and the
    /// maximun number of iterations
    // pub fn with_max_stack_pow(mutations_pre:  MtPre, mutations: MT, mutations_post: MtPost,
    // max_stack_pow: u64) -> Self {     FocusScheduledMutator {
    //         name: format!("FocusScheduledMutator[{};{};{}]", mutations_pre.names().join(", "),
    // mutations.names().join(", "), mutations_post.names().join(", ")),         mutations,
    //         mutations_pre,
    //         mutations_post,
    //         max_stack_pow,
    //         phantom: PhantomData,
    //     }
    // }

    /// Get the next core-mutation to apply
    fn schedule_core(&self, state: &mut S, _: &I) -> MutationId {
        debug_assert!(!self.mutations_core.is_empty());
        state
            .rand_mut()
            .below(self.mutations_core.len() as u64)
            .into()
    }

    /// Get the next pre-mutation to apply
    fn schedule_pre(&self, state: &mut S, _: &I) -> MutationId {
        debug_assert!(!self.mutations_pre.is_empty());
        state
            .rand_mut()
            .below(self.mutations_pre.len() as u64)
            .into()
    }

    /// Get the next post-mutation to apply
    fn schedule_post(&self, state: &mut S, _: &I) -> MutationId {
        debug_assert!(!self.mutations_post.is_empty());
        state
            .rand_mut()
            .below(self.mutations_post.len() as u64)
            .into()
    }

    /// Get the pre-mutations (mutable): we use a custom selection instead of the default
    fn mutations_pre_mut(&mut self) -> &mut MtPre {
        &mut self.mutations_pre
    }

    /// Get the core-mutations (mutable): we use a custom selection instead of the default
    fn mutations_core_mut(&mut self) -> &mut MT {
        &mut self.mutations_core
    }

    /// Get the post-mutations (mutable): we use a custom selection instead of the default
    fn mutations_post_mut(&mut self) -> &mut MtPost {
        &mut self.mutations_post
    }

    pub fn mutate(
        &mut self,
        state: &mut S,
        input: &mut I,
        stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        self.scheduled_mutate(state, input, stage_idx)
    }
}

/* --------------------- OLD STUFF ------------------------------- */
/// The default mutational stage
#[derive(Clone, Debug)]
pub struct PuffinMutationalStage<E, EM, I, M, Z> {
    mutator: M,
    #[allow(clippy::type_complexity)]
    phantom: PhantomData<(E, EM, I, Z)>,
    max_iterations_per_stage: u64,
}

impl<E, EM, I, M, Z> UsesState for PuffinMutationalStage<E, EM, I, M, Z>
where
    E: UsesState<State = Z::State>,
    EM: UsesState<State = Z::State>,
    M: Mutator<I, Z::State>,
    Z: Evaluator<E, EM>,
    Z::State: HasClientPerfMonitor + HasCorpus + HasRand,
{
    type State = Z::State;
}

impl<E, EM, I, M, Z> MutationalStage<E, EM, I, M, Z> for PuffinMutationalStage<E, EM, I, M, Z>
where
    E: UsesState<State = Z::State>,
    EM: UsesState<State = Z::State>,
    M: Mutator<I, Z::State>,
    Z: Evaluator<E, EM>,
    Z::State: HasClientPerfMonitor + HasCorpus + HasRand,
    I: MutatedTransform<Self::Input, Self::State> + Clone,
{
    /// The mutator, added to this stage
    #[inline]
    fn mutator(&self) -> &M {
        &self.mutator
    }

    /// The list of mutators, added to this stage (as mutable ref)
    #[inline]
    fn mutator_mut(&mut self) -> &mut M {
        &mut self.mutator
    }

    /// Gets the number of iterations as a random number
    fn iterations(&self, state: &mut Z::State, _corpus_idx: CorpusId) -> Result<u64, Error> {
        Ok(1 + state.rand_mut().below(self.max_iterations_per_stage))
    }
}

impl<E, EM, I, M, Z> Stage<E, EM, Z> for PuffinMutationalStage<E, EM, I, M, Z>
where
    E: UsesState<State = Z::State>,
    EM: UsesState<State = Z::State>,
    M: Mutator<I, Z::State>,
    Z: Evaluator<E, EM>,
    Z::State: HasClientPerfMonitor + HasCorpus + HasRand,
    I: MutatedTransform<Self::Input, Self::State> + Clone,
{
    #[inline]
    #[allow(clippy::let_and_return)]
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut Z::State,
        manager: &mut EM,
        corpus_idx: CorpusId,
    ) -> Result<(), Error> {
        let ret = self.perform_mutational(fuzzer, executor, state, manager, corpus_idx);

        #[cfg(feature = "introspection")]
        state.introspection_monitor_mut().finish_stage();

        ret
    }
}

impl<E, EM, I, M, Z> PuffinMutationalStage<E, EM, I, M, Z>
where
    I: Input,
    E: UsesState<State = Z::State>,
    EM: UsesState<State = Z::State>,
    M: Mutator<I, Z::State>,
    Z: Evaluator<E, EM>,
{
    #[allow(dead_code)]
    /// Creates a new default mutational stage
    pub const fn new(mutator: M, max_iterations_per_stage: u64) -> Self {
        Self {
            mutator,
            phantom: PhantomData,
            max_iterations_per_stage,
        }
    }
}

//-----------------------------

/// A [`Mutator`] that schedules one of the embedded mutations on each call.
pub struct PuffinScheduledMutator<I, MT, S>
where
    I: Input,
    MT: MutatorsTuple<I, S>,
    S: HasRand,
{
    mutations: MT,
    phantom: PhantomData<(I, S)>,
    max_mutations_per_iteration: u64,
}

impl<I, MT, S> Debug for PuffinScheduledMutator<I, MT, S>
where
    I: Input,
    MT: MutatorsTuple<I, S>,
    S: HasRand,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "StdScheduledMutator with {} mutations for Input type {}",
            self.mutations.len(),
            core::any::type_name::<I>()
        )
    }
}

impl<I, MT, S> Named for PuffinScheduledMutator<I, MT, S>
where
    I: Input,
    MT: MutatorsTuple<I, S>,
    S: HasRand,
{
    fn name(&self) -> &str {
        "PuffinScheduledMutator"
    }
}

impl<I, MT, S> Mutator<I, S> for PuffinScheduledMutator<I, MT, S>
where
    I: Input,
    MT: MutatorsTuple<I, S>,
    S: HasRand,
{
    #[inline]
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut I,
        stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        self.scheduled_mutate(state, input, stage_idx)
    }
}

impl<I, MT, S> ComposedByMutations<I, MT, S> for PuffinScheduledMutator<I, MT, S>
where
    I: Input,
    MT: MutatorsTuple<I, S>,
    S: HasRand,
{
    /// Get the mutations
    #[inline]
    fn mutations(&self) -> &MT {
        &self.mutations
    }

    // Get the mutations (mut)
    #[inline]
    fn mutations_mut(&mut self) -> &mut MT {
        &mut self.mutations
    }
}

impl<I, MT, S> ScheduledMutator<I, MT, S> for PuffinScheduledMutator<I, MT, S>
where
    I: Input,
    MT: MutatorsTuple<I, S>,
    S: HasRand,
{
    /// Compute the number of iterations used to apply stacked mutations
    fn iterations(&self, state: &mut S, _: &I) -> u64 {
        state.rand_mut().below(self.max_mutations_per_iteration)
    }

    /// Get the next mutation to apply
    fn schedule(&self, state: &mut S, _: &I) -> MutationId {
        debug_assert!(!self.mutations().is_empty());
        (state.rand_mut().below(self.mutations().len() as u64) as usize).into()
    }
}

impl<I, MT, S> PuffinScheduledMutator<I, MT, S>
where
    I: Input,
    MT: MutatorsTuple<I, S>,
    S: HasRand,
{
    #[allow(dead_code)]
    /// Create a new [`PuffinScheduledMutator`] instance specifying mutations
    pub const fn new(mutations: MT, max_mutations_per_iteration: u64) -> Self {
        Self {
            mutations,
            phantom: PhantomData,
            max_mutations_per_iteration,
        }
    }
}
