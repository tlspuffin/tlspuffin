use libafl::bolts::rands::Rand;
use libafl::corpus::Corpus;
use libafl::inputs::Input;
use libafl::mutators::{
    ComposedByMutations, MutationResult, Mutator, MutatorsTuple, ScheduledMutator,
};
use libafl::stages::{MutationalStage, Stage};
use libafl::state::{HasClientPerfStats, HasCorpus, HasRand};
use libafl::{Error, Evaluator};
use std::fmt;
use std::fmt::Debug;
use std::marker::PhantomData;

/// The default mutational stage
#[derive(Clone, Debug)]
pub struct PuffinMutationalStage<C, E, EM, I, M, R, S, Z>
where
    C: Corpus<I>,
    M: Mutator<I, S>,
    I: Input,
    R: Rand,
    S: HasClientPerfStats + HasCorpus<C, I> + HasRand<R>,
    Z: Evaluator<E, EM, I, S>,
{
    mutator: M,
    #[allow(clippy::type_complexity)]
    phantom: PhantomData<(C, E, EM, I, R, S, Z)>,
    max_iterations_per_stage: u64,
}

impl<C, E, EM, I, M, R, S, Z> MutationalStage<C, E, EM, I, M, S, Z>
    for PuffinMutationalStage<C, E, EM, I, M, R, S, Z>
where
    C: Corpus<I>,
    M: Mutator<I, S>,
    I: Input,
    R: Rand,
    S: HasClientPerfStats + HasCorpus<C, I> + HasRand<R>,
    Z: Evaluator<E, EM, I, S>,
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
    fn iterations(&self, state: &mut S) -> usize {
        1 + state.rand_mut().below(self.max_iterations_per_stage) as usize
    }
}

impl<C, E, EM, I, M, R, S, Z> Stage<E, EM, S, Z> for PuffinMutationalStage<C, E, EM, I, M, R, S, Z>
where
    C: Corpus<I>,
    M: Mutator<I, S>,
    I: Input,
    R: Rand,
    S: HasClientPerfStats + HasCorpus<C, I> + HasRand<R>,
    Z: Evaluator<E, EM, I, S>,
{
    #[inline]
    #[allow(clippy::let_and_return)]
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
        corpus_idx: usize,
    ) -> Result<(), Error> {
        let ret = self.perform_mutational(fuzzer, executor, state, manager, corpus_idx);

        #[cfg(feature = "introspection")]
        state.introspection_stats_mut().finish_stage();

        ret
    }
}

impl<C, E, EM, I, M, R, S, Z> PuffinMutationalStage<C, E, EM, I, M, R, S, Z>
where
    C: Corpus<I>,
    M: Mutator<I, S>,
    I: Input,
    R: Rand,
    S: HasClientPerfStats + HasCorpus<C, I> + HasRand<R>,
    Z: Evaluator<E, EM, I, S>,
{
    /// Creates a new default mutational stage
    pub fn new(mutator: M, max_iterations_per_stage: u64) -> Self {
        Self {
            mutator,
            phantom: PhantomData,
            max_iterations_per_stage,
        }
    }
}

//-----------------------------

/// A [`Mutator`] that schedules one of the embedded mutations on each call.
pub struct PuffinScheduledMutator<I, MT, R, S>
where
    I: Input,
    MT: MutatorsTuple<I, S>,
    R: Rand,
    S: HasRand<R>,
{
    mutations: MT,
    phantom: PhantomData<(I, R, S)>,
    max_mutations_per_iteration: u64,
}

impl<I, MT, R, S> Debug for PuffinScheduledMutator<I, MT, R, S>
where
    I: Input,
    MT: MutatorsTuple<I, S>,
    R: Rand,
    S: HasRand<R>,
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

impl<I, MT, R, S> Mutator<I, S> for PuffinScheduledMutator<I, MT, R, S>
where
    I: Input,
    MT: MutatorsTuple<I, S>,
    R: Rand,
    S: HasRand<R>,
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

impl<I, MT, R, S> ComposedByMutations<I, MT, S> for PuffinScheduledMutator<I, MT, R, S>
where
    I: Input,
    MT: MutatorsTuple<I, S>,
    R: Rand,
    S: HasRand<R>,
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

impl<I, MT, R, S> ScheduledMutator<I, MT, S> for PuffinScheduledMutator<I, MT, R, S>
where
    I: Input,
    MT: MutatorsTuple<I, S>,
    R: Rand,
    S: HasRand<R>,
{
    /// Compute the number of iterations used to apply stacked mutations
    fn iterations(&self, state: &mut S, _: &I) -> u64 {
        state.rand_mut().below(self.max_mutations_per_iteration)
    }

    /// Get the next mutation to apply
    fn schedule(&self, state: &mut S, _: &I) -> usize {
        debug_assert!(!self.mutations().is_empty());
        state.rand_mut().below(self.mutations().len() as u64) as usize
    }
}

impl<I, MT, R, S> PuffinScheduledMutator<I, MT, R, S>
where
    I: Input,
    MT: MutatorsTuple<I, S>,
    R: Rand,
    S: HasRand<R>,
{
    /// Create a new [`StdScheduledMutator`] instance specifying mutations
    pub fn new(mutations: MT, max_mutations_per_iteration: u64) -> Self {
        PuffinScheduledMutator {
            mutations,
            phantom: PhantomData,
            max_mutations_per_iteration,
        }
    }
}
