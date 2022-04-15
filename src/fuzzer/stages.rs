use std::fmt;
use std::fmt::Debug;
use std::marker::PhantomData;

use libafl::{Error, Evaluator};
use libafl::bolts::rands::Rand;
use libafl::corpus::Corpus;
use libafl::inputs::Input;
use libafl::mutators::{
    ComposedByMutations, MutationResult, Mutator, MutatorsTuple, ScheduledMutator,
};
use libafl::stages::{MutationalStage, Stage};
use libafl::state::{HasClientPerfMonitor, HasCorpus, HasRand};

/// The default mutational stage
#[derive(Clone, Debug)]
pub struct PuffinMutationalStage<E, EM, I, M, S, Z>
    where
        M: Mutator<I, S>,
        I: Input,
        S:  HasClientPerfMonitor + HasCorpus<I> + HasRand,
        Z: Evaluator<E, EM, I, S>,
{
    mutator: M,
    #[allow(clippy::type_complexity)]
    phantom: PhantomData<(E, EM, I, S, Z)>,
    max_iterations_per_stage: u64,
}

impl<E, EM, I, M,  S, Z> MutationalStage<E, EM, I, M, S, Z>
for PuffinMutationalStage<E, EM, I, M, S, Z>
    where
        M: Mutator<I, S>,
        I: Input,
        S: HasClientPerfMonitor +  HasClientPerfMonitor + HasCorpus<I> + HasRand,
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
    fn iterations(&self, state: &mut S, corpus_idx: usize) -> Result<usize, Error> {
        Ok(1 + state.rand_mut().below(self.max_iterations_per_stage) as usize)
    }
}

impl<E, EM, I, M, S, Z> Stage<E, EM, S, Z> for PuffinMutationalStage<E, EM, I, M, S, Z>
    where
        M: Mutator<I, S>,
        I: Input,
        S: HasClientPerfMonitor +  HasClientPerfMonitor + HasCorpus<I> + HasRand,
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
        state.introspection_monitor_mut().finish_stage();

        ret
    }
}

impl<E, EM, I, M, S, Z> PuffinMutationalStage<E, EM, I, M, S, Z>
    where
        M: Mutator<I, S>,
        I: Input,
        S:  HasClientPerfMonitor + HasCorpus<I> + HasRand,
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
    fn schedule(&self, state: &mut S, _: &I) -> usize {
        debug_assert!(!self.mutations().is_empty());
        state.rand_mut().below(self.mutations().len() as u64) as usize
    }
}

impl<I, MT, S> PuffinScheduledMutator<I, MT, S>
    where
        I: Input,
        MT: MutatorsTuple<I, S>,
        S: HasRand,
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
