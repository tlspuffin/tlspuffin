use libafl::stages::{MutationalStage, Stage};
use libafl::corpus::Corpus;
use libafl::mutators::Mutator;
use libafl::{Evaluator, Error};
use libafl::state::{HasRand, HasCorpus, HasClientPerfStats};
use libafl::bolts::rands::Rand;
use libafl::inputs::Input;
use std::marker::PhantomData;

/// Default value, how many iterations each stage gets, as an upper bound
/// It may randomly continue earlier.
pub static MAX_ITERATIONS: u64 = 128;

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
        1 + state.rand_mut().below(MAX_ITERATIONS) as usize
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
    pub fn new(mutator: M) -> Self {
        Self {
            mutator,
            phantom: PhantomData,
        }
    }
}