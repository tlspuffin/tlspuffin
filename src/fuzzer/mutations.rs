use std::marker::PhantomData;

use libafl::bolts::rands::Rand;
use libafl::bolts::tuples::Named;
use libafl::mutators::{MutationResult, Mutator};
use libafl::state::{HasMaxSize, HasRand};
use libafl::{
    bolts::tuples::{tuple_list, tuple_list_type},
    corpus::Corpus,
    state::{HasCorpus, HasMetadata},
    Error,
};

use super::Trace;

pub fn trace_mutations<R, C, S>() -> tuple_list_type!(
       DummyMutator<R, S>,
   )
where
    S: HasCorpus<C, Trace> + HasMetadata + HasMaxSize + HasRand<R>,
    C: Corpus<Trace>,
    R: Rand,
{
    tuple_list!(DummyMutator::new())
}

#[derive(Default)]
pub struct DummyMutator<R, S>
where
    S: HasRand<R>,
    R: Rand,
{
    phantom: PhantomData<(R, S)>,
}

impl<R, S> Mutator<Trace, S> for DummyMutator<R, S>
where
    S: HasRand<R>,
    R: Rand,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut Trace,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        Ok(MutationResult::Skipped)
    }
}

impl<R, S> Named for DummyMutator<R, S>
where
    S: HasRand<R>,
    R: Rand,
{
    fn name(&self) -> &str {
        "DummyMutator"
    }
}

impl<R, S> DummyMutator<R, S>
where
    S: HasRand<R>,
    R: Rand,
{
    #[must_use]
    pub fn new() -> Self {
        Self {
            phantom: PhantomData,
        }
    }
}
