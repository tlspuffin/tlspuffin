use std::marker::PhantomData;

use libafl::{
    bolts::{
        rands::Rand,
        tuples::{tuple_list, tuple_list_type, Named},
    },
    corpus::Corpus,
    mutators::{MutationResult, Mutator},
    state::{HasCorpus, HasMaxSize, HasMetadata, HasRand},
    Error,
};

use crate::trace::Trace;

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
        _state: &mut S,
        _input: &mut Trace,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        /* match &mut input.steps[3].action {
            Action::Input(input) => {
                //input.recipe = Term::Variable(sig.new_var_by_type::<SessionID>());
            }
            Action::Output(_) => {}
        }*/
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
