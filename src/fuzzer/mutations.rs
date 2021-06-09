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

use crate::trace::{Action, Trace};
use crate::term::Term;

pub fn trace_mutations<R, C, S>() -> tuple_list_type!(
       RepeatMutator<R, S>,
   )
where
    S: HasCorpus<C, Trace> + HasMetadata + HasMaxSize + HasRand<R>,
    C: Corpus<Trace>,
    R: Rand,
{
    tuple_list!(RepeatMutator::new())
}

/// REPEAT: Repeats an input which is already part of the trace
#[derive(Default)]
pub struct RepeatMutator<R, S>
where
    S: HasRand<R>,
    R: Rand,
{
    phantom: PhantomData<(R, S)>,
}

impl<R, S> Mutator<Trace, S> for RepeatMutator<R, S>
where
    S: HasRand<R>,
    R: Rand,
{
    fn mutate(
        &mut self,
        state: &mut S,
        trace: &mut Trace,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        let step = state.rand_mut().choose(&trace.steps);
        trace.steps.push(step.clone()); // todo, only append, or also insert randomly?
        Ok(MutationResult::Mutated)
    }
}

impl<R, S> Named for RepeatMutator<R, S>
where
    S: HasRand<R>,
    R: Rand,
{
    fn name(&self) -> &str {
        "RepeatMutator"
    }
}

impl<R, S> RepeatMutator<R, S>
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

/// REPLACE-REUSE: Replaces a sub-term with a different sub-term which is part of the trace
/// (such that types match). The new sub-term could come from another step which has a different recipe term.
#[derive(Default)]
pub struct ReplaceReuseMutator<R, S>
where
    S: HasRand<R>,
    R: Rand,
{
    phantom: PhantomData<(R, S)>,
}


impl<R, S> ReplaceReuseMutator<R, S>
where
    S: HasRand<R>,
    R: Rand,
{
    fn choose_random_term<'a>(trace: &'a Trace, rand: &mut R) -> Option<&'a Term>{
        let step = rand.choose(&trace.steps);

        match &step.action {
            Action::Input(input) => {
                let mut term = &input.recipe;

                while rand.between(0,1) == 0 {
                    match &term {
                        Term::Variable(_) => {
                            break; // can't go deeper
                        }
                        Term::Application(function, subterms) => {
                            let subterm = rand.choose(subterms);
                            term = subterm;
                        }
                    }
                }

                Some(term)
            },
            Action::Output(_) => None,
        }
    }

}

impl<R, S> Mutator<Trace, S> for ReplaceReuseMutator<R, S>
where
    S: HasRand<R>,
    R: Rand,
{

    fn mutate(
        &mut self,
        state: &mut S,
        trace: &mut Trace,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        let rand = state.rand_mut();
        if let (Some(random_term1), Some(random_term2)) = (
            Self::choose_random_term(trace, rand),
            Self::choose_random_term(trace, rand)
        ) {
            Ok(MutationResult::Mutated)
        } else {
            Ok(MutationResult::Skipped)
        }
    }
}

impl<R, S> Named for ReplaceReuseMutator<R, S>
where
    S: HasRand<R>,
    R: Rand,
{
    fn name(&self) -> &str {
        "ReplaceReuseMutator"
    }
}

impl<R, S> ReplaceReuseMutator<R, S>
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
