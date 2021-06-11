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

use crate::term::{Term, TypeShape};
use crate::trace::{Action, InputAction, Step, Trace};
use crate::fuzzer::mutations_util::*;
use crate::tls::SIGNATURE;

pub fn trace_mutations<R, C, S>() -> tuple_list_type!(
       RepeatMutator<R, S>,
       SkipMutator<R, S>,
       ReplaceReuseMutator<R, S>,
       ReplaceMatchMutator<R, S>,
   )
where
    S: HasCorpus<C, Trace> + HasMetadata + HasMaxSize + HasRand<R>,
    C: Corpus<Trace>,
    R: Rand,
{
    tuple_list!(
        RepeatMutator::new(),
        SkipMutator::new(),
        ReplaceReuseMutator::new(),
        ReplaceMatchMutator::new()
    )
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
        let steps = &trace.steps;
        let length = steps.len();
        if length == 0 {
            return Ok(MutationResult::Skipped);
        }
        let step = state.rand_mut().choose(steps);
        let insert_index = state.rand_mut().between(0, (length - 1) as u64) as usize;
        &mut trace.steps.insert(insert_index, step.clone());
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

/// SKIP:  Removes an input step
#[derive(Default)]
pub struct SkipMutator<R, S>
where
    S: HasRand<R>,
    R: Rand,
{
    phantom: PhantomData<(R, S)>,
}

impl<R, S> Mutator<Trace, S> for SkipMutator<R, S>
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
        let steps = &mut trace.steps;
        let length = steps.len();
        if length == 0 {
            return Ok(MutationResult::Skipped);
        }
        let remove_index = state.rand_mut().between(0, (length - 1) as u64) as usize;
        steps.remove(remove_index);
        Ok(MutationResult::Mutated)
    }
}

impl<R, S> Named for SkipMutator<R, S>
where
    S: HasRand<R>,
    R: Rand,
{
    fn name(&self) -> &str {
        "SkipMutator"
    }
}

impl<R, S> SkipMutator<R, S>
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
    #[must_use]
    pub fn new() -> Self {
        Self {
            phantom: PhantomData,
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
        if let Some(replacement) = choose_term(trace, rand).cloned() {
            let requested_type = replacement.get_type_shape();
            if let Some(to_replace) = choose_term_mut(trace, rand, requested_type) {
                to_replace.mutate(&replacement);
                return Ok(MutationResult::Mutated);
            }
        }

        Ok(MutationResult::Skipped)
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

/// REPLACE-MATCH: Replaces a function symbol with a different one (such that types match).
/// An example would be to replace a constant with another constant or the binary function
/// fn_add with fn_sub.
#[derive(Default)]
pub struct ReplaceMatchMutator<R, S>
    where
        S: HasRand<R>,
        R: Rand,
{
    phantom: PhantomData<(R, S)>,
}

impl<R, S> ReplaceMatchMutator<R, S>
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

impl<R, S> Mutator<Trace, S> for ReplaceMatchMutator<R, S>
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
        let (requested_shape, requested_dynamic_fn) = rand.choose(&SIGNATURE.functions);

        // todo improve choosing such that we only find function which have compatible arguments
        if let Some(mut to_mutate) = choose_term_mut(trace, rand, &requested_shape.return_type).cloned() {
                match &mut to_mutate {
                    Term::Variable(_) => {
                        // todo improve choosing such that we only look at functions in the term
                        Ok(MutationResult::Skipped)
                    }
                    Term::Application(func, _) => {
                        func.change_function(requested_shape.clone(), requested_dynamic_fn.clone());
                        Ok(MutationResult::Mutated)
                    }
                }
        } else {
            Ok(MutationResult::Skipped)
        }
    }
}

impl<R, S> Named for ReplaceMatchMutator<R, S>
where
    S: HasRand<R>,
    R: Rand,
{
    fn name(&self) -> &str {
        "ReplaceMatchMutator"
    }
}


#[cfg(test)]
mod tests {
    use libafl::bolts::rands::{RomuTrioRand, StdRand};
    use libafl::corpus::InMemoryCorpus;
    use libafl::state::StdState;

    use crate::agent::AgentName;
    use crate::fuzzer::seeds::*;
    use crate::graphviz::write_graphviz;

    use super::*;

    #[test]
    fn test_replace_reuse() {
        let rand = StdRand::with_seed(1235);
        let mut corpus: InMemoryCorpus<Trace> = InMemoryCorpus::new();

        let mut state = StdState::new(rand, corpus, InMemoryCorpus::new(), ());

        let mut mutator: ReplaceReuseMutator<
            RomuTrioRand,
            StdState<InMemoryCorpus<Trace>, (), _, _, InMemoryCorpus<Trace>>,
        > = ReplaceReuseMutator::new();

        let client = AgentName::first();
        let server = client.next();
        let mut trace = seed_client_attacker12(client, server);

        write_graphviz("test_mutation.svg", "svg", trace.dot_graph(true).as_str());

        for i in 0..10 {
            let mut trace = seed_client_attacker12(client, server);
            println!("{:?}", mutator.mutate(&mut state, &mut trace, 0).unwrap());
            write_graphviz(
                format!("test_mutation_after{}.svg", i).as_str(),
                "svg",
                trace.dot_graph(true).as_str(),
            );
        }
    }

    #[test]
    fn test_rand() {
        let mut rand = StdRand::with_seed(1337);
        println!("{}", rand.between(0, 1));
        println!("{}", rand.between(0, 1));
        println!("{}", rand.between(0, 1));
        println!("{}", rand.between(0, 1));
        println!("{}", rand.between(0, 1));
        println!("{}", rand.between(0, 1));
        println!("{}", rand.between(0, 1));
        println!("{}", rand.between(0, 1));
    }
}
