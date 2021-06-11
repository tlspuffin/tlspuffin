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

pub fn trace_mutations<R, C, S>() -> tuple_list_type!(
       RepeatMutator<R, S>,
       SkipMutator<R, S>,
       ReplaceReuseMutator<R, S>,
   )
where
    S: HasCorpus<C, Trace> + HasMetadata + HasMaxSize + HasRand<R>,
    C: Corpus<Trace>,
    R: Rand,
{
    tuple_list!(
        RepeatMutator::new(),
        SkipMutator::new(),
        ReplaceReuseMutator::new()
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
    fn choose_iter<I, E, T, P>(from: I, filter: P, rand: &mut R) -> Option<T>
    where
        I: IntoIterator<Item = T, IntoIter = E>,
        E: ExactSizeIterator + Iterator<Item = T>,
        P: FnMut(&T) -> bool,
    {
        // create iterator
        let mut iter = from.into_iter().filter(filter).collect::<Vec<T>>();
        let length = iter.len();

        if length == 0 {
            None
        } else {
            // pick a random, valid index
            let index = rand.below(length as u64) as usize;

            // return the item chosen
            iter.into_iter().nth(index)
        }
    }

    fn choose_input_action_mut<'a>(
        trace: &'a mut Trace,
        rand: &mut R,
    ) -> Option<&'a mut InputAction> {
        Self::choose_iter(
            &mut trace.steps,
            |step| matches!(step.action, Action::Input(_)),
            rand,
        )
        .and_then(|step| match &mut step.action {
            Action::Input(input) => Some(input),
            Action::Output(_) => None,
        })
    }

    fn choose_input_action<'a>(trace: &'a Trace, rand: &mut R) -> Option<&'a InputAction> {
        Self::choose_iter(
            &trace.steps,
            |step| matches!(step.action, Action::Input(_)),
            rand,
        )
        .and_then(|step| match &step.action {
            Action::Input(input) => Some(input),
            Action::Output(_) => None,
        })
    }

    /// Finds a term by a `type_shape` and `requested_index`.
    /// `requested_index` and `current_index` must be smaller than the amount of terms which have
    /// the type shape `type_shape`.
    fn find_term_mut<'a>(
        term: &'a mut Term,
        rand: &mut R,
        requested_index: usize,
        mut current_index: usize,
        type_shape: &TypeShape,
    ) -> (Option<&'a mut Term>, usize) {
        let is_compatible = term.get_type_shape() == type_shape;
        if is_compatible && requested_index == current_index {
            (Some(term), current_index)
        } else {
            if is_compatible {
                // increment only if the term is relevant
                current_index += 1;
            };

            match term {
                Term::Application(_, ref mut subterms) => {
                    for subterm in subterms {
                        let (selected, new_index) = Self::find_term_mut(
                            subterm,
                            rand,
                            requested_index,
                            current_index,
                            type_shape,
                        );

                        current_index = new_index;

                        if let Some(selected) = selected {
                            return (Some(selected), new_index);
                        }
                    }
                }
                Term::Variable(_) => {}
            }

            (None, current_index)
        }
    }

    fn choose_term_mut<'a>(
        trace: &'a mut Trace,
        rand: &mut R,
        requested_type: &TypeShape,
    ) -> Option<&'a mut Term> {
        if let Some(input) = Self::choose_input_action_mut(trace, rand) {
            let term = &mut input.recipe;
            let length = term.length_of_type(requested_type);

            if length == 0 {
                None
            } else {
                let requested_index = rand.between(0, (length - 1) as u64) as usize;
                Self::find_term_mut(term, rand, requested_index, 0, requested_type).0
            }
        } else {
            None
        }
    }

    fn choose_term<'a>(trace: &'a Trace, rand: &mut R) -> Option<&'a Term> {
        if let Some(input) = Self::choose_input_action(trace, rand) {
            let term = &input.recipe;
            let size = term.length();

            let index = rand.between(0, (size - 1) as u64) as usize;

            term.into_iter().nth(index)
        } else {
            None
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
        if let Some(replacement) = Self::choose_term(trace, rand).cloned() {
            let requested_type = replacement.get_type_shape();
            if let Some(to_replace) = Self::choose_term_mut(trace, rand, requested_type) {
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
