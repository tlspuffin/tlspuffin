use std::borrow::{Borrow, BorrowMut};
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
       ReplaceReuseMutator<R, S>,
   )
where
    S: HasCorpus<C, Trace> + HasMetadata + HasMaxSize + HasRand<R>,
    C: Corpus<Trace>,
    R: Rand,
{
    tuple_list!(RepeatMutator::new(), ReplaceReuseMutator::new())
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
    fn choose_iter<I, E, T, P>(from: I, filter: P, rand: &mut R) -> T
    where
        I: IntoIterator<Item = T, IntoIter = E>,
        E: ExactSizeIterator + Iterator<Item = T>,
        P: FnMut(&T) -> bool,
    {
        // create iterator
        let mut iter = from.into_iter().filter(filter).collect::<Vec<T>>();
        let length = iter.len();

        // make sure there is something to choose from
        debug_assert!(length > 0, "choosing from an empty iterator");

        // pick a random, valid index
        let index = rand.below(length as u64) as usize;

        // return the item chosen
        iter.into_iter().nth(index).unwrap()
    }

    fn choose_input_action_mut<'a>(
        trace: &'a mut Trace,
        rand: &mut R,
    ) -> Option<&'a mut InputAction> {
        let step: &mut Step = Self::choose_iter(
            &mut trace.steps,
            |step| matches!(step.action, Action::Input(_)),
            rand,
        );

        let action: &mut Action = &mut step.action;
        match action {
            Action::Input(ref mut input) => Some(input),
            Action::Output(_) => None,
        }
    }

    fn choose_input_action<'a>(trace: &'a Trace, rand: &mut R) -> Option<&'a InputAction> {
        let step: &Step = Self::choose_iter(
            &trace.steps,
            |step| matches!(step.action, Action::Input(_)),
            rand,
        );

        let action: &Action = &step.action;
        match action {
            Action::Input(ref input) => Some(input),
            Action::Output(_) => None,
        }
    }

    fn choose_term_mut<'a>(
        trace: &'a mut Trace,
        rand: &mut R,
        type_shape: &TypeShape,
    ) -> Option<&'a mut Term> {
        if let Some(input) = Self::choose_input_action_mut(trace, rand) {
            fn random<'a, R: Rand>(
                term: &'a mut Term,
                rand: &mut R,
                requested_index: usize,
                mut current_index: usize,
                type_shape: &TypeShape,
            ) -> (Option<&'a mut Term>, usize) {
                if requested_index == current_index && term.get_type_shape() == type_shape {
                    (Some(term), current_index)
                } else {
                    let increment = if term.get_type_shape() == type_shape {
                        1
                    } else {
                        0
                    };
                    current_index += increment;

                    match term {
                        Term::Variable(_) => {}
                        Term::Application(_, ref mut subterms) => {
                            for subterm in subterms {
                                let (selected, new_index) = random(
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
                    }

                    (None, current_index)
                }
            }

            let term = &mut input.recipe;
            let length = term.length_of_type(type_shape);

            if length == 0 {
                None
            } else {
                let index = rand.between(0, (length - 1) as u64) as usize;
                random(term, rand, index, 0, type_shape).0
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

            //term.into_iter().filter(|term| term.get_type_shape() == *shape).nth(index)
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

        /*        if let (Some(replacement), Some(to_replace)) = (
                    Self::choose_term(trace, rand, &TypeShape::of::<Term>()).cloned(),
                    Self::choose_term_mut(trace, rand),
                ) {
        */
        if let Some(replacement) = Self::choose_term(trace, rand).cloned() {
            let shape = replacement.get_type_shape();
            if let Some(to_replace) = Self::choose_term_mut(trace, rand, shape) {
                match replacement {
                    Term::Variable(variable) => {
                        to_replace.mutate_to_variable(variable.clone());
                    }
                    Term::Application(func, subterms) => {
                        to_replace.mutate_to_application(func.clone(), subterms.clone());
                    }
                }
                Ok(MutationResult::Mutated)
            } else {
                Ok(MutationResult::Skipped)
            }
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
