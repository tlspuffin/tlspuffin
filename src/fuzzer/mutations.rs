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

use crate::term::Term;
use crate::trace::{Action, InputAction, Step, Trace};

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
    fn choose_iter<I, E, T, P>(from: I, filter: P, rand: &mut R) -> T
    where
        I: IntoIterator<Item = T, IntoIter = E>,
        E: ExactSizeIterator + Iterator<Item = T>,
        P: FnMut(&T) -> bool,
    {
        // create iterator
        let mut iter = from.into_iter().filter(filter);
        let length = iter.size_hint().1.unwrap();

        // make sure there is something to choose from
        debug_assert!(length > 0, "choosing from an empty iterator");

        // pick a random, valid index
        let index = rand.below(length as u64) as usize;

        // return the item chosen
        iter.nth(index).unwrap()
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

    fn choose_term_mut<'a>(trace: &'a mut Trace, rand: &mut R) -> Option<&'a mut Term> {
        if let Some(input) = Self::choose_input_action_mut(trace, rand) {
            let mut term = &mut input.recipe;
            let size = term.size();

            loop {
                if rand.between(0, (size - 1) as u64) != 0 {
                    return Some(term)
                }

                match term {
                    Term::Variable(_) => {}
                    Term::Application(_, ref mut subterms) => {
                        let subterm = rand.choose(subterms);
                        term = subterm
                    }
                }

                if term.is_leaf() {
                    break
                }
            }

            None
        } else {
            None
        }
    }

    fn choose_term<'a>(trace: &'a Trace, rand: &mut R) -> Option<&'a Term> {
        if let Some(input) = Self::choose_input_action(trace, rand) {
            let mut term = &input.recipe;
            let size = term.size();

            loop {
                if rand.between(0, (size - 1) as u64) != 0 {
                    return Some(term)
                }

                match term {
                    Term::Variable(_) => {}
                    Term::Application(_, ref subterms) => {
                        let subterm = rand.choose(subterms);
                        term = subterm
                    }
                }

                match term {
                    Term::Variable(_) => {
                        break; // variable, can't go deeper
                    }
                    Term::Application(_, ref subterms) => {
                        if subterms.is_empty() {
                            break; // constant, can't go deeper
                        }
                    }
                }
            }

            None
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
        if let (Some(random_term2), Some(random_term1)) = (
            Self::choose_term(trace, rand).cloned(),
            Self::choose_term_mut(trace, rand),
        ) {
            match random_term2 {
                Term::Variable(variable) => {
                    random_term1.mutate_to_variable(variable.clone());
                }
                Term::Application(func, subterms) => {
                    random_term1.mutate_to_application(func.clone(), subterms.clone());
                }
            }
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
        let rand = StdRand::with_seed(88);
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

        mutator.mutate(&mut state, &mut trace, 0).unwrap();

        write_graphviz(
            "test_mutation_after.svg",
            "svg",
            trace.dot_graph(true).as_str(),
        );
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
