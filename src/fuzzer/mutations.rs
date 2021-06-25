

use libafl::{
    bolts::{
        tuples::{tuple_list, tuple_list_type},
    },
    mutators::{MutationResult},
    Error
};

use util::*;

use crate::mutator;
use crate::term::dynamic_function::DynamicFunction;
use crate::term::signature::FunctionDefinition;
use crate::term::{Subterms, Term};
use crate::tls::SIGNATURE;
use crate::trace::Trace;
use libafl::state::{HasCorpus, HasMetadata, HasMaxSize, HasRand};
use libafl::corpus::Corpus;
use libafl::bolts::rands::Rand;

pub fn trace_mutations<R, C, S>() -> tuple_list_type!(
       RepeatMutator<R, S>,
       SkipMutator<R, S>,
       ReplaceReuseMutator<R, S>,
       ReplaceMatchMutator<R, S>,
       RemoveAndLiftMutator<R, S>,
       SwapMutator<R,S>
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
        ReplaceMatchMutator::new(),
        RemoveAndLiftMutator::new(),
        SwapMutator::new()
    )
}

mutator! {
    /// SWAP: Swaps a sub-term with a different sub-term which is part of the trace
    /// (such that types match).
    SwapMutator,
    Trace,
    fn mutate(
        &mut self,
        state: &mut S,
        trace: &mut Trace,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        let rand = state.rand_mut();

        if let Some((term_a, trace_path_a)) = choose(trace, rand) {
            if let Some(trace_path_b) = choose_term_path_filtered(
                trace,
                |term: &Term| term.get_type_shape() == term_a.get_type_shape(),
                rand,
            ) {
                let term_a_cloned = term_a.clone();

                if let Some(term_b) = find_term_mut(trace, &trace_path_b) {
                    let term_b_cloned = term_b.clone();
                    term_b.mutate(term_a_cloned);

                    if let Some(trace_a_mut) = find_term_mut(trace, &trace_path_a) {
                        trace_a_mut.mutate(term_b_cloned);
                    }

                    return Ok(MutationResult::Mutated);
                }
            }
        }

        Ok(MutationResult::Skipped)
    }
}

mutator! {
    /// REMOVE AND LIFT: Removes a sub-term from a term and attaches orphaned children to the parent
    /// (such that types match). This only works if there is only a single child.
    RemoveAndLiftMutator,
    Trace,
     fn mutate(
        &mut self,
        state: &mut S,
        trace: &mut Trace,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        let rand = state.rand_mut();

        // Check whether there are grand_subterms with the same shape as a subterm.
        // If we find such a term, then we can remove the subterm and lift the children to the `term`.
        let filter = |term: &Term| match term {
            Term::Variable(_) => false,
            Term::Application(_, subterms) => subterms
                .find_subterm(|subterm| match subterm {
                    Term::Variable(_) => false,
                    Term::Application(_, grand_subterms) => {
                        grand_subterms.find_subterm_same_shape(subterm).is_some()
                    }
                })
                .is_some(),
        };
        if let Some(mut to_mutate) = choose_term_filtered_mut(trace, rand, filter) {
            match &mut to_mutate {
                Term::Variable(_) => {
                    // never reached as `filter` returns false for variables
                    Ok(MutationResult::Skipped)
                }
                Term::Application(_, ref mut subterms) => {
                    if let Some(((subterm_index, _), grand_subterm)) = choose_iter(
                        subterms.filter_grand_subterms(|subterm, grand_subterm| {
                            subterm.get_type_shape() == grand_subterm.get_type_shape()
                        }),
                        rand,
                    ) {
                        let grand_subterm_cloned = grand_subterm.clone();
                        subterms.push(grand_subterm_cloned);
                        subterms.swap_remove(subterm_index);
                        return Ok(MutationResult::Mutated);
                    }

                    Ok(MutationResult::Skipped)
                }
            }
        } else {
            Ok(MutationResult::Skipped)
        }
    }
}

mutator! {
    /// REPLACE-MATCH: Replaces a function symbol with a different one (such that types match).
    /// An example would be to replace a constant with another constant or the binary function
    /// fn_add with fn_sub.
    ReplaceMatchMutator,
    Trace,
    fn mutate(
        &mut self,
        state: &mut S,
        trace: &mut Trace,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        let rand = state.rand_mut();

        if let Some(mut to_mutate) =
            choose_term_filtered_mut(trace, rand, |term| matches!(term, Term::Application(_, _)))
        {
            match &mut to_mutate {
                Term::Variable(_) => {
                    // never reached as `filter` returns false for variables
                    Ok(MutationResult::Skipped)
                }
                Term::Application(func_mut, _) => {
                    if let Some((shape, dynamic_fn)) = choose_iter_filtered(
                        &SIGNATURE.functions,
                        |(shape, dynamic_fn)| {
                            func_mut.shape() != shape // do not mutate if we change the same funciton
                                && func_mut.shape().return_type == shape.return_type
                                && func_mut.shape().argument_types == shape.argument_types
                        },
                        rand,
                    ) {
                        func_mut.change_function(shape.clone(), dynamic_fn.clone());
                        Ok(MutationResult::Mutated)
                    } else {
                        Ok(MutationResult::Skipped)
                    }
                }
            }
        } else {
            Ok(MutationResult::Skipped)
        }
    }
}

mutator! {
    /// REPLACE-REUSE: Replaces a sub-term with a different sub-term which is part of the trace
    /// (such that types match). The new sub-term could come from another step which has a different recipe term.
    ReplaceReuseMutator,
    Trace,
    // todo make sure that we do not replace a term with itself (performance improvement)
    fn mutate(
        &mut self,
        state: &mut S,
        trace: &mut Trace,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        let rand = state.rand_mut();
        if let Some(replacement) = choose_term(trace, rand).cloned() {
            if let Some(to_replace) = choose_term_filtered_mut(trace, rand, |term: &Term| {
                term.get_type_shape() == replacement.get_type_shape()
            }) {
                to_replace.mutate(replacement);
                return Ok(MutationResult::Mutated);
            }
        }

        Ok(MutationResult::Skipped)
    }
}

mutator! {
    /// SKIP:  Removes an input step
    SkipMutator,
    Trace,
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

mutator! {
    /// REPEAT: Repeats an input which is already part of the trace
    RepeatMutator,
    Trace,
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
        let insert_index = state.rand_mut().between(0, length as u64) as usize;
        let step = state.rand_mut().choose(steps).clone();
        (&mut trace.steps).insert(insert_index, step);
        Ok(MutationResult::Mutated)
    }
}

mod util {
    use libafl::bolts::rands::Rand;

    use crate::term::Term;
    use crate::trace::{Action, InputAction, Step, Trace};

    pub fn choose_iter_filtered<I, E, T, P, R: Rand>(from: I, filter: P, rand: &mut R) -> Option<T>
    where
        I: IntoIterator<Item = T, IntoIter = E>,
        E: ExactSizeIterator + Iterator<Item = T>,
        P: FnMut(&T) -> bool,
    {
        // create iterator
        let iter = from.into_iter().filter(filter).collect::<Vec<T>>();
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

    pub fn choose_iter<I, E, T, R: Rand>(from: I, rand: &mut R) -> Option<T>
    where
        I: IntoIterator<Item = T, IntoIter = E>,
        E: ExactSizeIterator + Iterator<Item = T>,
    {
        // create iterator
        let iter = from.into_iter();
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

    pub fn choose_input_action_mut<'a, R: Rand>(
        trace: &'a mut Trace,
        rand: &mut R,
    ) -> Option<&'a mut InputAction> {
        choose_iter_filtered(
            &mut trace.steps,
            |step| matches!(step.action, Action::Input(_)),
            rand,
        )
        .and_then(|step| match &mut step.action {
            Action::Input(input) => Some(input),
            Action::Output(_) => None,
        })
    }

    pub fn choose_input_action<'a, R: Rand>(
        trace: &'a Trace,
        rand: &mut R,
    ) -> Option<&'a InputAction> {
        choose_iter_filtered(
            &trace.steps,
            |step| matches!(step.action, Action::Input(_)),
            rand,
        )
        .and_then(|step| match &step.action {
            Action::Input(input) => Some(input),
            Action::Output(_) => None,
        })
    }

    type StepIndex = usize;
    type TermPath = Vec<usize>;
    type TracePath = (StepIndex, TermPath);

    /// https://en.wikipedia.org/wiki/Reservoir_sampling#Simple_algorithm
    pub fn reservoir_sample<'a, R: Rand, P: Fn(&Term) -> bool + Copy>(
        trace: &'a Trace,
        rand: &mut R,
        filter: P,
    ) -> Option<(&'a Term, TracePath)> {
        let mut reservoir: Option<(&'a Term, TracePath)> = None;
        let mut visited = 0;

        for (step_index, step) in trace.steps.iter().enumerate() {
            match &step.action {
                Action::Input(input) => {
                    let term = &input.recipe;

                    let mut stack: Vec<(&Term, TracePath)> = vec![(term, (step_index, Vec::new()))];

                    while let Some((term, path)) = stack.pop() {
                        // push next terms onto stack
                        match term {
                            Term::Variable(_) => {
                                // reached leaf
                            }
                            Term::Application(_, subterms) => {
                                // inner node, recursively continue
                                for (path_index, subterm) in subterms.iter().enumerate() {
                                    let mut new_path = path.clone();
                                    new_path.1.push(path_index); // invert because of .iter().rev()
                                    stack.push((subterm, new_path));
                                }
                            }
                        }

                        // sample
                        if filter(term) {
                            // consider in sampling
                            if let None = reservoir {
                                // fill initial reservoir
                                reservoir = Some((term, path)); // todo Rust 1.53 use insert
                            } else {
                                // `1/visited` chance of overwriting
                                // replace elements with gradually decreasing probability
                                if rand.between(1, visited) == 1 {
                                    reservoir = Some((term, path)); // todo Rust 1.53 use insert
                                }
                            }

                            visited += 1;
                        }
                    }
                }
                Action::Output(_) => {
                    // no term -> skip
                }
            }
        }

        reservoir
    }

    fn find_term_by_term_path_mut<'a>(
        term: &'a mut Term,
        term_path: &mut TermPath,
    ) -> Option<&'a mut Term> {
        if term_path.is_empty() {
            return Some(term);
        }

        let subterm_index = term_path.remove(0);

        match term {
            Term::Variable(_) => None,
            Term::Application(_, subterms) => {
                if let Some(subterm) = subterms.get_mut(subterm_index) {
                    find_term_by_term_path_mut(subterm, term_path)
                } else {
                    None
                }
            }
        }
    }

    pub fn find_term_mut<'a>(trace: &'a mut Trace, trace_path: &TracePath) -> Option<&'a mut Term> {
        let (step_index, term_path) = trace_path;

        let step: Option<&mut Step> = trace.steps.get_mut(*step_index);
        if let Some(step) = step {
            match &mut step.action {
                Action::Input(input) => {
                    find_term_by_term_path_mut(&mut input.recipe, &mut term_path.clone())
                }
                Action::Output(_) => None,
            }
        } else {
            None
        }
    }

    pub fn choose_term_filtered_mut<'a, R: Rand, P: Fn(&Term) -> bool + Copy>(
        trace: &'a mut Trace,
        rand: &mut R,
        filter: P,
    ) -> Option<&'a mut Term> {
        if let Some(trace_path) = choose_term_path_filtered(trace, filter, rand) {
            find_term_mut(trace, &trace_path)
        } else {
            None
        }
    }

    pub fn choose_term_mut<'a, R: Rand>(
        trace: &'a mut Trace,
        rand: &mut R,
    ) -> Option<&'a mut Term> {
        if let Some(trace_path) = choose_term_path_filtered(trace, |_| true, rand) {
            find_term_mut(trace, &trace_path)
        } else {
            None
        }
    }

    pub fn choose<'a, R: Rand>(
        trace: &'a Trace,
        rand: &mut R,
    ) -> Option<(&'a Term, (usize, TermPath))> {
        reservoir_sample(trace, rand, |_| true)
    }

    pub fn choose_term<'a, R: Rand>(trace: &'a Trace, rand: &mut R) -> Option<&'a Term> {
        reservoir_sample(trace, rand, |_| true).map(|ret| ret.0)
    }

    pub fn choose_term_path<'a, R: Rand>(trace: &Trace, rand: &mut R) -> Option<TracePath> {
        choose_term_path_filtered(trace, |_| true, rand)
    }

    pub fn choose_term_path_filtered<'a, R: Rand, P: Fn(&Term) -> bool + Copy>(
        trace: &Trace,
        filter: P,
        rand: &mut R,
    ) -> Option<TracePath> {
        reservoir_sample(trace, rand, filter).map(|ret| ret.1)
    }
}
