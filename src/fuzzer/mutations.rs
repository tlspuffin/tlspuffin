use libafl::bolts::rands::Rand;
use libafl::corpus::Corpus;
use libafl::state::{HasCorpus, HasMaxSize, HasMetadata, HasRand};
use libafl::{
    bolts::tuples::{tuple_list, tuple_list_type},
    mutators::MutationResult,
    Error,
};

use util::Choosable;
use util::*;

use crate::fuzzer::term_generation::generate_multiple_terms;
use crate::mutator;
use crate::term::atoms::Function;
use crate::term::{Subterms, Term};
use crate::tls::SIGNATURE;
use crate::trace::Trace;

pub fn trace_mutations<R, C, S>(
    min_trace_length: usize,
    max_trace_length: usize,
    constraints: TermConstraints,
) -> tuple_list_type!(
       RepeatMutator<R, S>,
       SkipMutator<R, S>,
       ReplaceReuseMutator<R, S>,
       ReplaceMatchMutator<R, S>,
       RemoveAndLiftMutator<R, S>,
       GenerateMutator<R, S>,
       SwapMutator<R,S>
   )
where
    S: HasCorpus<C, Trace> + HasMetadata + HasMaxSize + HasRand<R>,
    C: Corpus<Trace>,
    R: Rand,
{
    tuple_list!(
        RepeatMutator::new(max_trace_length),
        SkipMutator::new(min_trace_length),
        ReplaceReuseMutator::new(constraints),
        ReplaceMatchMutator::new(constraints),
        RemoveAndLiftMutator::new(constraints),
        GenerateMutator::new(constraints, None),
        SwapMutator::new(constraints)
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

        if let Some((term_a, trace_path_a)) = choose(trace, self.constraints, rand) {
            if let Some(trace_path_b) = choose_term_path_filtered(
                trace,
                |term: &Term| term.get_type_shape() == term_a.get_type_shape(),
                self.constraints,
                rand,
            ) {
                let term_a_cloned = term_a.clone();

                if let Some(term_b_mut) = find_term_mut(trace, &trace_path_b) {
                    let term_b_cloned = term_b_mut.clone();
                    term_b_mut.mutate(term_a_cloned);

                    if let Some(trace_a_mut) = find_term_mut(trace, &trace_path_a) {
                        trace_a_mut.mutate(term_b_cloned);
                    }

                    return Ok(MutationResult::Mutated);
                }
            }
        }

        Ok(MutationResult::Skipped)
    },
    constraints: TermConstraints
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
        if let Some(mut to_mutate) = choose_term_filtered_mut(trace, filter, self.constraints, rand) {
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
                        // move last item to the position of the item we removed
                        subterms.swap_remove(subterm_index);
                        return Ok(MutationResult::Mutated);
                    }

                    Ok(MutationResult::Skipped)
                }
            }
        } else {
            Ok(MutationResult::Skipped)
        }
    },
    constraints: TermConstraints
}

mutator! {
    /// REPLACE-MATCH: Replaces a function symbol with a different one (such that types match).
    /// An example would be to replace a constant with another constant or the binary function
    /// fn_add with fn_sub.
    /// It can also replace any variable with a constant.
    ReplaceMatchMutator,
    Trace,
    fn mutate(
        &mut self,
        state: &mut S,
        trace: &mut Trace,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        let rand = state.rand_mut();

        if let Some(mut to_mutate) = choose_term_mut(trace, self.constraints, rand) {
            match &mut to_mutate {
                Term::Variable(variable) => {
                    // Replace variable with constant
                    if let Some((shape, dynamic_fn)) = SIGNATURE.functions.choose_filtered(
                        |(shape, _)| {
                            variable.typ == shape.return_type && shape.is_constant()
                        },
                        rand,
                    ) {
                        to_mutate.mutate(Term::Application(
                            Function::new(shape.clone(), dynamic_fn.clone()), vec![]));
                        Ok(MutationResult::Mutated)
                    } else {
                        Ok(MutationResult::Skipped)
                    }
                }
                Term::Application(func_mut, _) => {
                    if let Some((shape, dynamic_fn)) = SIGNATURE.functions.choose_filtered(
                        |(shape, _)| {
                            func_mut.shape() != shape // do not mutate if we change the same function
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
    },
    constraints: TermConstraints
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
        if let Some(replacement) = choose_term(trace, self.constraints, rand).cloned() {
            if let Some(to_replace) = choose_term_filtered_mut(trace, |term: &Term| {
                term.get_type_shape() == replacement.get_type_shape()
            }, self.constraints, rand) {
                to_replace.mutate(replacement);
                return Ok(MutationResult::Mutated);
            }
        }

        Ok(MutationResult::Skipped)
    },
    constraints: TermConstraints
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

        if length <= self.min_trace_length {
            // reached min step length
            return Ok(MutationResult::Skipped);
        }

        if length == 0 {
            return Ok(MutationResult::Skipped);
        }
        let remove_index = state.rand_mut().between(0, (length - 1) as u64) as usize;
        steps.remove(remove_index);
        Ok(MutationResult::Mutated)
    },
    min_trace_length: usize
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

        if length >= self.max_trace_length {
            // reached max step length
            return Ok(MutationResult::Skipped);
        }

        if length == 0 {
            return Ok(MutationResult::Skipped);
        }

        let insert_index = state.rand_mut().between(0, length as u64) as usize;
        let step = state.rand_mut().choose(steps).clone();
        (&mut trace.steps).insert(insert_index, step);
        Ok(MutationResult::Mutated)
    },
    max_trace_length: usize
}

mutator! {
    /// GENERATE: TODO
    GenerateMutator,
    Trace,
    fn mutate(
        &mut self,
        state: &mut S,
        trace: &mut Trace,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        let rand = state.rand_mut();

        if let Some(mut to_mutate) = choose_term_mut(trace, self.constraints, rand) {
            let zoo = self.zoo.get_or_insert_with(|| generate_multiple_terms(&SIGNATURE, rand));

            // Replace with generated term
            if let Some(term) = zoo.choose_filtered(
                |term| {
                    to_mutate.get_type_shape() == term.get_type_shape()
                },
                rand,
            ) {
                to_mutate.mutate(term.clone());
                Ok(MutationResult::Mutated)
            } else {
                Ok(MutationResult::Skipped)
            }
        } else {
            Ok(MutationResult::Skipped)
        }
    },
    constraints: TermConstraints,
    zoo: Option<Vec<Term>>
}

pub mod util {
    use libafl::bolts::rands::Rand;

    use crate::term::Term;
    use crate::trace::{Action, Step, Trace};

    #[derive(Copy, Clone)]
    pub struct TermConstraints {
        pub min_term_size: usize,
        pub max_term_size: usize,
    }

    /// Default values which represent no constraint
    impl Default for TermConstraints {
        fn default() -> Self {
            Self {
                min_term_size: 0,
                max_term_size: 9000,
            }
        }
    }

    pub trait Choosable<T, P, R: Rand>
    where
        P: FnMut(&&T) -> bool,
    {
        fn choose_filtered(&self, filter: P, rand: &mut R) -> Option<&T>;
        fn choose(&self, rand: &mut R) -> Option<&T>;
    }

    impl<T, P, R: Rand> Choosable<T, P, R> for Vec<T>
        where
            P: FnMut(&&T) -> bool,
    {
        fn choose_filtered(&self, filter: P, rand: &mut R) -> Option<&T> {
            let filtered = self
                .iter()
                .filter(filter)
                .collect::<Vec<&T>>();
            let length = filtered.len();

            if length == 0 {
                None
            } else {
                let index = rand.below(length as u64) as usize;
                filtered.into_iter().nth(index)
            }
        }

        fn choose(&self, rand: &mut R) -> Option<&T> {
            let length = self.len();

            if length == 0 {
                None
            } else {
                let index = rand.below(length as u64) as usize;
                self.get(index)
            }
        }
    }

    pub fn choose_iter<I, E, T, R: Rand>(from: I, rand: &mut R) -> Option<T>
    where
        I: IntoIterator<Item = T, IntoIter = E>,
        E: ExactSizeIterator + Iterator<Item = T>,
    {
        // create iterator
        let mut iter = from.into_iter();
        let length = iter.len();

        if length == 0 {
            None
        } else {
            // pick a random, valid index
            let index = rand.below(length as u64) as usize;

            // return the item chosen
            iter.nth(index)
        }
    }

    pub type StepIndex = usize;
    pub type TermPath = Vec<usize>;
    pub type TracePath = (StepIndex, TermPath);

    /// https://en.wikipedia.org/wiki/Reservoir_sampling#Simple_algorithm
    fn reservoir_sample<'a, R: Rand, P: Fn(&Term) -> bool + Copy>(
        trace: &'a Trace,
        filter: P,
        constraints: TermConstraints,
        rand: &mut R,
    ) -> Option<(&'a Term, TracePath)> {
        let mut reservoir: Option<(&'a Term, TracePath)> = None;
        let mut visited = 0;

        for (step_index, step) in trace.steps.iter().enumerate() {
            match &step.action {
                Action::Input(input) => {
                    let term = &input.recipe;

                    let size = term.size();
                    if size <= constraints.min_term_size || size >= constraints.max_term_size {
                        continue;
                    }

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
                            visited += 1;

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

    pub fn find_term_mut<'a>(trace: &'a mut Trace, trace_path: &TracePath) -> Option<&'a mut Term> {
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

    pub fn choose<'a, R: Rand>(
        trace: &'a Trace,
        constraints: TermConstraints,
        rand: &mut R,
    ) -> Option<(&'a Term, (usize, TermPath))> {
        reservoir_sample(trace, |_| true, constraints, rand)
    }

    pub fn choose_term<'a, R: Rand>(
        trace: &'a Trace,
        constraints: TermConstraints,
        rand: &mut R,
    ) -> Option<&'a Term> {
        reservoir_sample(trace, |_| true, constraints, rand).map(|ret| ret.0)
    }

    pub fn choose_term_mut<'a, R: Rand>(
        trace: &'a mut Trace,
        constraints: TermConstraints,
        rand: &mut R,
    ) -> Option<&'a mut Term> {
        if let Some(trace_path) = choose_term_path_filtered(trace, |_| true, constraints, rand) {
            find_term_mut(trace, &trace_path)
        } else {
            None
        }
    }

    pub fn choose_term_filtered_mut<'a, R: Rand, P: Fn(&Term) -> bool + Copy>(
        trace: &'a mut Trace,
        filter: P,
        constraints: TermConstraints,
        rand: &mut R,
    ) -> Option<&'a mut Term> {
        if let Some(trace_path) = choose_term_path_filtered(trace, filter, constraints, rand) {
            find_term_mut(trace, &trace_path)
        } else {
            None
        }
    }

    pub fn choose_term_path<'a, R: Rand>(
        trace: &Trace,
        constraints: TermConstraints,
        rand: &mut R,
    ) -> Option<TracePath> {
        choose_term_path_filtered(trace, |_| true, constraints, rand)
    }

    pub fn choose_term_path_filtered<'a, R: Rand, P: Fn(&Term) -> bool + Copy>(
        trace: &Trace,
        filter: P,
        constraints: TermConstraints,
        rand: &mut R,
    ) -> Option<TracePath> {
        reservoir_sample(trace, filter, constraints, rand).map(|ret| ret.1)
    }
}
