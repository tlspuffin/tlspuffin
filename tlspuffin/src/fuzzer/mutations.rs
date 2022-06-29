use libafl::{
    bolts::{
        rands::Rand,
        tuples::{tuple_list, tuple_list_type},
    },
    mutators::MutationResult,
    state::{HasCorpus, HasMaxSize, HasMetadata, HasRand},
    Error,
};
use util::{Choosable, *};

use crate::{
    algebra::{atoms::Function, Subterms, Term},
    fuzzer::term_zoo::TermZoo,
    mutator,
    tls::SIGNATURE,
    trace::Trace,
};

pub fn trace_mutations<S>(
    min_trace_length: usize,
    max_trace_length: usize,
    constraints: TermConstraints,
    fresh_zoo_after: u64,
) -> tuple_list_type!(
    RepeatMutator<S>,
    SkipMutator<S>,
    ReplaceReuseMutator<S>,
    ReplaceMatchMutator<S>,
    RemoveAndLiftMutator<S>,
    GenerateMutator<S>,
    SwapMutator<S>
)
where
    S: HasCorpus<Trace> + HasMetadata + HasMaxSize + HasRand,
{
    tuple_list!(
        RepeatMutator::new(max_trace_length),
        SkipMutator::new(min_trace_length),
        ReplaceReuseMutator::new(constraints),
        ReplaceMatchMutator::new(constraints),
        RemoveAndLiftMutator::new(constraints),
        GenerateMutator::new(0, fresh_zoo_after, constraints, None), // Refresh zoo after 100000M mutations
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
    // TODO make sure that we do not replace a term with itself (performance improvement)
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
    /// GENERATE: Generates a previously-unseen term using a
    GenerateMutator,
    Trace,
    fn mutate(
        &mut self,
        state: &mut S,
        trace: &mut Trace,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        let rand = state.rand_mut();

        if let Some(to_mutate) = choose_term_mut(trace, self.constraints, rand) {

            self.mutation_counter += 1;

            let zoo = if self.mutation_counter % self.refresh_zoo_after == 0 {
                self.zoo.insert(TermZoo::generate(&SIGNATURE, rand))
            } else {
                self.zoo.get_or_insert_with(|| TermZoo::generate(&SIGNATURE, rand))
            };

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
    mutation_counter: u64,
    refresh_zoo_after: u64,
    constraints: TermConstraints,
    zoo: Option<TermZoo>
}

pub mod util {
    use libafl::bolts::rands::Rand;

    use crate::{
        algebra::Term,
        trace::{Action, Step, Trace},
    };

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

    pub trait Choosable<T, R: Rand> {
        fn choose_filtered<P>(&self, filter: P, rand: &mut R) -> Option<&T>
        where
            P: FnMut(&&T) -> bool;
        fn choose(&self, rand: &mut R) -> Option<&T>;
    }

    impl<T, R: Rand> Choosable<T, R> for Vec<T> {
        fn choose_filtered<P>(&self, filter: P, rand: &mut R) -> Option<&T>
        where
            P: FnMut(&&T) -> bool,
        {
            let filtered = self.iter().filter(filter).collect::<Vec<&T>>();
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
                            if reservoir.is_none() {
                                // fill initial reservoir
                                reservoir = Some((term, path));
                            } else {
                                // `1/visited` chance of overwriting
                                // replace elements with gradually decreasing probability
                                if rand.between(1, visited) == 1 {
                                    reservoir = Some((term, path));
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

    pub fn choose_term_path<R: Rand>(
        trace: &Trace,
        constraints: TermConstraints,
        rand: &mut R,
    ) -> Option<TracePath> {
        choose_term_path_filtered(trace, |_| true, constraints, rand)
    }

    pub fn choose_term_path_filtered<R: Rand, P: Fn(&Term) -> bool + Copy>(
        trace: &Trace,
        filter: P,
        constraints: TermConstraints,
        rand: &mut R,
    ) -> Option<TracePath> {
        reservoir_sample(trace, filter, constraints, rand).map(|ret| ret.1)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};

    use libafl::{
        bolts::rands::{RomuDuoJrRand, StdRand},
        corpus::InMemoryCorpus,
        mutators::{MutationResult, Mutator},
        state::StdState,
    };

    use super::*;
    use crate::{
        agent::AgentName,
        algebra::{dynamic_function::DescribableFunction, Term},
        put_registry::current_put,
        tls::{fn_impl::*, seeds::*},
        trace::{Action, Step, Trace},
    };

    fn create_state() -> StdState<InMemoryCorpus<Trace>, Trace, RomuDuoJrRand, InMemoryCorpus<Trace>>
    {
        let rand = StdRand::with_seed(1235);
        let corpus: InMemoryCorpus<Trace> = InMemoryCorpus::new();
        StdState::new(rand, corpus, InMemoryCorpus::new(), &mut (), &mut ()).unwrap()
    }

    /// Checks whether repeat can repeat the last step
    #[test]
    fn test_repeat_mutator() {
        let _rand = StdRand::with_seed(1235);
        let _corpus: InMemoryCorpus<Trace> = InMemoryCorpus::new();
        let mut state = create_state();
        let _server = AgentName::first();
        let _trace = seed_client_attacker12.build_trace();

        let mut mutator = RepeatMutator::new(15);

        fn check_is_encrypt12(step: &Step) -> bool {
            if let Action::Input(input) = &step.action {
                if input.recipe.name() == fn_encrypt12.name() {
                    return true;
                }
            }
            false
        }

        loop {
            let mut trace = seed_client_attacker12.build_trace();
            mutator.mutate(&mut state, &mut trace, 0).unwrap();

            let length = trace.steps.len();
            if let Some(last) = trace.steps.get(length - 1) {
                if check_is_encrypt12(last) {
                    if let Some(step) = trace.steps.get(length - 2) {
                        if check_is_encrypt12(step) {
                            break;
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn test_replace_match_mutator() {
        let _server = AgentName::first();
        let mut state = create_state();
        let mut mutator = ReplaceMatchMutator::new(TermConstraints::default());

        loop {
            let mut trace = seed_client_attacker12.build_trace();
            mutator.mutate(&mut state, &mut trace, 0).unwrap();

            if let Some(last) = trace.steps.iter().last() {
                match &last.action {
                    Action::Input(input) => match &input.recipe {
                        Term::Variable(_) => {}
                        Term::Application(_, subterms) => {
                            if let Some(last_subterm) = subterms.iter().last() {
                                if last_subterm.name() == fn_seq_1.name() {
                                    break;
                                }
                            }
                        }
                    },
                    Action::Output(_) => {}
                }
            }
        }
    }

    #[test]
    fn test_remove_lift_mutator() {
        // Should remove an extension
        let mut state = create_state();
        let _server = AgentName::first();
        let mut mutator = RemoveAndLiftMutator::new(TermConstraints::default());

        // Returns the amount of extensions in the trace
        fn sum_extension_appends(trace: &Trace) -> u16 {
            trace.count_functions_by_name(fn_client_extensions_append.name())
        }

        loop {
            let mut trace = seed_client_attacker12.build_trace();
            let before_mutation = sum_extension_appends(&trace);
            let result = mutator.mutate(&mut state, &mut trace, 0).unwrap();

            if let MutationResult::Mutated = result {
                let after_mutation = sum_extension_appends(&trace);
                if after_mutation < before_mutation {
                    // extension removed
                    break;
                }
            }
        }
    }

    #[test]
    fn test_replace_reuse_mutator() {
        let mut state = create_state();
        let _server = AgentName::first();
        let mut mutator = ReplaceReuseMutator::new(TermConstraints::default());

        fn count_client_hello(trace: &Trace) -> u16 {
            trace.count_functions_by_name(fn_client_hello.name())
        }

        fn count_finished(trace: &Trace) -> u16 {
            trace.count_functions_by_name(fn_finished.name())
        }

        loop {
            let mut trace = seed_client_attacker12.build_trace();
            let result = mutator.mutate(&mut state, &mut trace, 0).unwrap();

            if let MutationResult::Mutated = result {
                let client_hellos = count_client_hello(&trace);
                let finishes = count_finished(&trace);
                if client_hellos == 2 && finishes == 0 {
                    // finished replaced by client_hello
                    break;
                }
            }
        }
    }

    #[test]
    fn test_skip_mutator() {
        let mut state = create_state();
        let _server = AgentName::first();
        let mut mutator = SkipMutator::new(2);

        loop {
            let mut trace = seed_client_attacker12.build_trace();
            let before_len = trace.steps.len();
            mutator.mutate(&mut state, &mut trace, 0).unwrap();

            if before_len - 1 == trace.steps.len() {
                break;
            }
        }
    }

    #[test]
    fn test_swap_mutator() {
        let mut state = create_state();
        let mut mutator = SwapMutator::new(TermConstraints::default());

        loop {
            let mut trace = seed_client_attacker12.build_trace();
            mutator.mutate(&mut state, &mut trace, 0).unwrap();

            let is_last_not_encrypt = if let Some(last) = trace.steps.iter().last() {
                match &last.action {
                    Action::Input(input) => Some(input.recipe.name() != fn_encrypt12.name()),
                    Action::Output(_) => None,
                }
            } else {
                None
            };

            let is_first_not_ch = if let Some(first) = trace.steps.get(0) {
                match &first.action {
                    Action::Input(input) => Some(input.recipe.name() != fn_client_hello.name()),
                    Action::Output(_) => None,
                }
            } else {
                None
            };

            if let Some(first) = is_first_not_ch {
                if let Some(last) = is_last_not_encrypt {
                    if first && last {
                        break;
                    }
                }
            }
        }
    }

    #[test]
    fn test_find_term() {
        let mut rand = StdRand::with_seed(45);
        let (client_hello, mut trace) = util::setup_simple_trace(current_put());

        let mut stats: HashSet<TracePath> = HashSet::new();

        for _ in 0..10000 {
            let path = crate::fuzzer::mutations::util::choose_term_path(
                &trace,
                TermConstraints::default(),
                &mut rand,
            )
            .unwrap();
            crate::fuzzer::mutations::util::find_term_mut(&mut trace, &path).unwrap();
            stats.insert(path);
        }

        assert_eq!(client_hello.size(), stats.len());
    }

    #[test]
    fn test_reservoir_sample_randomness() {
        /// https://rust-lang-nursery.github.io/rust-cookbook/science/mathematics/statistics.html#standard-deviation
        fn std_deviation(data: &[u32]) -> Option<f32> {
            fn mean(data: &[u32]) -> Option<f32> {
                let sum = data.iter().sum::<u32>() as f32;
                let count = data.len();

                match count {
                    positive if positive > 0 => Some(sum / count as f32),
                    _ => None,
                }
            }

            match (mean(data), data.len()) {
                (Some(data_mean), count) if count > 0 => {
                    let variance = data
                        .iter()
                        .map(|value| {
                            let diff = data_mean - (*value as f32);

                            diff * diff
                        })
                        .sum::<f32>()
                        / count as f32;

                    Some(variance.sqrt())
                }
                _ => None,
            }
        }

        let (client_hello, trace) = util::setup_simple_trace(current_put());

        let mut rand = StdRand::with_seed(45);
        let mut stats: HashMap<u32, u32> = HashMap::new();

        for _ in 0..10000 {
            let term = crate::fuzzer::mutations::util::choose(
                &trace,
                TermConstraints::default(),
                &mut rand,
            )
            .unwrap();

            let id = term.0.resistant_id();

            let count: u32 = *stats.get(&id).unwrap_or(&0);
            stats.insert(id, count + 1);
        }

        let std_dev =
            std_deviation(stats.values().cloned().collect::<Vec<u32>>().as_slice()).unwrap();
        /*        println!("{:?}", std_dev);
        println!("{:?}", stats);*/

        assert!(std_dev < 30.0);
        assert_eq!(client_hello.size(), stats.len());
    }

    #[test]
    fn test_corpus_term_size() {
        let corpus = create_corpus();
        let _trace_term_sizes = corpus
            .iter()
            .map(|(trace, name)| {
                (
                    name,
                    trace
                        .steps
                        .iter()
                        .map(|step| match &step.action {
                            Action::Input(input) => input.recipe.size(),
                            Action::Output(_) => 0,
                        })
                        .sum::<usize>(),
                )
            })
            .collect::<Vec<_>>();

        //println!("{:?}", trace_term_sizes);
    }

    mod util {
        use crate::{
            agent::{AgentDescriptor, AgentName, TLSVersion},
            algebra::Term,
            graphviz::write_graphviz,
            put::PutDescriptor,
            term,
            tls::fn_impl::*,
            trace::{Action, InputAction, Step, Trace},
        };

        pub fn setup_simple_trace(put_descriptor: PutDescriptor) -> (Term, Trace) {
            let server = AgentName::first();
            let client_hello = term! {
                  fn_client_hello(
                    fn_protocol_version12,
                    fn_new_random,
                    fn_new_session_id,
                    (fn_append_cipher_suite(
                        (fn_new_cipher_suites()),
                        // force TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
                        fn_cipher_suite12
                    )),
                    fn_compressions,
                    (fn_client_extensions_append(
                        (fn_client_extensions_append(
                            (fn_client_extensions_append(
                                (fn_client_extensions_append(
                                    (fn_client_extensions_append(
                                        (fn_client_extensions_append(
                                            fn_client_extensions_new,
                                            fn_secp384r1_support_group_extension
                                        )),
                                        fn_signature_algorithm_extension
                                    )),
                                    fn_ec_point_formats_extension
                                )),
                                fn_signed_certificate_timestamp_extension
                            )),
                             // Enable Renegotiation
                            (fn_renegotiation_info_extension(fn_empty_bytes_vec))
                        )),
                        // Add signature cert extension
                        fn_signature_algorithm_cert_extension
                    ))
                )
            };

            let cloned = client_hello.clone();
            (
                client_hello,
                Trace {
                    prior_traces: vec![],
                    descriptors: vec![AgentDescriptor {
                        name: server,
                        tls_version: TLSVersion::V1_2,
                        server: true,
                        try_reuse: false,
                        put_descriptor,
                    }],
                    steps: vec![Step {
                        agent: server,
                        action: Action::Input(InputAction { recipe: cloned }),
                    }],
                },
            )
        }

        impl Trace {
            pub fn count_functions_by_name(&self, find_name: &'static str) -> u16 {
                self.steps
                    .iter()
                    .map(|step| match &step.action {
                        Action::Input(input) => input.recipe.count_functions_by_name(find_name),
                        Action::Output(_) => 0,
                    })
                    .sum::<u16>()
            }

            pub fn write_plots(&self, i: u16) {
                write_graphviz(
                    format!("test_mutation{}.svg", i).as_str(),
                    "svg",
                    self.dot_graph(true).as_str(),
                )
                .unwrap();
            }
        }

        impl Term {
            pub fn count_functions_by_name(&self, find_name: &'static str) -> u16 {
                let mut found = 0;
                for term in self.into_iter() {
                    if let Term::Application(func, _) = term {
                        if func.name() == find_name {
                            found += 1;
                        }
                    }
                }
                found
            }
        }
    }
}
