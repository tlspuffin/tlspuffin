use std::cmp::max;
use libafl::bolts::rands::Rand;
use log::error;

use crate::algebra::{TermEval, TermType};
use crate::protocol::ProtocolBehavior;
use crate::trace::InputAction;
use crate::{
    algebra::{Matcher, Term},
    trace::{Action, Step, Trace},
};

#[derive(Copy, Clone, Debug)]
pub struct TermConstraints {
    pub min_term_size: usize,
    pub max_term_size: usize,
    // [NO LONGER USED! Can be removed!]
    // when true: only look for terms with no payload in sub-terms (for bit-le
    // note that we always exclude terms that are sub-terms of non-symbolic terms (i.e., with paylaods)
    pub no_payload_in_subterm: bool,
    // when true: we do not choose terms that have a list symbol and whose parent also has a list symbol
    // those terms are thus "inside a list", like t in fn_append(t,t3) for t = fn(append(t1,t2)
    pub not_inside_list: bool,
    // choose term giving higher probability to deeper term
    pub weighted_depth: bool,

}

/// Default values which represent no constraint
impl Default for TermConstraints {
    fn default() -> Self {
        Self {
            min_term_size: 0,
            max_term_size: 300, // was 9000 but we were rewriting this to 300 anyway when instantiating the fuzzer
            no_payload_in_subterm: false,
            not_inside_list: false,
            weighted_depth: false,
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
// RULE: never choose a term for a DY or bit-level mutation which is a sub-term of a not is_symbolic() term
// Indeed, this latter term is considered atomic/leaf and is treated as a bitstring.
fn reservoir_sample<'a, R: Rand, M: Matcher, P: Fn(&TermEval<M>) -> bool + Copy>(
    trace: &'a Trace<M>,
    filter: P,
    constraints: TermConstraints,
    rand: &mut R
) -> Option<(&'a TermEval<M>, TracePath)> {
    // If if_wighted is set to true, we run a Reservoir Sampling algorithm per depth (of chosen sub-terms
    // in the overall recipe. See the two vectors: depth_counts and depth_reservoir, indices are depths.
    // Otherwise, the two above vectors have size 1 and we only store one counter and one sample, as
    // in the usual algorithm.
    let if_weighted = constraints.weighted_depth;
    let mut max_depth = 1;
    let mut depth_counts: Vec<u64> = vec![0];
    let mut depth_reservoir: Vec<Option<(&'a TermEval<M>, TracePath)>> = vec![None];
    // if if_weighted=false, we will only access the first cell of those two vec
    // independently of the depth

    // calculate max tree height amongst the input steps
    if if_weighted {
        for step in &trace.steps {
            match &step.action {
                Action::Input(input) => {
                    max_depth = max(max_depth, input.recipe.height());
                }
                Action::Output(_) => {}
            }
        }
        depth_counts.resize(max_depth, 0);
        depth_reservoir.resize(max_depth, None);
    }

    for (step_index, step) in trace.steps.iter().enumerate() {
        match &step.action {
            Action::Input(input) => {
                let term = &input.recipe;

                let size = term.size();
                if size <= constraints.min_term_size || size >= constraints.max_term_size {
                    continue;
                    //TODO-bitlevel: consider removing this, we just want to exclude picking such terms
                    // but it is OK to enter the term and look for suitable sub-terms
                }

                let mut stack: Vec<(&TermEval<M>, TracePath, bool, usize)> =
                    vec![(term, (step_index, Vec::new()), false, 0)]; // bool is true for terms inside a list (e.g., fn_append)
                                                                      // usize if for depth

                // DFS Algo: the version with if_weighted inplements the reservoir sampling algorithm
                // at each depth, independently
                while let Some((term, path, is_inside_list, depth)) = stack.pop() {
                    // push next terms onto stack

                    if term.is_symbolic() {
                        // if not, we reached a leaf (real leaf or a term with payloads)
                        match &term.term {
                            Term::Variable(_) => {
                                // reached leaf
                            }
                            Term::Application(fd, subterms) => {
                                // inner node, recursively continue
                                for (path_index, subterm) in subterms.iter().enumerate() {
                                    let mut new_path = path.clone();
                                    new_path.1.push(path_index);
                                    let is_inside_list_sub =
                                        constraints.not_inside_list && fd.is_list();
                                    stack.push((subterm, new_path, is_inside_list_sub, depth+1));
                                }
                            }
                        }
                    }

                    // sample
                    if filter(term)
                        && (!constraints.no_payload_in_subterm // TODO: currently not used!
                            || (term.is_symbolic() && term.all_payloads().is_empty()) // TODO: consider whether we want to use payloads_to_replace instead?
                            || (!term.is_symbolic() && term.all_payloads().len() == 1))
                        && (!constraints.not_inside_list || !(is_inside_list && term.is_list()))
                    {
                        let mut level = if if_weighted { // if weighted, we reason per-depth, otherwise, we reason globally
                            depth
                        } else { 0 };
                        depth_counts[level] += 1;

                        // consider in sampling
                        if depth_reservoir[level].is_none() {
                            // fill initial reservoir
                            depth_reservoir[level] = Some((term, path));
                        } else {
                                // `1/visited` chance of overwriting
                                // replace elements with gradually decreasing probability
                                if rand.between(1, depth_counts[level]) == 1 {
                                    depth_reservoir[level] = Some((term, path));
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

    // Picking the actual term by randmly picking a level
    let mut reservoir  = None;
    if if_weighted {
        // we need to randmly pick a depth from which we will sample the term
        // we give higher probability to deeper terms (linear bonus by 1+lambda) and proportional
        // to the number of elements in that depts (hence an exponetial bonus for deeper terms should
        // the overall term be roughly balanced
        let lambda = 0.5;
        let mut count_weighted = 0 as f64;
        for i in 0..max_depth {
            count_weighted += depth_counts[i] as f64 * (1 as f64 + (i as f64 * lambda));
            // TODO: ?: depth_counts[i] = count_weighted.floor() as u64;
        }
        let random = rand.between(0, count_weighted.floor() as u64);
        // print!("depth_counts: {:?}, count_weighted: {count_weighted}, random: {random}", depth_counts);
        let mut i = 0;
        count_weighted = 0 as f64;
        while random >= count_weighted as u64 && i < max_depth {
            count_weighted += depth_counts[i] as f64 * (1 as f64 + i as f64 * lambda);
            i += 1; // TODO: do it more efficiently by benefiting from the previous pre-processing
        }
        assert!(i>0);
        reservoir = depth_reservoir.remove(i-1);
    } else {
        reservoir = depth_reservoir.remove(0);
    }
    reservoir
}

pub fn find_term_by_term_path_mut<'a, M: Matcher>(
    term: &'a mut TermEval<M>,
    term_path: &mut TermPath,
) -> Option<&'a mut TermEval<M>> {
    if term_path.is_empty() {
        return Some(term);
    }

    let subterm_index = term_path.remove(0);

    match &mut term.term {
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

pub fn find_term_by_term_path<'a, M: Matcher>(
    term: &'a TermEval<M>,
    term_path: &mut TermPath,
) -> Option<&'a TermEval<M>> {
    if term_path.is_empty() {
        return Some(term);
    }

    let subterm_index = term_path.remove(0);

    match &term.term {
        Term::Variable(_) => None,
        Term::Application(_, subterms) => {
            if let Some(subterm) = subterms.get(subterm_index) {
                find_term_by_term_path(subterm, term_path)
            } else {
                None
            }
        }
    }
}

pub fn find_term_mut<'a, M: Matcher>(
    trace: &'a mut Trace<M>,
    trace_path: &TracePath,
) -> Option<&'a mut TermEval<M>> {
    let (step_index, term_path) = trace_path;

    let step: Option<&mut Step<M>> = trace.steps.get_mut(*step_index);
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

pub fn find_term<'a, M: Matcher>(
    trace: &'a Trace<M>,
    trace_path: &TracePath,
) -> Option<&'a TermEval<M>> {
    let (step_index, term_path) = trace_path;

    let step: Option<&Step<M>> = trace.steps.get(*step_index);
    if let Some(step) = step {
        match &step.action {
            Action::Input(input) => find_term_by_term_path(&input.recipe, &mut term_path.clone()),
            Action::Output(_) => None,
        }
    } else {
        None
    }
}

pub fn choose<'a, R: Rand, M: Matcher>(
    trace: &'a Trace<M>,
    constraints: TermConstraints,
    rand: &mut R,
) -> Option<(&'a TermEval<M>, (usize, TermPath))> {
    reservoir_sample(trace, |_| true, constraints, rand)
}

pub fn choose_mut<'a, R: Rand, M: Matcher>(
    trace: &'a mut Trace<M>,
    constraints: TermConstraints,
    rand: &mut R,
) -> Option<(&'a mut TermEval<M>, (usize, TermPath))> {
    if let Some((t, (u, path))) = reservoir_sample(trace, |_| true, constraints, rand) {
        let t = find_term_mut(trace, &(u, path.clone()));
        t.map(|t| (t, (u, path)))
    } else {
        None
    }
}

pub fn choose_term<'a, R: Rand, M: Matcher>(
    trace: &'a Trace<M>,
    constraints: TermConstraints,
    rand: &mut R,
) -> Option<&'a TermEval<M>> {
    reservoir_sample(trace, |_| true, constraints, rand).map(|ret| ret.0)
}

pub fn choose_term_mut<'a, R: Rand, M: Matcher>(
    trace: &'a mut Trace<M>,
    constraints: TermConstraints,
    rand: &mut R,
) -> Option<&'a mut TermEval<M>> {
    if let Some(trace_path) = choose_term_path_filtered(trace, |_| true, constraints, rand) {
        find_term_mut(trace, &trace_path)
    } else {
        None
    }
}

pub fn choose_term_filtered_mut<'a, R: Rand, M: Matcher, P: Fn(&TermEval<M>) -> bool + Copy>(
    trace: &'a mut Trace<M>,
    filter: P,
    constraints: TermConstraints,
    rand: &mut R,
) -> Option<&'a mut TermEval<M>> {
    if let Some(trace_path) = choose_term_path_filtered(trace, filter, constraints, rand) {
        find_term_mut(trace, &trace_path)
    } else {
        None
    }
}

pub fn choose_term_path<R: Rand, M: Matcher>(
    trace: &Trace<M>,
    constraints: TermConstraints,
    rand: &mut R,
) -> Option<TracePath> {
    choose_term_path_filtered(trace, |_| true, constraints, rand)
}

pub fn choose_term_path_filtered<R: Rand, M: Matcher, P: Fn(&TermEval<M>) -> bool + Copy>(
    trace: &Trace<M>,
    filter: P,
    constraints: TermConstraints,
    rand: &mut R,
) -> Option<TracePath> {
    reservoir_sample(trace, filter, constraints, rand).map(|ret| ret.1)
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
    use log::debug;

    use super::*;
    use crate::{agent::AgentName, algebra::{
        dynamic_function::DescribableFunction,
        test_signature::{TestTrace, TestProtocolBehavior, *},
        AnyMatcher, Term,
    }, trace::{Action, Step}, trace};

    #[test]
    fn test_find_term() {
        let mut rand = StdRand::with_seed(45);
        let mut trace = setup_simple_trace();
        let term_size = trace.count_functions();

        let mut stats: HashSet<TracePath> = HashSet::new();

        for _ in 0..10000 {
            let path = choose_term_path(&trace, TermConstraints::default(), &mut rand).unwrap();
            find_term_mut(&mut trace, &path).unwrap();
            stats.insert(path);
        }

        assert_eq!(term_size, stats.len());
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

        let trace = setup_simple_trace();
        let term_size = trace.count_functions();

        let mut rand = StdRand::with_seed(45);
        let mut stats: HashMap<u32, u32> = HashMap::new();

        for _ in 0..10000 {
            let term = choose(&trace, TermConstraints::default(), &mut rand).unwrap();

            let id = term.0.resistant_id();

            let count: u32 = *stats.get(&id).unwrap_or(&0);
            stats.insert(id, count + 1);
        }

        let std_dev =
            std_deviation(stats.values().cloned().collect::<Vec<u32>>().as_slice()).unwrap();
        /*        println!("{:?}", std_dev);
        println!("{:?}", stats);*/

        assert!(std_dev < 30.0);
        assert_eq!(term_size, stats.len());
    }

    #[test]
    fn test_reservoir_sample_weighted() {
        let mut rand = StdRand::with_seed(50);
        let mut trace = setup_simple_trace();
        let term_size = trace.count_functions();
        let constraints = TermConstraints {
            weighted_depth: true,
            .. TermConstraints::default()
        };
        let mut stats: HashSet<TracePath> = HashSet::new();

        for _ in 0..10000 {
            let path = choose_term_path(&trace, constraints, &mut rand).unwrap();
            find_term_mut(&mut trace, &path).unwrap();
            stats.insert(path);
        }

        assert_eq!(term_size, stats.len());
    }
}