use libafl_bolts::rands::Rand;

use crate::algebra::{DYTerm, Term, TermType};
use crate::protocol::ProtocolTypes;
use crate::trace::{Action, Step, Trace};

#[derive(Copy, Clone, Debug)]
pub struct TermConstraints {
    pub min_term_size: usize,
    pub max_term_size: usize,
    pub must_be_symbolic: bool,
    // when true: only look for terms with no payload in sub-terms
    pub no_payload_in_subterm: bool,
    // when true: we do not choose terms that have a list symbol and whose parent also has a list
    // symbol those terms are thus "inside a list", like t in fn_append(t,t3) for t =
    // fn(append(t1,t2)
    pub not_inside_list: bool,
    // choose term giving higher probability to deeper term
    pub weighted_depth: bool,
    // only select root terms
    pub must_be_root: bool,
}

/// Default values which represent no constraint
impl Default for TermConstraints {
    fn default() -> Self {
        Self {
            min_term_size: 0,
            max_term_size: 300, /* was 9000 but we were rewriting this to 300 anyway when
                                 * instantiating the fuzzer */
            must_be_symbolic: false,
            no_payload_in_subterm: false,
            not_inside_list: false,
            weighted_depth: false,
            must_be_root: false,
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

/// <https://en.wikipedia.org/wiki/Reservoir_sampling#Simple_algorithm>
fn reservoir_sample<'a, R: Rand, PT: ProtocolTypes, P: Fn(&Term<PT>) -> bool + Copy>(
    trace: &'a Trace<PT>,
    filter: P,
    constraints: TermConstraints,
    rand: &mut R,
) -> Option<(&'a Term<PT>, TracePath)> {
    let mut reservoir: Option<(&'a Term<PT>, TracePath)> = None;
    let mut visited = 0;

    for (step_index, step) in trace.steps.iter().enumerate() {
        match &step.action {
            Action::Input(input) => {
                let term = &input.recipe;

                let size = term.size();
                if size <= constraints.min_term_size || size >= constraints.max_term_size {
                    continue;
                }

                let mut stack: Vec<(&Term<PT>, TracePath)> = vec![(term, (step_index, Vec::new()))];

                while let Some((term, path)) = stack.pop() {
                    // push next terms onto stack
                    match &term.term {
                        DYTerm::Variable(_) => {
                            // reached leaf
                        }
                        DYTerm::Application(_, subterms) => {
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

pub fn find_term_by_term_path_mut<'a, PT: ProtocolTypes>(
    term: &'a mut Term<PT>,
    term_path: &[usize],
) -> Option<&'a mut Term<PT>> {
    if term_path.is_empty() {
        return Some(term);
    }
    let subterm_index = term_path[0];

    match &mut term.term {
        DYTerm::Variable(_) => None,
        DYTerm::Application(_, subterms) => {
            if let Some(subterm) = subterms.get_mut(subterm_index) {
                find_term_by_term_path_mut(subterm, &term_path[1..])
            } else {
                None
            }
        }
    }
}

pub fn find_term_by_term_path<'a, PT: ProtocolTypes>(
    term: &'a Term<PT>,
    term_path: &[usize],
) -> Option<&'a Term<PT>> {
    if term_path.is_empty() {
        return Some(term);
    }

    let subterm_index = term_path[0];

    match &term.term {
        DYTerm::Variable(_) => None,
        DYTerm::Application(_, subterms) => {
            if let Some(subterm) = subterms.get(subterm_index) {
                find_term_by_term_path(subterm, &term_path[1..])
            } else {
                None
            }
        }
    }
}

pub fn find_term_mut<'a, PT: ProtocolTypes>(
    trace: &'a mut Trace<PT>,
    trace_path: &TracePath,
) -> Option<&'a mut Term<PT>> {
    let (step_index, term_path) = trace_path;

    let step: Option<&mut Step<PT>> = trace.steps.get_mut(*step_index);
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

#[must_use]
pub fn find_term<'a, PT: ProtocolTypes>(
    trace: &'a Trace<PT>,
    trace_path: &TracePath,
) -> Option<&'a Term<PT>> {
    let (step_index, term_path) = trace_path;

    let step: Option<&Step<PT>> = trace.steps.get(*step_index);
    if let Some(step) = step {
        match &step.action {
            Action::Input(input) => find_term_by_term_path(&input.recipe, &mut term_path.clone()),
            Action::Output(_) => None,
        }
    } else {
        None
    }
}

pub fn choose<'a, R: Rand, PT: ProtocolTypes>(
    trace: &'a Trace<PT>,
    constraints: TermConstraints,
    rand: &mut R,
) -> Option<(&'a Term<PT>, (usize, TermPath))> {
    reservoir_sample(trace, |_| true, constraints, rand)
}

pub fn choose_mut<'a, R: Rand, PT: ProtocolTypes>(
    trace: &'a mut Trace<PT>,
    constraints: TermConstraints,
    rand: &mut R,
) -> Option<(&'a mut Term<PT>, (usize, TermPath))> {
    if let Some((_, (u, path))) = reservoir_sample(trace, |_| true, constraints, rand) {
        let t = find_term_mut(trace, &(u, path.clone()));
        t.map(|t| (t, (u, path)))
    } else {
        None
    }
}

pub fn choose_term<'a, R: Rand, PT: ProtocolTypes>(
    trace: &'a Trace<PT>,
    constraints: TermConstraints,
    rand: &mut R,
) -> Option<&'a Term<PT>> {
    reservoir_sample(trace, |_| true, constraints, rand).map(|ret| ret.0)
}

pub fn choose_term_mut<'a, R: Rand, PT: ProtocolTypes>(
    trace: &'a mut Trace<PT>,
    constraints: TermConstraints,
    rand: &mut R,
) -> Option<&'a mut Term<PT>> {
    if let Some(trace_path) = choose_term_path_filtered(trace, |_| true, constraints, rand) {
        find_term_mut(trace, &trace_path)
    } else {
        None
    }
}

pub fn choose_term_filtered_mut<'a, R: Rand, PT: ProtocolTypes, P: Fn(&Term<PT>) -> bool + Copy>(
    trace: &'a mut Trace<PT>,
    filter: P,
    constraints: TermConstraints,
    rand: &mut R,
) -> Option<&'a mut Term<PT>> {
    if let Some(trace_path) = choose_term_path_filtered(trace, filter, constraints, rand) {
        find_term_mut(trace, &trace_path)
    } else {
        None
    }
}

pub fn choose_term_path<R: Rand, PT: ProtocolTypes>(
    trace: &Trace<PT>,
    constraints: TermConstraints,
    rand: &mut R,
) -> Option<TracePath> {
    choose_term_path_filtered(trace, |_| true, constraints, rand)
}

pub fn choose_term_path_filtered<R: Rand, PT: ProtocolTypes, P: Fn(&Term<PT>) -> bool + Copy>(
    trace: &Trace<PT>,
    filter: P,
    constraints: TermConstraints,
    rand: &mut R,
) -> Option<TracePath> {
    reservoir_sample(trace, filter, constraints, rand).map(|ret| ret.1)
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};

    use libafl_bolts::rands::StdRand;

    use super::*;
    use crate::algebra::test_signature::*;

    #[test_log::test]
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

    #[test_log::test]
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
            std_deviation(stats.values().copied().collect::<Vec<u32>>().as_slice()).unwrap();
        /*        println!("{:?}", std_dev);
        println!("{:?}", stats);*/

        assert!(std_dev < 30.0);
        assert_eq!(term_size, stats.len());
    }
}
