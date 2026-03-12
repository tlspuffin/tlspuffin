use libafl_bolts::rands::Rand;

use crate::algebra::{DYTerm, Term, TermType};
use crate::protocol::ProtocolTypes;
use crate::trace::{Action, Step, Trace};

#[derive(Copy, Clone, Debug)]
pub struct TermConstraints {
    // For selecting (sub)terms for mutation candidates, for example
    pub min_term_size: usize,
    pub max_term_size: usize,
    // For continuing exploring (sub)terms, if larger: we don't even bother traversing the term
    pub max_term_size_explore: usize,
    pub must_be_symbolic: bool,
    /// when true: only look for terms with no payload in sub-terms
    pub no_payload_in_subterm: bool,
    // when true: only look for terms with at least one payload in sub-terms
    pub must_payload_in_subterm: bool,
    /// when true: we do not choose terms that have a list symbol and whose parent also has a list
    /// symbol those terms are thus "inside a list", like t in fn_append(t,t3) for t =
    /// fn(append(t1,t2)
    pub not_inside_list: bool,
    /// choose term giving higher probability to deeper term
    pub weighted_depth: bool,
    /// only select root terms
    pub must_be_root: bool,
    /// when true: only look for readable terms
    pub not_readable: bool,
    /// Forbids sub-terms with no det function symbols
    pub must_be_det: bool,
    /// Number of terms to generate for each type
    pub zoo_gen_how_many: usize,
    /// Max number of paylaods per term (limiting further MakeMessage)
    pub threshold_max_payloads_per_term: usize,
}

/// Default values which represent no constraint
impl Default for TermConstraints {
    fn default() -> Self {
        Self {
            min_term_size: 0,
            max_term_size: 300, // we do not select larger terms for mutations
            /* was 9000 but we were rewriting this to 300 anyway when
             * instantiating the fuzzer */
            max_term_size_explore: 1000, // we don't even bother exploring terms that are too large
            must_be_symbolic: false,
            no_payload_in_subterm: false,
            must_payload_in_subterm: false,
            not_inside_list: false,
            weighted_depth: false,
            must_be_root: false,
            not_readable: false,
            must_be_det: false,
            zoo_gen_how_many: 10, /* Over-approximates 1/10 of the threshold obtained from
                                   * `test_term_payloads_eval`, making sure we successfully
                                   * generate, MakeMessage,
                                   * and evaluate after 10 expansions of TermZoo. Was 1 initially */
            threshold_max_payloads_per_term: 10,
        }
    }
}

impl TermConstraints {
    /// Returns whether a term is not extremely large (in which case we don't even bother exploring
    /// it)
    pub fn satisfy_size_max_constraints<PT: ProtocolTypes>(&self, term: &Term<PT>) -> bool {
        term.size() < self.max_term_size_explore
    }

    /// Returns whether a term satisfies all the constraint predicates.
    /// This does NOT include the user-supplied filter — callers must check that separately.
    pub fn satisfy_constraints<PT: ProtocolTypes>(&self, term: &Term<PT>) -> bool {
        let size = term.size();
        // Use exclusive bounds (min < size < max)
        if size < self.min_term_size || size > self.max_term_size {
            return false;
        }

        if self.must_be_symbolic && !term.is_symbolic() {
            return false;
        }
        if self.no_payload_in_subterm {
            // filter-out terms with payload in strict sub-term
            if term.is_symbolic() && term.has_payload_to_replace() {
                return false;
            }
            if !term.is_symbolic() && term.has_payload_to_replace_wo_root() {
                return false;
            }
        }
        if self.not_inside_list && term.is_list() {
            return false;
        }
        if self.not_readable && term.is_readable() {
            return false;
        }
        if self.must_be_det && term.has_no_det() {
            return false;
        }
        true
    }

    /// Returns whether we should recurse into the sub-terms of a given term.
    pub fn should_recurse<PT: ProtocolTypes>(&self, term: &Term<PT>) -> bool {
        // Only recurse into symbolic terms, and not when we only want root terms
        !self.must_be_root && term.is_symbolic()
    }

    /// Return TermConstraints with minimal/no constraint
    pub fn no_constraint() -> Self {
        Self {
            min_term_size: 0,
            max_term_size: usize::MAX,
            max_term_size_explore: usize::MAX,
            must_be_symbolic: false,
            no_payload_in_subterm: false,
            must_payload_in_subterm: false,
            not_inside_list: false,
            weighted_depth: false,
            must_be_root: false,
            not_readable: false,
            must_be_det: false,
            zoo_gen_how_many: usize::MAX,
            threshold_max_payloads_per_term: usize::MAX,
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
            let index = rand.below_or_zero(length);
            filtered.into_iter().nth(index)
        }
    }

    fn choose(&self, rand: &mut R) -> Option<&T> {
        let length = self.len();

        if length == 0 {
            None
        } else {
            let index = rand.below_or_zero(length);
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
        let index = rand.below_or_zero(length);

        // return the item chosen
        iter.nth(index)
    }
}

pub type StepIndex = usize;
pub type TermPath = Vec<usize>;
pub type TracePath = (StepIndex, TermPath);

/// <https://en.wikipedia.org/wiki/Reservoir_sampling#Simple_algorithm>
pub fn reservoir_sample<'a, R: Rand, PT: ProtocolTypes, P: Fn(&Term<PT>) -> bool + Copy>(
    trace: &'a Trace<PT>,
    filter: P,
    constraints: &TermConstraints,
    rand: &mut R,
) -> Option<(&'a Term<PT>, TracePath)> {
    let mut reservoir: Option<(&'a Term<PT>, TracePath)> = None;
    let mut visited = 0;

    for (step_index, step) in trace.steps.iter().enumerate() {
        match &step.action {
            Action::Input(input) => {
                let term = &input.recipe;

                if !constraints.satisfy_size_max_constraints(term) {
                    log::error!(
                        "[reservoir_sample] Skipping term because it is too large: {}",
                        term.size()
                    );
                    continue; // the term is too large, we don't even bother
                }

                let mut stack: Vec<(&Term<PT>, TracePath)> = vec![(term, (step_index, Vec::new()))];

                while let Some((term, path)) = stack.pop() {
                    // Recurse into sub-terms if allowed
                    if constraints.should_recurse(term) {
                        if let DYTerm::Application(_, subterms) = &term.term {
                            for (path_index, subterm) in subterms.iter().enumerate() {
                                let mut new_path = path.clone();
                                new_path.1.push(path_index);
                                stack.push((subterm, new_path));
                            }
                        }
                    }

                    // Check constraints and user filter
                    if constraints.satisfy_constraints(term) && filter(term) {
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
                find_term_by_term_path_mut(&mut input.recipe, &term_path.clone())
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
            Action::Input(input) => find_term_by_term_path(&input.recipe, &term_path.clone()),
            Action::Output(_) => None,
        }
    } else {
        None
    }
}

pub fn choose<'a, R: Rand, PT: ProtocolTypes>(
    trace: &'a Trace<PT>,
    constraints: &TermConstraints,
    rand: &mut R,
) -> Option<(&'a Term<PT>, (usize, TermPath))> {
    reservoir_sample(trace, |_| true, constraints, rand)
}

pub fn choose_filtered<'a, R: Rand, PT: ProtocolTypes, P: Fn(&Term<PT>) -> bool + Copy>(
    trace: &'a Trace<PT>,
    constraints: &TermConstraints,
    filter: P,
    rand: &mut R,
) -> Option<(&'a Term<PT>, (usize, TermPath))> {
    reservoir_sample(trace, filter, constraints, rand)
}

pub fn choose_mut<'a, R: Rand, PT: ProtocolTypes>(
    trace: &'a mut Trace<PT>,
    constraints: &TermConstraints,
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
    constraints: &TermConstraints,
    rand: &mut R,
) -> Option<&'a Term<PT>> {
    reservoir_sample(trace, |_| true, constraints, rand).map(|ret| ret.0)
}

pub fn choose_term_mut<'a, R: Rand, PT: ProtocolTypes>(
    trace: &'a mut Trace<PT>,
    constraints: &TermConstraints,
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
    constraints: &TermConstraints,
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
    constraints: &TermConstraints,
    rand: &mut R,
) -> Option<TracePath> {
    choose_term_path_filtered(trace, |_| true, constraints, rand)
}

pub fn choose_term_path_filtered<R: Rand, PT: ProtocolTypes, P: Fn(&Term<PT>) -> bool + Copy>(
    trace: &Trace<PT>,
    filter: P,
    constraints: &TermConstraints,
    rand: &mut R,
) -> Option<TracePath> {
    reservoir_sample(trace, filter, constraints, rand).map(|ret| ret.1)
}

/// Finds all sub-terms in a given term that satisfy a filtering condition and term constraints.
pub fn find_all_sub_term_filtered<PT: ProtocolTypes, P: Fn(&Term<PT>) -> bool + Copy>(
    term: &Term<PT>,
    filter: P,
    constraints: &TermConstraints,
) -> Vec<TermPath> {
    if !constraints.satisfy_size_max_constraints(term) {
        log::error!(
            "[find_all_sub_term_filtered] Skipping term because it is too large: {}",
            term.size()
        );
        return Vec::new(); // the term is too large, we don't even bother exploring it
    }

    let mut result = Vec::new();
    let mut stack: Vec<(&Term<PT>, TermPath)> = vec![(term, Vec::new())];

    while let Some((current, path)) = stack.pop() {
        // Recurse into sub-terms if allowed
        if constraints.should_recurse(current) {
            if let DYTerm::Application(_, subterms) = &current.term {
                for (i, subterm) in subterms.iter().enumerate() {
                    let mut new_path = path.clone();
                    new_path.push(i);
                    stack.push((subterm, new_path));
                }
            }
        }

        if constraints.satisfy_constraints(current) && filter(current) {
            result.push(path);
        }
    }

    result
}

/// Finds all trace paths in a trace that satisfy a given filter predicate and term constraints.
pub fn find_all_term_filtered<PT: ProtocolTypes, P: Fn(&Term<PT>) -> bool + Copy>(
    trace: &Trace<PT>,
    filter: P,
    constraints: &TermConstraints,
) -> Vec<TracePath> {
    trace
        .steps
        .iter()
        .enumerate()
        .flat_map(|(step_index, step)| match &step.action {
            Action::Input(input) => {
                let term = &input.recipe;
                find_all_sub_term_filtered(term, filter, constraints)
                    .into_iter()
                    .map(move |term_path| (step_index, term_path))
                    .collect::<Vec<_>>()
            }
            Action::Output(_) => vec![],
        })
        .collect()
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
            let path = choose_term_path(&trace, &TermConstraints::default(), &mut rand).unwrap();
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
            let term = choose(&trace, &TermConstraints::default(), &mut rand).unwrap();

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
