use libafl_bolts::rands::Rand;

use crate::algebra::{DYTerm, Term, TermType};
use crate::fuzzer::term_zoo::DEFAULT_MAX_DEPTH;
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
    /// Max depth of the terms generated for the zoo, see [`crate::fuzzer::term_zoo`]
    pub zoo_max_depth: u16,
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
            zoo_max_depth: DEFAULT_MAX_DEPTH,
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
    pub fn satisfy_constraints<PT: ProtocolTypes>(&self, term: &Term<PT>) -> bool {
        self.satisfy_constraints_with_size(term, term.size())
    }

    /// Same as [`Self::satisfy_constraints`], for a caller that already knows `term`'s size.
    ///
    /// [`TermType::size`] is recursive, so calling [`Self::satisfy_constraints`] at every node of a
    /// term makes a traversal quadratic in the term size. Traversals that fold the sizes bottom-up
    /// (see [`reservoir_sample`]) pass the size in instead.
    pub fn satisfy_constraints_with_size<PT: ProtocolTypes>(
        &self,
        term: &Term<PT>,
        size: usize,
    ) -> bool {
        // Use inclusive bounds (min <= size <= max)
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
            zoo_max_depth: DEFAULT_MAX_DEPTH,
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
    let mut path = TermPath::new();

    for (step_index, step) in trace.steps.iter().enumerate() {
        match &step.action {
            Action::Input(input) => {
                let term = &input.recipe;

                if !constraints.satisfy_size_max_constraints(term) {
                    log::warn!(
                        "[reservoir_sample] Skipping term because it is too large: {}",
                        term.size()
                    );
                    continue; // the term is too large, we don't even bother
                }

                path.clear();
                sample_subterms(
                    term,
                    step_index,
                    &mut path,
                    true,
                    filter,
                    constraints,
                    rand,
                    &mut reservoir,
                    &mut visited,
                );
            }
            Action::Output(_) => {
                // no term -> skip
            }
        }
    }

    reservoir
}

/// Post-order half of [`reservoir_sample`]: offers every selectable sub-term of `term` to the
/// reservoir and returns `term`'s [`TermType::size`].
///
/// The size is folded bottom-up so that the whole traversal stays linear in the term size:
/// calling [`TermType::size`] at each node instead would make it quadratic.
///
/// `selectable` says whether this node may be picked at all. It is `false` under a node the
/// constraints forbid recursing into ([`TermConstraints::should_recurse`]); the recursion still
/// goes on below such a node, but only to fold its size.
///
/// `path` is the path of `term` inside its recipe, maintained in place: each level pushes its
/// index before recursing and pops it after, so the whole traversal allocates a path only when the
/// reservoir is actually updated.
#[allow(clippy::too_many_arguments)]
fn sample_subterms<'a, R: Rand, PT: ProtocolTypes, P: Fn(&Term<PT>) -> bool + Copy>(
    term: &'a Term<PT>,
    step_index: StepIndex,
    path: &mut TermPath,
    selectable: bool,
    filter: P,
    constraints: &TermConstraints,
    rand: &mut R,
    reservoir: &mut Option<(&'a Term<PT>, TracePath)>,
    visited: &mut usize,
) -> usize {
    let children_selectable = selectable && constraints.should_recurse(term);

    // Mirrors `TermType::size`: a non-symbolic term counts as an atom, and so does a variable or a
    // constant.
    let mut size = 1;
    if term.is_symbolic() {
        match &term.term {
            DYTerm::Variable(_) => {}
            DYTerm::Application(_, subterms) => {
                for (path_index, subterm) in subterms.iter().enumerate() {
                    path.push(path_index);
                    size += sample_subterms(
                        subterm,
                        step_index,
                        path,
                        children_selectable,
                        filter,
                        constraints,
                        rand,
                        reservoir,
                        visited,
                    );
                    path.pop();
                }
            }
            // A deconstructor's source is its single sub-term, at index 0.
            DYTerm::Deconstructor(_, inner, _) => {
                path.push(0);
                size += sample_subterms(
                    inner,
                    step_index,
                    path,
                    children_selectable,
                    filter,
                    constraints,
                    rand,
                    reservoir,
                    visited,
                );
                path.pop();
            }
        }
    }

    // Check constraints and user filter
    if selectable && constraints.satisfy_constraints_with_size(term, size) && filter(term) {
        *visited += 1;

        // `1/visited` chance of overwriting: replace elements with gradually decreasing probability
        if reservoir.is_none() || rand.between(1, *visited) == 1 {
            *reservoir = Some((term, (step_index, path.clone())));
        }
    }

    size
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
        DYTerm::Deconstructor(_, inner, _) => {
            if subterm_index == 0 {
                find_term_by_term_path_mut(inner, &term_path[1..])
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
        DYTerm::Deconstructor(_, inner, _) => {
            if subterm_index == 0 {
                find_term_by_term_path(inner, &term_path[1..])
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
        log::warn!(
            "[find_all_sub_term_filtered] Skipping term because it is too large: {}",
            term.size()
        );
        return Vec::new(); // the term is too large, we don't even bother exploring it
    }

    let mut result = Vec::new();
    let mut path = TermPath::new();
    collect_subterms(term, &mut path, true, filter, constraints, &mut result);
    result
}

/// Post-order half of [`find_all_sub_term_filtered`]: same bottom-up size fold and in-place `path`
/// as [`sample_subterms`], collecting every matching path instead of sampling one.
fn collect_subterms<PT: ProtocolTypes, P: Fn(&Term<PT>) -> bool + Copy>(
    term: &Term<PT>,
    path: &mut TermPath,
    selectable: bool,
    filter: P,
    constraints: &TermConstraints,
    result: &mut Vec<TermPath>,
) -> usize {
    let children_selectable = selectable && constraints.should_recurse(term);

    let mut size = 1;
    if term.is_symbolic() {
        match &term.term {
            DYTerm::Variable(_) => {}
            DYTerm::Application(_, subterms) => {
                for (i, subterm) in subterms.iter().enumerate() {
                    path.push(i);
                    size += collect_subterms(
                        subterm,
                        path,
                        children_selectable,
                        filter,
                        constraints,
                        result,
                    );
                    path.pop();
                }
            }
            // A deconstructor's source is its single sub-term, at index 0.
            DYTerm::Deconstructor(_, inner, _) => {
                path.push(0);
                size += collect_subterms(
                    inner,
                    path,
                    children_selectable,
                    filter,
                    constraints,
                    result,
                );
                path.pop();
            }
        }
    }

    if selectable && constraints.satisfy_constraints_with_size(term, size) && filter(term) {
        result.push(path.clone());
    }

    size
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
