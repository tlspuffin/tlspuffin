use std::cell::Cell;

use libafl_bolts::rands::Rand;

use crate::algebra::{DYTerm, Term, TermType};
use crate::protocol::ProtocolTypes;
use crate::trace::{Action, Step, Trace};

thread_local! {
    /// Per-stage anchor step lock. When set to `Some(k)`, every anchor drawn by
    /// [`reservoir_sample`] -- and therefore all `choose*` helpers built on it -- is restricted to
    /// step `k`. Set by [`crate::fuzzer::stages::StepLockedStackMutator`] so that all mutations
    /// stacked in one mutational stage edit the SAME step. Global/Step *fan-out* (via
    /// `find_all_term_filtered` / `find_all_sub_term_filtered`) does NOT consult this lock, so a
    /// Global mutation still spreads its effect across the whole trace -- only its anchor choice is
    /// confined to the locked step. Safe as a thread-local: LibAFL runs a single mutation thread
    /// per fuzzer process (one process per core), so there is no cross-trace interference.
    static STEP_LOCK: Cell<Option<StepIndex>> = const { Cell::new(None) };
}

/// Set (or clear, with `None`) the process-local anchor step lock. Returns the previous value so
/// the caller can restore it after the stage.
pub fn set_step_lock(step: Option<StepIndex>) -> Option<StepIndex> {
    STEP_LOCK.with(|c| c.replace(step))
}

/// Read the current anchor step lock (`None` when unlocked).
pub fn step_lock() -> Option<StepIndex> {
    STEP_LOCK.with(Cell::get)
}

/// Size budget for terms and traces during mutation.
///
/// # Units
///
/// All `*_size` values below are **node counts** in the term tree (`Term::size()`): every
/// application/variable counts 1, summed over the whole (symbolic) tree; `Trace::size()` sums each
/// input step's recipe size and additionally counts every output action as one node. They are NOT
/// bytes.
///
/// # How the caps relate
///
/// - `min_term_size` / `max_term_size`: bounds on a *sub-term selected* as a mutation candidate.
/// - `max_result_term_size`: **hard post-condition on the *result* of a replacement mutation** — a
///   mutation that would push any single step recipe over `max_result_term_size` is rejected
///   (reject-whole). Whole-trace growth is bounded instead by the number of steps
///   (`MutationConfig::max_result_trace_length`) times this per-step cap. It is enforced
///   *incrementally* on top of an already-bounded input (seeds within caps + reject-whole preserve
///   the invariant), so set them at or above the largest seed: a cap configured *below* an existing
///   seed's size is a corpus-boundary misconfiguration and cannot be enforced retroactively by the
///   mutators (see the precondition on `replacement_within_caps`).
///
/// # Maintenance rules — READ THIS BEFORE ADDING A PROTOCOL OR EXTENDING A MAPPER
///
/// These numbers are chosen from the sizes of the hand-written seeds/attacks. When you add a
/// protocol, add seeds, or grow the signature (mapper), **re-measure the seeds and re-check the
/// rules below**. As of this writing the largest seed values are:
///
/// | metric                         | TLS  | OPC UA | SSH  | rule for the cap                            |
/// |--------------------------------|------|--------|------|---------------------------------------------|
/// | max single-step recipe (nodes) | 324  | 137    | 285  | `max_term_size >= 2 * max_seed_term`        |
/// | max #steps                     | 13   | 10     | 10   | `max_result_trace_length >= max_seed_steps + 2` |
///
/// The current values sit **well above** these minima on purpose, to leave headroom for future
/// growth of the mappers (larger signatures / seed terms / longer attacks) without another cap
/// bump:
/// - `max_term_size` MUST be at least `2 * (largest single-term size across all seeds)` so seeds
///   (and moderately grown variants) stay selectable. Largest today = 324 (TLS) ⇒ rule wants ≥648;
///   set to 800.
/// - whole-trace growth is bounded by `MutationConfig::max_result_trace_length` (max #steps) times
///   the per-step `max_result_term_size` cap, so there is no separate whole-trace node cap.
///   `max_result_trace_length` is set to 20 (largest seed today = 13 steps, rule wants ≥15).
/// - `max_result_term_size` (whole step recipe after a replacement) is kept >= `max_term_size` so a
///   max-size replacement sub-term still fits; set to 1000.
#[derive(Copy, Clone, Debug)]
pub struct TermConstraints {
    /// Minimum size of a sub-term selected as a mutation candidate.
    pub min_term_size: usize,
    /// Maximum size of a sub-term selected as a mutation candidate. Rule: `>= 2 * max_seed_term`
    /// (largest single-term size across all seeds). Measured max seed term = 324 (TLS).
    pub max_term_size: usize,
    /// Hard post-condition: reject a replacement whose *result* makes any single step recipe
    /// exceed this many nodes. Rule: `> max_seed_term` with headroom (measured max = 324).
    pub max_result_term_size: usize,
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
            // Selection cap. Comfortably above the maintenance rule `>= 2 * max_seed_term`
            // (largest seed term today = 324 (TLS) => rule wants >= 648); we set 800 to leave
            // headroom for future growth of the mappers (larger signatures / seed terms).
            max_term_size: 800,
            // Post-condition cap (reject-whole) on a single step recipe, i.e. the largest a step
            // may become after a replacement. Kept >= `max_term_size` so a max-size replacement
            // sub-term still fits into a step.
            max_result_term_size: 1000,
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
    /// Returns whether a term satisfies all the constraint predicates.
    pub fn satisfy_constraints<PT: ProtocolTypes>(&self, term: &Term<PT>) -> bool {
        let size = term.size();
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
            max_result_term_size: usize::MAX,
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

    let locked = step_lock();
    for (step_index, step) in trace.steps.iter().enumerate() {
        // Anchor step lock: when a stage has locked a step, only draw anchors from that step.
        if let Some(k) = locked {
            if step_index != k {
                continue;
            }
        }
        match &step.action {
            Action::Input(input) => {
                let term = &input.recipe;

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

    #[test_log::test]
    fn test_step_lock_confines_anchors_to_locked_step() {
        let trace = setup_simple_trace();
        let n_steps = trace.steps.len();
        assert!(n_steps >= 2, "need a multi-step trace to test the lock");
        let mut rand = StdRand::with_seed(45);

        // With a lock set, every anchor drawn must come from exactly the locked step.
        for k in 0..n_steps {
            let prev = set_step_lock(Some(k));
            for _ in 0..500 {
                if let Some((_, (step_index, _))) =
                    choose(&trace, &TermConstraints::default(), &mut rand)
                {
                    assert_eq!(step_index, k, "anchor escaped the locked step {}", k);
                }
            }
            set_step_lock(prev);
        }

        // Without a lock, anchors must spread across more than one step (sanity: the lock is what
        // confined them above, not some other property of the trace).
        set_step_lock(None);
        let mut seen = HashSet::new();
        for _ in 0..2000 {
            if let Some((_, (step_index, _))) =
                choose(&trace, &TermConstraints::default(), &mut rand)
            {
                seen.insert(step_index);
            }
        }
        assert!(
            seen.len() > 1,
            "unlocked anchors should span multiple steps, saw {:?}",
            seen
        );
    }
}
