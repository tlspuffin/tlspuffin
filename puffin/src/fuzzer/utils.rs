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
    // when true: only look for terms with no payload in sub-terms (for bit-le
    // note that we always exclude terms that are sub-terms of non-symbolic terms (i.e., with paylaods)
    pub no_payload_in_subterm: bool,
    // when true: we do not choose terms that have a list symbol and whose parent also has a list symbol
    // those terms are thus "inside a list", like t in fn_append(t,t3) for t = fn(append(t1,t2)
    pub not_inside_list: bool,
}

/// Default values which represent no constraint
impl Default for TermConstraints {
    fn default() -> Self {
        Self {
            min_term_size: 0,
            max_term_size: 300, // was 9000 but we were rewriting this to 300 anyway when instantiating the fuzzer
            no_payload_in_subterm: false,
            not_inside_list: false,
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
// RULE: never choose a term for a DY or bit-level mutation which a sub-term of a not is_symbolic() term
// Indeed, this latter term is considered atomic and a bitstring, including the former sub-term.
// leaves --> considered as atoms and not terms!
fn reservoir_sample<'a, R: Rand, M: Matcher, P: Fn(&TermEval<M>) -> bool + Copy>(
    trace: &'a Trace<M>,
    filter: P,
    constraints: TermConstraints,
    rand: &mut R,
) -> Option<(&'a TermEval<M>, TracePath)> {
    let mut reservoir: Option<(&'a TermEval<M>, TracePath)> = None;
    let mut visited = 0;

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

                let mut stack: Vec<(&TermEval<M>, TracePath, bool)> =
                    vec![(term, (step_index, Vec::new()), false)]; // bool is true for terms inside a list (e.g., fn_append)

                while let Some((term, path, is_inside_list)) = stack.pop() {
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
                                    new_path.1.push(path_index); // invert because of .iter().rev()
                                    let is_inside_list_sub =
                                        constraints.not_inside_list && fd.is_list();
                                    stack.push((subterm, new_path, is_inside_list_sub));
                                }
                            }
                        }
                    }

                    // sample
                    if filter(term)
                        && (!constraints.no_payload_in_subterm
                            || (term.is_symbolic() && term.all_payloads().is_empty())
                            || (!term.is_symbolic() && term.all_payloads().len() == 1))
                        && (!constraints.not_inside_list || !(is_inside_list && term.is_list()))
                    {
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

fn find_term_by_term_path_mut<'a, M: Matcher>(
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

fn find_term_by_term_path<'a, M: Matcher>(
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
