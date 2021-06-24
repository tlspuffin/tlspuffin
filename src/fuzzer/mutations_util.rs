use libafl::bolts::rands::Rand;

use crate::term::Term;
use crate::trace::{Action, InputAction, Step, Trace};

pub fn choose_iter<I, E, T, P, R: Rand>(from: I, filter: P, rand: &mut R) -> Option<T>
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

pub fn choose_input_action_mut<'a, R: Rand>(
    trace: &'a mut Trace,
    rand: &mut R,
) -> Option<&'a mut InputAction> {
    choose_iter(
        &mut trace.steps,
        |step| matches!(step.action, Action::Input(_)),
        rand,
    )
    .and_then(|step| match &mut step.action {
        Action::Input(input) => Some(input),
        Action::Output(_) => None,
    })
}

pub fn choose_input_action<'a, R: Rand>(trace: &'a Trace, rand: &mut R) -> Option<&'a InputAction> {
    choose_iter(
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

    println!("sdf");

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

pub fn choose<'a, R: Rand>(trace: &'a Trace, rand: &mut R) -> Option<(&'a Term, (usize, TermPath))> {
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
