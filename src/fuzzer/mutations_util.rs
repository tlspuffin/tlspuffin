use crate::trace::{Trace, InputAction, Action};
use crate::term::{Term};
use libafl::bolts::rands::Rand;
use std::rc::Rc;

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

pub fn choose_term_mut<'a, R: Rand, P: Fn(&Term) -> bool + Copy>(
    trace: &'a mut Trace,
    rand: &mut R,
    filter: P
) -> Option<&'a mut Term> {
    // todo get rid of this next line and randomly select a term over all input actions
    //      https://gitlab.inria.fr/mammann/tlspuffin/-/issues/66
    if let Some(input) = choose_input_action_mut(trace, rand) {
        let term = &mut input.recipe;
        let size = term.length();

        let index = rand.between(0, (size - 1) as u64) as usize;

        let x: &mut Term = Rc::make_mut(term).into_iter().nth(index).unwrap();

        None
    } else {
        None
    }
}

pub fn choose_term<'a, R: Rand>(trace: &'a Trace, rand: &mut R) -> Option<&'a Term> {
    if let Some(input) = choose_input_action(trace, rand) {
        let term = &input.recipe;
        let size = term.length();

        let index = rand.between(0, (size - 1) as u64) as usize;

        term.into_iter().nth(index)
    } else {
        None
    }
}