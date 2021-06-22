use libafl::bolts::rands::Rand;

use crate::term::{Symbol, Term, TermNode};
use crate::trace::{Action, InputAction, Trace};

pub fn choose_iter<I, E, T, P, R: Rand>(from: I, filter: P, rand: &mut R) -> Option<T>
where
    I: IntoIterator<Item = T, IntoIter = E>,
    E: ExactSizeIterator + Iterator<Item = T>,
    P: Fn(&T) -> bool,
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

pub fn choose_term_mut<'a, R: Rand, P: Fn(&&mut TermNode) -> bool + Copy>(
    trace: &'a mut Trace,
    rand: &mut R,
    filter: P,
) -> Option<(&'a mut TermNode, &'a Term)> {
    // todo get rid of this next line and randomly select a term over all input actions
    //      https://gitlab.inria.fr/mammann/tlspuffin/-/issues/66
    if let Some(input) = choose_input_action_mut(trace, rand) {
        let term = &mut input.recipe;
        Some((choose_iter(&mut term.nodes, filter, rand).unwrap(), term))
    } else {
        None
    }
}

pub fn choose_term_id<'a, R: Rand>(trace: &'a Trace, rand: &mut R) -> Option<(&'a TermNode, &'a Term)> {
    if let Some(input) = choose_input_action(trace, rand) {
        let term = &input.recipe;
        Some((choose_iter(&term.nodes, |node| true, rand).unwrap(), term))
    } else {
        None
    }
}
