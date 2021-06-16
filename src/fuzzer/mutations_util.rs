use crate::trace::{Trace, InputAction, Action};
use crate::term::{Term};
use libafl::bolts::rands::Rand;

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

/// Finds a term by a `type_shape` and `requested_index`.
/// `requested_index` and `current_index` must be smaller than the amount of terms which have
/// the type shape `type_shape`.
pub fn find_term_mut<'a, R: Rand, P: Fn(&Term) -> bool + Copy>(
    term: &'a mut Term,
    rand: &mut R,
    requested_index: usize,
    mut current_index: usize,
    filter: P
) -> (Option<&'a mut Term>, usize) {
    let is_compatible = filter(term);
    if is_compatible && requested_index == current_index {
        (Some(term), current_index)
    } else {
        if is_compatible {
            // increment only if the term is relevant
            current_index += 1;
        };

        match term {
            Term::Application(_, ref mut subterms) => {
                for subterm in subterms {
                    let (selected, new_index) = find_term_mut(
                        subterm,
                        rand,
                        requested_index,
                        current_index,
                        filter,
                    );

                    current_index = new_index;

                    if let Some(selected) = selected {
                        return (Some(selected), new_index);
                    }
                }
            }
            Term::Variable(_) => {}
        }

        (None, current_index)
    }
}

pub fn choose_term_mut<'a, R: Rand, P: Fn(&Term) -> bool + Copy>(
    trace: &'a mut Trace,
    rand: &mut R,
    filter: P
) -> Option<&'a mut Term> {
    if let Some(input) = choose_input_action_mut(trace, rand) {
        let term = &mut input.recipe;
        let length = term.length_filtered(filter);

        if length == 0 {
            None
        } else {
            let requested_index = rand.between(0, (length - 1) as u64) as usize;
            find_term_mut(term, rand, requested_index, 0, filter).0
        }
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