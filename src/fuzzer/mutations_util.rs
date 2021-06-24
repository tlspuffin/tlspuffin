use id_tree::Node;
use libafl::bolts::rands::Rand;

use crate::term::{Symbol, Term, TermId, TermNode};
use crate::trace::{Action, InputAction, Trace};

pub fn choose_iter_filtered<I, E, T, P, R: Rand>(from: I, filter: P, rand: &mut R) -> Option<T>
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

pub fn choose_iter<I, E, T, R: Rand>(from: I, rand: &mut R) -> Option<T>
where
    I: IntoIterator<Item = T, IntoIter = E>,
    E: ExactSizeIterator + Iterator<Item = T>,
{
    let mut iter = from.into_iter();
    // pick a random, valid index
    let index = rand.below(iter.len() as u64) as usize;

    // return the item chosen
    iter.into_iter().nth(index)
}

pub fn choose_input_action_mut<'a, R: Rand>(
    trace: &'a mut Trace,
    rand: &mut R,
) -> Option<&'a mut InputAction> {
    choose_iter_filtered(
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
    choose_iter_filtered(
        &trace.steps,
        |step| matches!(step.action, Action::Input(_)),
        rand,
    )
    .and_then(|step| match &step.action {
        Action::Input(input) => Some(input),
        Action::Output(_) => None,
    })
}

pub type StepIndex = usize;

pub fn get_input_action(trace: &Trace, index: StepIndex) -> Option<&Term> {
    if let Action::Input(input) = &trace.steps[index].action {
        Some(&input.recipe)
    } else {
        None
    }
}

pub fn get_step_by_index_mut(trace: &mut Trace, index: StepIndex) -> Option<&mut Term> {
    if let Action::Input(input) = &mut trace.steps[index].action {
        Some(&mut input.recipe)
    } else {
        None
    }
}

pub fn choose_term<R: Rand>(trace: &mut Trace, rand: &mut R) -> Option<(TermId, StepIndex)> {
    choose_term_filtered(trace, rand, |_, _| true)
}

pub fn choose_term_filtered<R: Rand, P: Fn(&TermId, StepIndex) -> bool + Copy>(
    trace: &Trace,
    rand: &mut R,
    filter: P,
) -> Option<(TermId, StepIndex)> {
    let mut ids: Vec::<(TermId, StepIndex)> = Vec::new();

    for (step_index, step) in trace.steps.iter().enumerate() {
        match &step.action {
            Action::Input(input) => {
                let term = &input.recipe;

                // todo remove unwraps
                ids.extend(
                    term.traverse_ids_from_root()
                        .unwrap()
                        .filter(|node| filter(node, step_index))
                        .map(|node| (node, step_index)),
                );
            }
            Action::Output(_) => {}
        }
    }

    let id = choose_iter(ids, rand).unwrap();
    Some(id)
}
