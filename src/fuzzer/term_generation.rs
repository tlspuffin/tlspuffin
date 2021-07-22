use itertools::{Itertools};
use libafl::bolts::rands::Rand;

use crate::fuzzer::mutations::util::{Choosable, choose_iter};
use crate::term::atoms::Function;
use crate::term::signature::{FunctionDefinition, Signature};
use crate::term::Term;

const MAX_DEPTH: u16 = 15;

pub fn generate_multiple_terms<R: Rand>(signature: &Signature, rand: &mut R) -> Vec<Term> {
    vec![
        generate_terms(signature, rand),
        generate_terms(signature, rand),
        generate_terms(signature, rand),
    ].into_iter()
        .flatten()
        .unique()
        .collect_vec()
}

pub fn generate_terms<R: Rand>(signature: &Signature, rand: &mut R) -> Vec<Term> {
    signature
        .functions
        .iter()
        .filter_map(|def| {
           generate_term(signature, &def, MAX_DEPTH, rand)
        })
        .collect_vec()
}

fn generate_term<R: Rand>(
    signature: &Signature,
    (shape, dynamic_fn): &FunctionDefinition,
    depth: u16,
    rand: &mut R,
) -> Option<Term> {
    if depth == 0 {
        // Reached max depth
        return None;
    }

    let required_types = &shape.argument_types;

    let mut subterms = Vec::with_capacity(required_types.len());

    for typ in required_types {
        if let Some(possibilities) = signature.functions_by_typ.get(typ) {
            if let Some(possibility) = possibilities.choose(rand) {
                if let Some(subterm) = generate_term(signature, possibility, depth - 1, rand) {
                    subterms.push(subterm)
                } else {
                    // Max depth reached
                    return None;
                }
            } else {
                // No possibilities available
                return None;
            }
        } else {
            // Type not available
            return None;
        }
    }

    Some(Term::Application(
        Function::new(shape.clone(), dynamic_fn.clone()),
        subterms,
    ))
}
