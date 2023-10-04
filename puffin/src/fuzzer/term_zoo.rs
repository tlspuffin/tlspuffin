//! Generates a zoo of terms form a [`Signature`]. For each function symbol in the signature
//! a closed term is generated and added to the zoo.

use libafl::bolts::rands::Rand;

use crate::algebra::TermEval;
use crate::{
    algebra::{
        atoms::Function,
        signature::{FunctionDefinition, Signature},
        Matcher, Term,
    },
    fuzzer::utils::Choosable,
};

const MAX_DEPTH: u16 = 8; // how deep terms we allow max
const MAX_TRIES: u16 = 100; // How often we want to try to generate before stopping

pub struct TermZoo<M: Matcher> {
    terms: Vec<TermEval<M>>,
}

impl<M: Matcher> TermZoo<M> {
    pub fn generate<R: Rand>(signature: &Signature, rand: &mut R) -> Self {
        Self::generate_many(signature, rand, 1, None)
    }

    pub fn generate_many<R: Rand>(signature: &Signature, rand: &mut R, how_many: usize, filter: Option<&FunctionDefinition>) -> Self {
        let mut acc = vec![];
        if let Some(def) = filter {
            let mut counter = MAX_TRIES as usize * how_many;
            let mut many = 0;

            loop {
                if counter == 0 || many >= how_many {
                    break;
                }

                counter -= 1;

                if let Some(term) = Self::generate_term(signature, def, MAX_DEPTH, rand) {
                    many += 1;
                    acc.push(term);
                }
            }
        } else {
            for def in &signature.functions {
                let mut counter = MAX_TRIES as usize * how_many;
                let mut many = 0;

                loop {
                    if counter == 0 || many >= how_many {
                        break;
                    }

                    counter -= 1;

                    if let Some(term) = Self::generate_term(signature, def, MAX_DEPTH, rand) {
                        many += 1;
                        acc.push(term);
                    }
                }
            }
        }

        Self { terms: acc }
    }

    fn generate_term<R: Rand>(
        signature: &Signature,
        (shape, dynamic_fn): &FunctionDefinition,
        depth: u16,
        rand: &mut R,
    ) -> Option<TermEval<M>> {
        if depth == 0 {
            // Reached max depth
            return None;
        }

        let required_types = &shape.argument_types;

        let mut subterms = Vec::with_capacity(required_types.len());

        for typ in required_types {
            if let Some(possibilities) = signature.functions_by_typ.get(typ) {
                if let Some(possibility) = possibilities.choose(rand) {
                    if let Some(subterm) =
                        Self::generate_term(signature, possibility, depth - 1, rand)
                    {
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

        Some(TermEval::from(Term::Application(
            Function::new(shape.clone(), dynamic_fn.clone()),
            subterms,
        )))
    }

    pub fn choose_filtered<P, R: Rand>(&self, filter: P, rand: &mut R) -> Option<&TermEval<M>>
    where
        P: FnMut(&&TermEval<M>) -> bool,
    {
        self.terms.choose_filtered(filter, rand)
    }

    pub fn terms(&self) -> &[TermEval<M>] {
        &self.terms
    }
}
