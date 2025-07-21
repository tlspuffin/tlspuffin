//! Generates a zoo of terms form a [`Signature`]. For each function symbol in the signature
//! a closed term is generated and added to the zoo.

use libafl_bolts::rands::Rand;

use crate::algebra::atoms::Function;
use crate::algebra::signature::{FunctionDefinition, Signature};
use crate::algebra::{DYTerm, Term, TermType};
use crate::fuzzer::utils::Choosable;
use crate::protocol::ProtocolBehavior;
use crate::trace::TraceContext;

const MAX_DEPTH: u16 = 8; // how deep terms we allow max
const MAX_TRIES: usize = 140_000; // How often we want to try to generate before stopping

pub struct TermZoo<PB: ProtocolBehavior> {
    terms: Vec<Term<PB::ProtocolTypes>>,
}

impl<PB: ProtocolBehavior> TermZoo<PB> {
    pub fn generate<R: Rand>(
        ctx: &TraceContext<PB>,
        signature: &Signature<PB::ProtocolTypes>,
        rand: &mut R,
        how_many: usize,
    ) -> Self {
        Self::generate_many(ctx, signature, rand, how_many, None, true, true)
    }

    pub fn generate_many<R: Rand>(
        ctx: &TraceContext<PB>,
        signature: &Signature<PB::ProtocolTypes>,
        rand: &mut R,
        how_many: usize, // how many terms to generate
        filter: Option<&FunctionDefinition<PB::ProtocolTypes>>,
        filter_evaluated: bool,
        filter_no_gen: bool,
    ) -> Self {
        let mut acc = vec![];
        if let Some(def) = filter {
            let mut counter = MAX_TRIES;
            let mut many = 0;

            loop {
                if counter == 0 || many >= how_many {
                    break;
                }

                counter -= 1;

                if let Some(term) = Self::generate_term(signature, def, MAX_DEPTH, rand) {
                    // If filter_evaluated, we must check the term can be evaluated before including
                    // it
                    if !filter_evaluated || term.evaluate(ctx).is_ok() {
                        many += 1;
                        counter = MAX_TRIES;
                        acc.push(term);
                    }
                }
            }
        } else {
            for def in &signature.functions {
                if filter_no_gen && signature.attrs_by_name.get(def.0.name).unwrap().no_gen {
                    log::debug!("Skipping generation for [{:?}]", def.0.name);
                    continue; // Skip this function symbol
                }
                let mut counter = MAX_TRIES;
                let mut many = 0;

                loop {
                    if counter == 0 || many >= how_many {
                        break;
                    }

                    counter -= 1;

                    if let Some(term) = Self::generate_term(signature, def, MAX_DEPTH, rand) {
                        if !filter_evaluated || term.evaluate(ctx).is_ok() {
                            many += 1;
                            counter = MAX_TRIES;
                            acc.push(term);
                        }
                    }
                }
            }
        }

        Self { terms: acc }
    }

    fn generate_term<R: Rand>(
        signature: &Signature<PB::ProtocolTypes>,
        (shape, dynamic_fn): &FunctionDefinition<PB::ProtocolTypes>,
        depth: u16,
        rand: &mut R,
    ) -> Option<Term<PB::ProtocolTypes>> {
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
                        subterms.push(subterm);
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

        Some(Term::from(DYTerm::Application(
            Function::new(shape.clone(), dynamic_fn.clone()),
            subterms,
        )))
    }

    pub fn choose_filtered<P, R: Rand>(
        &self,
        filter: P,
        rand: &mut R,
    ) -> Option<&Term<PB::ProtocolTypes>>
    where
        P: FnMut(&&Term<PB::ProtocolTypes>) -> bool,
    {
        self.terms.choose_filtered(filter, rand)
    }

    #[must_use]
    pub fn terms(&self) -> &[Term<PB::ProtocolTypes>] {
        &self.terms
    }
}
