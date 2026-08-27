//! Generates a zoo of terms form a [`Signature`]. For each function symbol in the signature
//! a closed term is generated and added to the zoo.

use libafl_bolts::rands::Rand;

use crate::algebra::atoms::Function;
use crate::algebra::signature::{FunctionDefinition, Signature};
use crate::algebra::{DYTerm, Term, TermType};
use crate::fuzzer::utils::Choosable;
use crate::protocol::ProtocolBehavior;
use crate::trace::TraceContext;

/// Default for [`crate::fuzzer::utils::TermConstraints::zoo_max_depth`]: how deep the terms we
/// generate may be.
///
/// A generated term must reach a closed leaf within that many levels, so this bounds which
/// function symbols the zoo can produce a term for at all. It has to be read together with the
/// *encoding* depth of the signature: with constructors generated from the protocol types, a
/// message is built through a chain of wrappers (for TLS: `fn_message` -> `fn_messagepayload_*`
/// -> `fn_handshakemessagepayload` -> `fn_handshakepayload_*` -> the payload struct) before the
/// interesting fields are even reached, so a value that used to sit at depth 2 now sits at depth
/// 6. A budget sized for a flat signature silently makes whole families of symbols
/// ungeneratable — the generation attempts do not fail loudly, they just always return `None`.
///
/// The signature wants roughly 14 here: a `ClientHello` carrying even one extension needs depth 9,
/// so at 8 the zoo can only build handshake messages with empty extension lists.
pub const DEFAULT_MAX_DEPTH: u16 = 14;

/// How many consecutive failures we accept for one symbol before giving up on it.
///
/// Note this is really a budget of *evaluations* when `filter_evaluated` is set: building a term
/// is cheap and, since the children are drawn among the symbols that fit the budgets, essentially
/// always succeeds, so nearly every try reaches the evaluation. That makes the budget much more
/// expensive to exhaust than it used to be when a try could fail for free, which is why the
/// symbols flagged `no_gen` — whose evaluation never succeeds, so they exhaust it in full — are
/// now skipped whichever way [`TermZoo::generate_many`] is called.
///
/// The budget is generous because a few symbols need it: the *first* term is cheap for every
/// symbol (`fn_encrypt12`, the slowest, takes under a second), but filling a whole quota for the
/// likes of `fn_derive_psk`, `fn_fill_binder` or `fn_get_client_key_share` costs seconds. The
/// fuzzer pays that once every `fresh_zoo_after` mutations (100_000 by default), so it is
/// amortised there; the tests, which build a zoo per symbol, feel it more.
const MAX_TRIES: usize = 140_000;

/// How large, in nodes, a generated term may get.
///
/// A depth budget does not bound the size: every argument may recurse as deep as the budget
/// allows, so the size grows exponentially with the depth (unbounded, a depth of 14 produced terms
/// of up to 1198 nodes against 43 at a depth of 8). This is the bound that actually keeps terms
/// small, which lets the depth budget be about reachability alone. Well above the sizes the zoo
/// produces in practice (a 99th percentile of ~20 nodes), and below the
/// [`crate::fuzzer::utils::TermConstraints::max_term_size`] beyond which the fuzzer would not
/// select the term for mutation anyway.
const MAX_SIZE: usize = 64;

pub struct TermZoo<PB: ProtocolBehavior> {
    terms: Vec<Term<PB::ProtocolTypes>>,
}

impl<PB: ProtocolBehavior> TermZoo<PB> {
    pub fn generate<R: Rand>(
        ctx: &TraceContext<PB>,
        signature: &Signature<PB::ProtocolTypes>,
        rand: &mut R,
        how_many: usize,
        max_depth: u16,
    ) -> Self {
        Self::generate_many(ctx, signature, rand, how_many, max_depth, None, true, true)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn generate_many<R: Rand>(
        ctx: &TraceContext<PB>,
        signature: &Signature<PB::ProtocolTypes>,
        rand: &mut R,
        how_many: usize, // how many terms to generate
        max_depth: u16,  // how deep the generated terms may be
        filter: Option<&FunctionDefinition<PB::ProtocolTypes>>,
        filter_evaluated: bool,
        filter_no_gen: bool,
    ) -> Self {
        let skip = |def: &FunctionDefinition<PB::ProtocolTypes>| {
            let skip = filter_no_gen && signature.attrs_by_name.get(def.0.name).unwrap().no_gen;
            if skip {
                log::debug!("Skipping generation for [{:?}]", def.0.name);
            }
            skip
        };

        let mut acc = vec![];
        if let Some(def) = filter {
            // Also skipped when asked for one symbol at a time: a `no_gen` symbol would otherwise
            // spend the whole `MAX_TRIES` budget evaluating terms that cannot evaluate.
            if !skip(def) {
                Self::generate_for(
                    &mut acc,
                    ctx,
                    signature,
                    rand,
                    def,
                    how_many,
                    max_depth,
                    filter_evaluated,
                );
            }
        } else {
            for def in &signature.functions {
                if skip(def) {
                    continue; // Skip this function symbol
                }
                Self::generate_for(
                    &mut acc,
                    ctx,
                    signature,
                    rand,
                    def,
                    how_many,
                    max_depth,
                    filter_evaluated,
                );
            }
        }

        Self { terms: acc }
    }

    /// Appends up to `how_many` terms rooted at `def` to `acc`, giving up on that symbol after
    /// [`MAX_TRIES`] consecutive failures.
    #[allow(clippy::too_many_arguments)]
    fn generate_for<R: Rand>(
        acc: &mut Vec<Term<PB::ProtocolTypes>>,
        ctx: &TraceContext<PB>,
        signature: &Signature<PB::ProtocolTypes>,
        rand: &mut R,
        def: &FunctionDefinition<PB::ProtocolTypes>,
        how_many: usize,
        max_depth: u16,
        filter_evaluated: bool,
    ) {
        let mut counter = MAX_TRIES;
        let mut many = 0;

        while counter > 0 && many < how_many {
            counter -= 1;

            if let Some(term) = Self::generate_term(signature, def, max_depth, MAX_SIZE, rand) {
                // If filter_evaluated, we must check the term can be evaluated before including it
                if !filter_evaluated || term.evaluate(ctx).is_ok() {
                    many += 1;
                    counter = MAX_TRIES;
                    acc.push(term);
                }
            }
        }
    }

    /// Builds a random closed term rooted at the given symbol, using at most `depth` levels and
    /// `max_size` nodes.
    ///
    /// The children are drawn among the symbols that still fit both budgets, so an attempt is
    /// essentially never abandoned half-way — the exception being that the reservation made for
    /// the remaining arguments is a lower bound (see [`Signature::min_gen_size_of_type`]) which a
    /// symbol may fail to meet at the depth left, in which case this returns `None` and the caller
    /// retries.
    ///
    /// The size budget is what a depth budget alone cannot do: keeping the choice of children
    /// unrestricted otherwise, so that the deep argument chains some symbols need (a `ClientHello`
    /// for `fn_fill_binder`, say) stay as reachable as they are without any budget at all.
    fn generate_term<R: Rand>(
        signature: &Signature<PB::ProtocolTypes>,
        (shape, dynamic_fn): &FunctionDefinition<PB::ProtocolTypes>,
        depth: u16,
        max_size: usize,
        rand: &mut R,
    ) -> Option<Term<PB::ProtocolTypes>> {
        // Rejecting a doomed symbol here, before building anything, is what keeps the recursion
        // below from wasting attempts: `depth` is at least the budget this symbol needs.
        if signature.min_gen_depth(shape.name)? > depth
            || signature.min_gen_size(shape.name)? > max_size
        {
            return None;
        }

        let required_types = &shape.argument_types;

        let mut subterms = Vec::with_capacity(required_types.len());

        // A symbol with arguments needs a depth of at least 2, and the check above guarantees
        // `depth` covers it, so there is a level left for the children.
        let budget = depth - 1;
        // What we must keep aside for the arguments we have not built yet, so that a greedy first
        // argument cannot eat the whole budget.
        let mut reserved: usize = required_types
            .iter()
            .map(|typ| signature.min_gen_size_of_type(typ))
            .sum::<Option<usize>>()?;
        let mut size_left = max_size - 1; // this node

        for typ in required_types {
            reserved -= signature.min_gen_size_of_type(typ)?;
            let child_max_size = size_left - reserved;

            // Only symbols that can reach a closed leaf within both budgets are considered.
            // Restricting the choice rather than recursing and failing keeps an attempt alive
            // instead of throwing away the whole term (and with it one of the `MAX_TRIES`
            // attempts); with a depth budget of 1 it leaves exactly the constants.
            let possibility =
                signature.choose_function_within(typ, budget, child_max_size, rand)?;
            let subterm =
                Self::generate_term(signature, possibility, budget, child_max_size, rand)?;

            size_left -= subterm.size();
            subterms.push(subterm);
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
