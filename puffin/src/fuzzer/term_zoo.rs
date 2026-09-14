//! Generates a zoo of terms form a [`Signature`]. For each function symbol in the signature
//! a closed term is generated and added to the zoo.

use libafl_bolts::rands::Rand;

use crate::algebra::atoms::Function;
use crate::algebra::dynamic_function::TypeShape;
use crate::algebra::signature::{FunctionDefinition, Signature};
use crate::algebra::{DYTerm, Term, TermType};
use crate::fuzzer::utils::Choosable;
use crate::protocol::ProtocolBehavior;
use crate::trace::TraceContext;

/// Defaults for the zoo budgets of [`ProtocolBehavior`], which every protocol may override. The
/// values are the ones tuned for tlspuffin, whose impl documents where they come from.
///
/// [`DEFAULT_MAX_DEPTH`] bounds which symbols the zoo can build a term for at all: a term must
/// reach a closed leaf within that many levels, and the wrapper chains of a generated signature
/// eat several of them. Too low, and whole families of symbols silently become ungeneratable.
///
/// [`DEFAULT_MAX_SIZE`] is what actually keeps terms small — the size grows exponentially with the
/// depth — which lets the depth budget be about reachability alone.
///
/// [`DEFAULT_MAX_TRIES`] is how many consecutive failures we accept for one symbol. With
/// `filter_evaluated` it is really a budget of *evaluations*, since building a term essentially
/// always succeeds, so it is driven by the cost of the slowest symbols to evaluate.
pub const DEFAULT_MAX_DEPTH: u16 = 14;
/// See [`DEFAULT_MAX_DEPTH`].
pub const DEFAULT_MAX_SIZE: usize = 64;
/// See [`DEFAULT_MAX_DEPTH`].
pub const DEFAULT_MAX_TRIES: usize = 140_000;

/// How many elements a generated [`DYTerm::List`] may hold.
const MAX_LIST_LENGTH: usize = 4;

pub struct TermZoo<PB: ProtocolBehavior> {
    terms: Vec<Term<PB::ProtocolTypes>>,
}

impl<PB: ProtocolBehavior> TermZoo<PB> {
    pub fn generate<R: Rand>(
        ctx: &TraceContext<PB>,
        signature: &Signature<PB::ProtocolTypes>,
        rand: &mut R,
        how_many: usize,
        max_depth: Option<u16>,
    ) -> Self {
        Self::generate_many(ctx, signature, rand, how_many, max_depth, None, true, true)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn generate_many<R: Rand>(
        ctx: &TraceContext<PB>,
        signature: &Signature<PB::ProtocolTypes>,
        rand: &mut R,
        how_many: usize,        // how many terms to generate
        max_depth: Option<u16>, // how deep the terms may be, `None` for `PB::ZOO_MAX_DEPTH`
        filter: Option<&FunctionDefinition<PB::ProtocolTypes>>,
        filter_evaluated: bool,
        filter_no_gen: bool,
    ) -> Self {
        let max_depth = max_depth.unwrap_or(PB::ZOO_MAX_DEPTH);
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
            // spend the whole `PB::ZOO_MAX_TRIES` budget evaluating terms that cannot evaluate.
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
            // A list is no function symbol, so it would otherwise never be a term of the zoo --
            // and the mutations that draw a whole term from it could never build one.
            let list_types: Vec<_> = signature
                .list_types
                .shapes()
                .map(|(list, _)| list.clone())
                .collect();
            for typ in list_types {
                Self::generate_lists_for(
                    &mut acc,
                    ctx,
                    signature,
                    rand,
                    &typ,
                    how_many,
                    max_depth,
                    filter_evaluated,
                );
            }
        }

        Self { terms: acc }
    }

    /// Appends up to `how_many` terms rooted at `def` to `acc`, giving up on that symbol after
    /// [`ProtocolBehavior::ZOO_MAX_TRIES`] consecutive failures.
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
        let mut counter = PB::ZOO_MAX_TRIES;
        let mut many = 0;

        while counter > 0 && many < how_many {
            counter -= 1;

            if let Some(term) =
                Self::generate_term(signature, def, max_depth, PB::ZOO_MAX_SIZE, rand)
            {
                // If filter_evaluated, we must check the term can be evaluated before including it
                if !filter_evaluated || term.evaluate(ctx).is_ok() {
                    many += 1;
                    counter = PB::ZOO_MAX_TRIES;
                    acc.push(term);
                }
            }
        }
    }

    /// Appends up to `how_many` list terms of type `typ` to `acc`, the list counterpart of
    /// [`Self::generate_for`].
    #[allow(clippy::too_many_arguments)]
    fn generate_lists_for<R: Rand>(
        acc: &mut Vec<Term<PB::ProtocolTypes>>,
        ctx: &TraceContext<PB>,
        signature: &Signature<PB::ProtocolTypes>,
        rand: &mut R,
        typ: &TypeShape<PB::ProtocolTypes>,
        how_many: usize,
        max_depth: u16,
        filter_evaluated: bool,
    ) {
        let mut counter = PB::ZOO_MAX_TRIES;
        let mut many = 0;

        while counter > 0 && many < how_many {
            counter -= 1;

            if let Some(term) =
                Self::generate_list(signature, typ, max_depth, PB::ZOO_MAX_SIZE, rand)
            {
                if !filter_evaluated || term.evaluate(ctx).is_ok() {
                    many += 1;
                    counter = PB::ZOO_MAX_TRIES;
                    acc.push(term);
                }
            }
        }
    }

    /// Builds a random closed term of the given type, within both budgets: either a
    /// [`DYTerm::List`] when the type is a list type, or a term rooted at a symbol returning it.
    ///
    /// A list counts as one alternative among the symbols returning the type, so it is certain
    /// for a type only a list can build (`Vec<Extension>`) and rare for one many symbols return
    /// (`Vec<u8>`, which 25 symbols produce as a bitstring and no symbol produces element-wise).
    fn generate_of_type<R: Rand>(
        signature: &Signature<PB::ProtocolTypes>,
        typ: &TypeShape<PB::ProtocolTypes>,
        depth: u16,
        max_size: usize,
        rand: &mut R,
    ) -> Option<Term<PB::ProtocolTypes>> {
        if signature.is_list_type(typ) {
            let symbols = signature
                .functions_by_typ
                .get(typ)
                .map_or(0, |functions| functions.len());
            if rand.below_or_zero(symbols + 1) == 0 {
                return Self::generate_list(signature, typ, depth, max_size, rand);
            }
        }

        match signature.choose_function_within(typ, depth, max_size, rand) {
            Some(definition) => Self::generate_term(signature, definition, depth, max_size, rand),
            // No symbol returns that type at this budget, but a list of it is always buildable.
            None if signature.is_list_type(typ) => {
                Self::generate_list(signature, typ, depth, max_size, rand)
            }
            None => None,
        }
    }

    /// Builds a random closed [`DYTerm::List`] of the given type, of up to [`MAX_LIST_LENGTH`]
    /// elements, stopping early when the budgets no longer allow one more element.
    fn generate_list<R: Rand>(
        signature: &Signature<PB::ProtocolTypes>,
        typ: &TypeShape<PB::ProtocolTypes>,
        depth: u16,
        max_size: usize,
        rand: &mut R,
    ) -> Option<Term<PB::ProtocolTypes>> {
        let element_type = signature.list_element_type(typ)?.clone();
        let budget = depth.saturating_sub(1);
        let mut size_left = max_size.checked_sub(1)?; // this node
        let how_many = rand.below_or_zero(MAX_LIST_LENGTH + 1);

        let mut elements = Vec::with_capacity(how_many);
        for _ in 0..how_many {
            let Some(element) =
                Self::generate_of_type(signature, &element_type, budget, size_left, rand)
            else {
                break;
            };
            size_left -= element.size();
            elements.push(element);
        }

        Some(Term::from(DYTerm::List(typ.clone(), elements)))
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
            // instead of throwing away the whole term (and with it one of the `PB::ZOO_MAX_TRIES`
            // attempts); with a depth budget of 1 it leaves exactly the constants.
            let subterm = Self::generate_of_type(signature, typ, budget, child_max_size, rand)?;

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
