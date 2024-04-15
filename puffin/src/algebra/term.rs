//! This module provides[`Term`]sas well as iterators over them.

use std::{
    any::{Any, TypeId},
    cmp::{max, min},
    fmt,
    fmt::{format, Debug, Display, Formatter},
    hash::Hash,
};

use anyhow::Context;
use itertools::Itertools;
use libafl::inputs::{BytesInput, HasBytesVec};
use log::{debug, error, trace, warn};
use serde::{de::Unexpected::Bytes, Deserialize, Serialize};

use super::atoms::{Function, Variable};
use crate::{
    algebra::{
        bitstrings::{replace_payloads, EvalTree, Payloads},
        dynamic_function::TypeShape,
        error::FnError,
        Matcher,
    },
    define_signature,
    error::Error,
    fuzzer::{
        start,
        utils::{find_term_by_term_path, find_term_by_term_path_mut, TermPath},
    },
    protocol::ProtocolBehavior,
    trace::{Trace, TraceContext},
    variable_data::VariableData,
};

const SIZE_LEAF: usize = 1;
const BITSTRING_NAME: &'static str = "BITSTRING_";

pub type ConcreteMessage = Vec<u8>;

/// A first-order term: either a [`Variable`] or an application of an [`Function`].
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
#[serde(bound = "M: Matcher")]
pub enum Term<M: Matcher> {
    /// A concrete but unspecified `Term` (e.g. `x`, `y`).
    /// See [`Variable`] for more information.
    ///
    Variable(Variable<M>),
    /// An [`Function`] applied to zero or more `Term`s (e.g. (`f(x, y)`, `g()`).
    ///
    /// A `Term` that is an application of an [`Function`] with arity 0 applied to 0 `Term`s can be considered a constant.
    ///
    Application(Function, Vec<TermEval<M>>),
}

impl<M: Matcher> fmt::Display for Term<M> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", display_term_at_depth(self, 0, false))
    }
}

/// Trait for data we can treat as terms (either Term or TermEval)
pub trait TermType<M>: Display + Debug + Clone {
    fn resistant_id(&self) -> u32;
    fn size(&self) -> usize;
    fn is_leaf(&self) -> bool;
    fn get_type_shape(&self) -> &TypeShape;
    fn name(&self) -> &str;
    fn mutate(&mut self, other: Self);
    fn display_at_depth(&self, depth: usize) -> String;
    fn is_symbolic(&self) -> bool;
    fn make_symbolic(&mut self); // remove all payloads

    /// Evaluate terms into bitstrings (considering Payloads or not depending on with_payloads)
    fn evaluate_config<PB: ProtocolBehavior>(
        &self,
        context: &TraceContext<PB>,
        with_payloads: bool,
    ) -> Result<ConcreteMessage, Error>
    where
        PB: ProtocolBehavior<Matcher = M>;

    /// Evaluate terms into bitstrings (considering Payloads)
    fn evaluate<PB: ProtocolBehavior>(
        &self,
        context: &TraceContext<PB>,
    ) -> Result<ConcreteMessage, Error>
    where
        PB: ProtocolBehavior<Matcher = M>,
    {
        self.evaluate_config(context, true)
    }

    /// Evaluate terms into bitstrings considering all sub-terms as symbolic (even those with Payloads)
    fn evaluate_symbolic<PB: ProtocolBehavior>(
        &self,
        ctx: &TraceContext<PB>,
    ) -> Result<ConcreteMessage, Error>
    where
        PB: ProtocolBehavior<Matcher = M>,
    {
        self.evaluate_config(ctx, false)
    }
}

fn append<'a, M: Matcher>(term: &'a Term<M>, v: &mut Vec<&'a Term<M>>) {
    match *term {
        Term::Variable(_) => {}
        Term::Application(_, ref subterms) => {
            for subterm in subterms {
                append(&subterm.term, v);
            }
        }
    }

    v.push(term);
}

/// Having the same mutator for &'a mut Term is not possible in Rust:
/// * https://stackoverflow.com/questions/49057270/is-there-a-way-to-iterate-over-a-mutable-tree-to-get-a-random-node
/// * https://sachanganesh.com/programming/graph-tree-traversals-in-rust/
impl<'a, M: Matcher> IntoIterator for &'a Term<M> {
    type Item = &'a Term<M>;
    type IntoIter = std::vec::IntoIter<&'a Term<M>>;

    fn into_iter(self) -> Self::IntoIter {
        let mut result = vec![];
        append::<M>(self, &mut result);
        result.into_iter()
    }
}

pub trait Subterms<M: Matcher, T>
where
    T: TermType<M>,
{
    fn find_subterm_same_shape(&self, term: &T) -> Option<&T>;

    fn find_subterm<P: Fn(&&T) -> bool + Copy>(&self, filter: P) -> Option<&T>;

    fn filter_grand_subterms<P: Fn(&T, &T) -> bool + Copy>(
        &self,
        predicate: P,
    ) -> Vec<((usize, &T), &T)>;
}

/// `tlspuffin::term::op_impl::op_protocol_version` -> `op_protocol_version`
/// `alloc::Vec<rustls::msgs::handshake::ServerExtension>` -> `Vec<rustls::msgs::handshake::ServerExtension>`
pub(crate) fn remove_prefix(str: &str) -> String {
    let split: Option<(&str, &str)> = str.split('<').collect_tuple();

    if let Some((non_generic, generic)) = split {
        let generic = &generic[0..generic.len() - 1];

        if let Some(pos) = non_generic.rfind("::") {
            non_generic[pos + 2..].to_string() + "<" + &remove_prefix(generic) + ">"
        } else {
            non_generic.to_string() + "<" + &remove_prefix(generic) + ">"
        }
    } else if let Some(pos) = str.rfind("::") {
        str[pos + 2..].to_string()
    } else {
        str.to_string()
    }
}

pub(crate) fn remove_fn_prefix(str: &str) -> String {
    str.replace("fn_", "")
}

/// `TermEval`s are `Term`s equipped with optional `Payloads` when they no longer are treated as
/// symbolic terms.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
#[serde(bound = "M: Matcher")]
pub struct TermEval<M: Matcher> {
    pub term: Term<M>,              // initial DY term
    pub payloads: Option<Payloads>, // None until make_message mutation is used and fill this with term.evaluate()
}

impl<M: Matcher> TermEval<M> {
    /// Height of term, considering non-symbolic terms as atoms
    pub fn height(&self) -> usize {
        match &self.term {
            Term::Application(_, subterms) => {
                if subterms.is_empty() || !self.is_symbolic() {
                    return 1;
                } else {
                    return 1 + subterms.iter().map(|t| t.height()).max().unwrap();
                }
            }
            _ => 1,
        }
    }

    /// When the term starts with a list function symbol
    pub fn is_list(&self) -> bool {
        match &self.term {
            Term::Variable(_) => false,
            Term::Application(fd, _) => fd.is_list(),
        }
    }

    /// When the term starts with an opaque function symbol (like encryption)
    pub fn is_opaque(&self) -> bool {
        match &self.term {
            Term::Variable(_) => false,
            Term::Application(fd, _) => fd.is_opaque(),
        }
    }

    /// Erase all payloads in a term, including those under opaque function symbol
    pub fn erase_payloads_subterms(&mut self, is_subterm: bool) {
        if is_subterm {
            self.payloads = None;
        }
        match &mut self.term {
            Term::Variable(_) => {}
            Term::Application(_, args) => {
                // Not true anymore: if opaque, we keep payloads in strict sub-terms
                for t in args {
                    t.erase_payloads_subterms(true);
                }
            }
        }
    }

    /// Add a payload at the root position, erase payloads in strict sub-terms not under opaque
    pub fn add_payload(&mut self, payload: Vec<u8>) {
        self.payloads = Option::from({
            Payloads {
                payload_0: BytesInput::new(payload.clone()),
                payload: BytesInput::new(payload),
            }
        });
        self.erase_payloads_subterms(false);
    }

    /// Make and Add a payload at the root position, erase payloads in strict sub-terms not under opaque
    pub fn make_payload<PB>(&mut self, ctx: &TraceContext<PB>) -> Result<(), Error>
    where
        PB: ProtocolBehavior<Matcher = M>,
    {
        let eval = self.evaluate_symbolic(&ctx)?;
        self.add_payload(eval.into());
        Ok(())
    }

    /// Return all payloads contains in a term, even under opaque terms.
    /// Note that we keep the invariant that a non-symbolic term cannot have payloads in struct-subterms,
    /// see `add_payload/make_payload`.
    pub fn all_payloads(&self) -> Vec<&Payloads> {
        self.into_iter()
            .filter_map(|t| t.payloads.as_ref())
            .collect()
    }

    /// Return all payloads contained in a term, except those under opaque terms.
    /// The deeper the first in the returned vector.
    pub fn payloads_to_replace(&self) -> Vec<&Payloads> {
        pub fn rec<'a, M: Matcher>(term: &'a TermEval<M>, acc: &mut Vec<&'a Payloads>) {
            match &term.term {
                Term::Variable(_) => {}
                Term::Application(_, args) => {
                    if !term.is_opaque() {
                        for t in args {
                            rec(t, acc)
                        }
                    }
                }
            }
            if let Some(payload) = &term.payloads {
                acc.push(payload);
            }
        }
        let mut acc = vec![];
        rec(self, &mut acc);
        acc
    }

    /// Return whether there is at least one payload, except those under opaque terms.
    pub fn has_payload_to_replace(&self) -> bool {
        has_payload_to_replace_rec(self, true)
    }

    /// Return whether there is at least one payload, except those under opaque terms and at the root..
    pub fn has_payload_to_replace_wo_root(&self) -> bool {
        has_payload_to_replace_rec(self, false)
    }
}

pub fn has_payload_to_replace_rec<'a, M: Matcher>(
    term: &'a TermEval<M>,
    include_root: bool,
) -> bool {
    if let (Some(_), true) = (&term.payloads, include_root) {
        return true;
    } else {
        match &term.term {
            Term::Variable(_) => {}
            Term::Application(_, args) => {
                if !term.is_opaque() {
                    for t in args {
                        if has_payload_to_replace_rec(t, true) {
                            return true;
                        }
                    }
                }
            }
        }
    }
    return false;
}

impl<M: Matcher> Display for TermEval<M> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.display_at_depth(0))
    }
}
impl<M: Matcher> From<Term<M>> for TermEval<M> {
    fn from(term: Term<M>) -> Self {
        TermEval {
            term,
            payloads: None,
        }
    }
}

impl<M: Matcher> From<TermEval<M>> for Term<M> {
    fn from(term: TermEval<M>) -> Self {
        term.term
    }
}

fn display_term_at_depth<M: Matcher>(term: &Term<M>, depth: usize, is_bitstring: bool) -> String {
    let tabs = "\t".repeat(depth);
    match term {
        Term::Variable(ref v) => {
            let is_bitstring = if is_bitstring { "BS//" } else { "" };
            format!("{}{}{}", tabs, is_bitstring, v)
        }
        Term::Application(ref func, ref args) => {
            let op_str = remove_prefix(func.name());
            let return_type = remove_prefix(func.shape().return_type.name);
            let is_bitstring = if is_bitstring { "BS//" } else { "" };
            if args.is_empty() {
                format!("{}{}{} -> {}", tabs, is_bitstring, op_str, return_type)
            } else {
                let args_str = args
                    .iter()
                    .map(|arg| display_term_at_depth(&arg.term, depth + 1, !arg.is_symbolic()))
                    .join(",\n");
                format!(
                    "{}{}{}(\n{}\n{}) -> {}",
                    tabs, is_bitstring, op_str, args_str, tabs, return_type
                )
            }
        }
    }
}

fn append_eval<'a, M: Matcher>(term_eval: &'a TermEval<M>, v: &mut Vec<&'a TermEval<M>>) {
    match term_eval.term {
        Term::Variable(_) => {}
        Term::Application(_, ref subterms) => {
            for subterm in subterms {
                append_eval(subterm, v);
            }
        }
    }

    v.push(term_eval);
}

impl<M: Matcher> TermType<M> for TermEval<M> {
    /// Evaluate terms into bitstrings (considering Payloads)
    fn evaluate_config<PB: ProtocolBehavior>(
        &self,
        context: &TraceContext<PB>,
        with_payloads: bool,
    ) -> Result<ConcreteMessage, Error>
    where
        PB: ProtocolBehavior<Matcher = M>,
    {
        debug!("[evaluate_config] About to evaluate {}\n===================================================================", &self);
        let mut eval_tree = EvalTree::init();
        let path = TermPath::new();
        let (m, all_payloads) = self.eval_until_opaque(
            &mut eval_tree,
            path,
            context,
            with_payloads,
            false,
            false,
            self.get_type_shape(),
        )?;
        // if let Some(mut e) = eval {
        if with_payloads && !all_payloads.is_empty() {
            debug!("[evaluate_config] About to replace for a term {}\n payloads with contexts {:?}\n-------------------------------------------------------------------",
                    self, &all_payloads);
            return (Ok(replace_payloads(
                self,
                &mut eval_tree,
                all_payloads,
                context,
            )?));
        } else {
            if let Ok(eval) = PB::any_get_encoding(&m) {
                trace!("        / We successfully evaluated the root term into: {eval:?}");
                return Ok(eval);
            } else {
                error!(
                    "Error with any_get_encoding: {:?}",
                    PB::any_get_encoding(&m)
                );
                return (Err(Error::Term(format!("[evaluate_config] Could not any_get_encode a term at root position. Current term: {}", &self.term)))
                        .map_err(|e| {
                            error!("[evaluate_config] Err: {}", e);
                            e
                        }));
            }
        }
    }

    fn resistant_id(&self) -> u32 {
        match &self.term {
            Term::Variable(v) => v.resistant_id,
            Term::Application(f, _) => f.resistant_id,
        }
    }

    /// size of a term, considering non-symbolic terms as atoms
    fn size(&self) -> usize {
        if self.is_leaf() {
            SIZE_LEAF
        } else {
            match &self.term {
                Term::Variable(_) => SIZE_LEAF,
                Term::Application(_, ref subterms) => {
                    if !self.is_symbolic() {
                        SIZE_LEAF
                    } else {
                        subterms.iter().map(|subterm| subterm.size()).sum::<usize>() + 1
                    }
                }
            }
        }
    }

    fn is_leaf(&self) -> bool {
        if self.is_symbolic() {
            match &self.term {
                Term::Variable(_) => {
                    true // variable
                }
                Term::Application(_, ref subterms) => {
                    subterms.is_empty() // constant
                }
            }
        } else {
            true
        }
    }

    fn get_type_shape(&self) -> &TypeShape {
        match &self.term {
            Term::Variable(v) => &v.typ,
            Term::Application(function, _) => &function.shape().return_type,
        }
    }

    fn name(&self) -> &str {
        if self.is_symbolic() {
            // we do not display this information for now
            match &self.term {
                Term::Variable(v) => v.typ.name,
                Term::Application(function, _) => function.name(),
            }
        } else {
            // let str =
            //     match &self.term {
            //     Term::Variable(v) => v.typ.name,
            //     Term::Application(function, _) => function.name(),
            // };
            // &format!("{}//{}", BITSTRING_NAME, str)
            BITSTRING_NAME
        }
    }

    fn mutate(&mut self, other: TermEval<M>) {
        *self = other;
    }

    fn display_at_depth(&self, depth: usize) -> String {
        display_term_at_depth(&self.term, depth, !self.is_symbolic())
    }

    fn is_symbolic(&self) -> bool {
        match self.payloads {
            None => true,
            Some(_) => false, // Once it embeds payloads, a term is no longer symbolic
        }
    }

    fn make_symbolic(&mut self) {
        self.erase_payloads_subterms(true); // true as we also want to remove payloads at top-level
    }
}

/// Having the same mutator for &'a mut Term is not possible in Rust:
/// * https://stackoverflow.com/questions/49057270/is-there-a-way-to-iterate-over-a-mutable-tree-to-get-a-random-node
/// * https://sachanganesh.com/programming/graph-tree-traversals-in-rust/
impl<'a, M: Matcher> IntoIterator for &'a TermEval<M> {
    type Item = &'a TermEval<M>;
    type IntoIter = std::vec::IntoIter<&'a TermEval<M>>;

    fn into_iter(self) -> Self::IntoIter {
        let mut result = vec![];
        append_eval::<M>(self, &mut result);
        result.into_iter()
    }
}

impl<M: Matcher> Subterms<M, TermEval<M>> for Vec<TermEval<M>> {
    /// Finds a subterm with the same type as `term`
    fn find_subterm_same_shape(&self, term: &TermEval<M>) -> Option<&TermEval<M>> {
        self.find_subterm(|subterm| term.get_type_shape() == subterm.get_type_shape())
    }

    /// Finds a subterm in this vector
    fn find_subterm<P: Fn(&&TermEval<M>) -> bool + Copy>(
        &self,
        predicate: P,
    ) -> Option<&TermEval<M>> {
        self.iter().find(predicate)
    }

    /// Finds all grand children/subterms which match the predicate.
    ///
    /// A grand subterm is defined as a subterm of a term in `self`.
    ///
    /// Each grand subterm is returned together with its parent and the index of the parent in `self`.
    fn filter_grand_subterms<P: Fn(&TermEval<M>, &TermEval<M>) -> bool + Copy>(
        &self,
        predicate: P,
    ) -> Vec<((usize, &TermEval<M>), &TermEval<M>)> {
        let mut found_grand_subterms = vec![];

        for (i, subterm) in self.iter().enumerate() {
            match &subterm.term {
                Term::Variable(_) => {}
                Term::Application(_, grand_subterms) => {
                    if subterm.is_symbolic() {
                        found_grand_subterms.extend(
                            grand_subterms
                                .iter()
                                .filter(|grand_subterm| predicate(subterm, grand_subterm))
                                .map(|grand_subterm| ((i, subterm), grand_subterm)),
                        );
                    }
                }
            };
        }

        found_grand_subterms
    }
}

// FOR TESTING ONLY
pub fn evaluate_lazy_test<PB, M>(
    term: &TermEval<M>,
    context: &TraceContext<PB>,
) -> Result<Box<dyn Any>, Error>
where
    M: Matcher,
    PB: ProtocolBehavior<Matcher = M>,
{
    match &term.term {
        Term::Variable(variable) => context
            .find_variable(variable.typ, &variable.query)
            .map(|data| data.boxed_any())
            .or_else(|| context.find_claim(variable.query.agent_name, variable.typ))
            .ok_or_else(|| Error::Term(format!("Unable to find variable {}!", variable))),
        Term::Application(func, args) => {
            let mut dynamic_args: Vec<Box<dyn Any>> = Vec::new();
            for term in args {
                match evaluate_lazy_test(term, context) {
                    Ok(data) => {
                        dynamic_args.push(data);
                    }
                    Err(e) => {
                        return Err(e);
                    }
                }
            }
            let dynamic_fn = &func.dynamic_fn();
            let result: Result<Box<dyn Any>, FnError> = dynamic_fn(&dynamic_args);
            result.map_err(Error::Fn)
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::algebra::remove_prefix;

    #[test]
    fn test_normal() {
        assert_eq!(remove_prefix("test::test::Test"), "Test");
    }

    #[test]
    fn test_generic() {
        assert_eq!(remove_prefix("test::test::Test<Asdf>"), "Test<Asdf>");
    }

    #[test]
    fn test_generic_recursive() {
        assert_eq!(remove_prefix("test::test::Test<asdf::Asdf>"), "Test<Asdf>");
    }
}
