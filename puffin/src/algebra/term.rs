//! This module provides[`Term`]sas well as iterators over them.

use std::fmt::{Debug, Display};
use std::hash::Hash;
use std::{any::Any, fmt, fmt::Formatter};

use itertools::Itertools;
use libafl::inputs::BytesInput;
use serde::de::Unexpected::Bytes;
use serde::{Deserialize, Serialize};

use super::atoms::{Function, Variable};
use crate::{
    algebra::{dynamic_function::TypeShape, error::FnError, Matcher},
    error::Error,
    protocol::ProtocolBehavior,
    trace::TraceContext,
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
        write!(f, "{}", self.display_at_depth(0))
    }
}

/// Trait for data we can treat as terms (either Term or TermEval)
pub trait TermType<M>: Display + Debug {
    fn resistant_id(&self) -> u32;
    fn size(&self) -> usize;
    fn is_leaf(&self) -> bool;
    fn get_type_shape(&self) -> &TypeShape;
    fn name(&self) -> &str;
    fn mutate(&mut self, other: Self);
    fn display_at_depth(&self, depth: usize) -> String;
    /// Semi-evaluate a term into a PB's internal representation of messages (Box<dyn Any>)
    // TODO-bitlevel: Will certainly be removed and replaced by `evaluate`
    fn evaluate_lazy<PB: ProtocolBehavior>(
        &self,
        context: &TraceContext<PB>,
    ) -> Result<Box<dyn Any>, Error>
    where
        PB: ProtocolBehavior<Matcher = M>;
    fn is_symbolic(&self) -> bool;

    /// Evaluate terms into bitstrings (considering Payloads)
    fn evaluate<PB: ProtocolBehavior>(
        &self,
        context: &TraceContext<PB>,
    ) -> Result<ConcreteMessage, Error>
    where
        PB: ProtocolBehavior<Matcher = M>;

    /// Evaluate terms into bitstrings considering all sub-terms as symbolic (even those with Payloads)
    fn evaluate_symbolic<PB: ProtocolBehavior>(
        //TODO-bitlevel: will eventually replace evaluate once we rework the PUT add_inbound interface
        &self,
        context: &TraceContext<PB>,
    ) -> Result<ConcreteMessage, Error>
        where
            PB: ProtocolBehavior<Matcher = M>,
    {
        PB::any_get_encoding(self.evaluate_lazy(&context)?)
    }
}

impl<M: Matcher> TermType<M> for Term<M> {
    fn resistant_id(&self) -> u32 {
        match self {
            Term::Variable(v) => v.resistant_id,
            Term::Application(f, _) => f.resistant_id,
        }
    }

    fn size(&self) -> usize {
        match self {
            Term::Variable(_) => SIZE_LEAF,
            Term::Application(_, ref subterms) => {
                subterms.iter().map(|subterm| subterm.size()).sum::<usize>() + 1
            }
        }
    }

    fn is_leaf(&self) -> bool {
        match self {
            Term::Variable(_) => {
                true // variable
            }
            Term::Application(_, ref subterms) => {
                subterms.is_empty() // constant
            }
        }
    }

    fn get_type_shape(&self) -> &TypeShape {
        match self {
            Term::Variable(v) => &v.typ,
            Term::Application(function, _) => &function.shape().return_type,
        }
    }

    fn name(&self) -> &str {
        match self {
            Term::Variable(v) => v.typ.name,
            Term::Application(function, _) => function.name(),
        }
    }

    fn mutate(&mut self, other: Term<M>) {
        *self = other;
    }

    fn display_at_depth(&self, depth: usize) -> String {
        let tabs = "\t".repeat(depth);
        match self {
            Term::Variable(ref v) => format!("{}{}", tabs, v),
            Term::Application(ref func, ref args) => {
                let op_str = remove_prefix(func.name());
                let return_type = remove_prefix(func.shape().return_type.name);
                if args.is_empty() {
                    format!("{}{} -> {}", tabs, op_str, return_type)
                } else {
                    let args_str = args
                        .iter()
                        .map(|arg| arg.display_at_depth(depth + 1))
                        .join(",\n");
                    format!(
                        "{}{}(\n{}\n{}) -> {}",
                        tabs, op_str, args_str, tabs, return_type
                    )
                }
            }
        }
    }

    fn evaluate_lazy<PB: ProtocolBehavior>(
        &self,
        context: &TraceContext<PB>,
    ) -> Result<Box<dyn Any>, Error>
    where
        M: Matcher,
        PB: ProtocolBehavior<Matcher = M>,
    {
        match self {
            Term::Variable(variable) => context
                .find_variable(variable.typ, &variable.query)
                .map(|data| data.boxed_any())
                .or_else(|| context.find_claim(variable.query.agent_name, variable.typ))
                .ok_or_else(|| Error::Term(format!("Unable to find variable {}!", variable))),
            Term::Application(func, args) => {
                let mut dynamic_args: Vec<Box<dyn Any>> = Vec::new();
                for term in args {
                    match term.evaluate_lazy(context) {
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

    // A Term is always symbolic
    fn is_symbolic(&self) -> bool {
        true
    }

    fn evaluate<PB: ProtocolBehavior>(
        &self,
        context: &TraceContext<PB>,
    ) -> Result<ConcreteMessage, Error>
    where
        PB: ProtocolBehavior<Matcher = M>,
    {
        self.evaluate_symbolic(context)
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

impl<M: Matcher> Subterms<M, Term<M>> for Vec<Term<M>> {
    /// Finds a subterm with the same type as `term`
    fn find_subterm_same_shape(&self, term: &Term<M>) -> Option<&Term<M>> {
        self.find_subterm(|subterm| term.get_type_shape() == subterm.get_type_shape())
    }

    /// Finds a subterm in this vector
    fn find_subterm<P: Fn(&&Term<M>) -> bool + Copy>(&self, predicate: P) -> Option<&Term<M>> {
        self.iter().find(predicate)
    }

    /// Finds all grand children/subterms which match the predicate.
    ///
    /// A grand subterm is defined as a subterm of a term in `self`.
    ///
    /// Each grand subterm is returned together with its parent and the index of the parent in `self`.
    fn filter_grand_subterms<P: Fn(&Term<M>, &Term<M>) -> bool + Copy>(
        &self,
        predicate: P,
    ) -> Vec<((usize, &Term<M>), &Term<M>)> {
        let mut found_grand_subterms = vec![];

        for (i, subterm) in self.iter().enumerate() {
            match &subterm {
                Term::Variable(_) => {}
                Term::Application(_, grand_subterms) => {
                    found_grand_subterms.extend(
                        grand_subterms
                            .iter()
                            .filter(|grand_subterm| predicate(subterm, &grand_subterm.term))
                            .map(|grand_subterm| ((i, subterm), &grand_subterm.term)),
                    );
                }
            };
        }

        found_grand_subterms
    }
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
/// symblic terms
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct Payloads {
    payload_0: BytesInput, // initially both are equal and correspond to the term evaluation
    pub(crate) payload: BytesInput, // this one will later be subject to bit-level mutation
}
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
#[serde(bound = "M: Matcher")]
pub struct TermEval<M: Matcher> {
    pub term: Term<M>,                     // initial DY term
    pub(crate) payloads: Option<Payloads>, // None until make_message mutation is used and fill this with term.evaluate()
}

impl<M: Matcher> TermEval<M> {
    pub fn add_payloads(&mut self, payload: Vec<u8>) {
        self.payloads = Option::from({
            Payloads {
                payload_0: BytesInput::new(payload.clone()),
                payload: BytesInput::new(payload),
            }
        });
    }
}

impl<M: Matcher> Display for TermEval<M> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.term, f)
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

impl<M: Matcher> TermType<M> for TermEval<M> {
    fn resistant_id(&self) -> u32 {
        self.term.resistant_id()
    }

    fn size(&self) -> usize {
        match self.payloads {
            None => self.term.size(),
            Some(_) => SIZE_LEAF,
        }
    }

    fn is_leaf(&self) -> bool {
        match self.payloads {
            None => self.is_leaf(),
            Some(_) => true,
        }
    }

    fn is_symbolic(&self) -> bool {
        match self.payloads {
            None => true,
            Some(_) => false, // Once it embeds payloads, a term is no longer symbolic
        }
    }

    fn get_type_shape(&self) -> &TypeShape {
        &self.term.get_type_shape()
    }

    fn name(&self) -> &str {
        if self.is_symbolic() {
            self.term.name()
        } else {
            BITSTRING_NAME
        }
    }

    fn mutate(&mut self, other: TermEval<M>) {
        *self = other;
    }

    fn display_at_depth(&self, depth: usize) -> String {
        match self.payloads {
            None => self.term.display_at_depth(depth),
            Some(_) => {
                let tabs = "\t".repeat(depth);
                format!(
                    "BITSTRING_OF {}{}",
                    tabs,
                    self.term.display_at_depth(depth + 4)
                )
            }
        }
    }

    fn evaluate_lazy<PB: ProtocolBehavior>(
        &self,
        context: &TraceContext<PB>,
    ) -> Result<Box<dyn Any>, Error>
    where
        M: Matcher,
        PB: ProtocolBehavior<Matcher = M>,
    {
        self.term.evaluate_lazy(context)
    }

    /// Evaluate terms into bitstrings (considering Payloads)
    fn evaluate<PB: ProtocolBehavior>(
        &self,
        context: &TraceContext<PB>,
    ) -> Result<ConcreteMessage, Error>
    where
        PB: ProtocolBehavior<Matcher = M>,
    {
        let mut to_replace = self.evaluate_symbolic(context)?;
        // V1: return self.evaluate_symbolic(context).replace-bitstrings(self)
        // if to_replace.len() > 101 {to_replace[80] = 1 as u8;}
            // TODO-bitlevel: implement the replacement

        // For all sub-terms having Payload in self, replace found Payload.paylaod_0 by Payload.payload
        // Here we need to replace in this result all the payload_0 by payload for all terms
        // having Payload {payload_0, payload}, possibly by refining the location where we need
        // to replace

        // V2: locate where replacements need to be done precisely if not injective

        // V3: do not evaluate_symbolic but go top_bottom:
        // if symbol is "encryption" (add this bool to interface) with arg_i being payload and arg_2 being key,
        // then evaluate symbolic both arguments, do the replacement on the bitstrings, and re-interpret
        // with decode and downcast to do the Box<Any> eval of the encryption.
        // if term.is_encryption() (calling itself: if FunnAPP.DynamicFunctionShape.is_encryption()
        // then for all term argument arg of type T (from TypeShape):
        //      args_replace.push(arg.evaluate_lazy.PB::encode<T>().replace_bitstrings(arg).PB::decode<T>())
        // call dybnamy funcrion of funapp on args_replace
        Ok(to_replace)
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
