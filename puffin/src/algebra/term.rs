//! This module provides[`Term`]sas well as iterators over them.

use std::cmp::max;
use std::fmt::{Debug, Display};
use std::hash::Hash;
use std::{any::Any, fmt, fmt::Formatter};
use std::any::TypeId;
use anyhow::Context;

use itertools::Itertools;
use libafl::inputs::{BytesInput, HasBytesVec};
use log::{debug, error, warn};
use serde::de::Unexpected::Bytes;
use serde::{Deserialize, Serialize};

use super::atoms::{Function, Variable};
use crate::{
    algebra::{dynamic_function::TypeShape, error::FnError, Matcher},
    error::Error,
    protocol::ProtocolBehavior,
    trace::TraceContext,
};
use crate::fuzzer::utils::{find_term_by_term_path_mut, find_term_by_term_path, TermPath};
use crate::variable_data::VariableData;

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
        write!(f, "{}", display_term_at_depth(self, 0))
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
/// symblic terms
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct Payloads {
    pub payload_0: BytesInput, // initially both are equal and correspond to the term evaluation
    pub payload: BytesInput,   // this one will later be subject to bit-level mutation
}
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
#[serde(bound = "M: Matcher")]
pub struct TermEval<M: Matcher> {
    pub term: Term<M>,              // initial DY term
    pub payloads: Option<Payloads>, // None until make_message mutation is used and fill this with term.evaluate()
}

impl<M: Matcher> TermEval<M> {
    pub fn height(&self) -> usize {
        match &self.term {
            Term::Application(_, subterms) => {
                if subterms.is_empty() {
                    return 1;
                } else {
                    return 1 + subterms.iter().map(|t| t.height()).max().unwrap();
                }
            }
            _ => 1,
        }
    }

    pub fn is_list(&self) -> bool {
        match &self.term {
            Term::Variable(_) => false,
            Term::Application(fd, _) => { fd.is_list() },
        }
    }

    pub fn is_opaque(&self) -> bool {
        match &self.term {
            Term::Variable(_) => false,
            Term::Application(fd, _) => { fd.is_opaque() },
        }
    }

    pub fn erase_payloads_subterms(&mut self, is_subterm: bool) {
        let is_opaque = self.is_opaque();
        match &mut self.term {
            Term::Variable(_) => {}
            Term::Application(fd, args) => {
                if is_subterm {
                    self.payloads = None;
                }
                if !is_opaque { // if opaque, we keep payloads in stric sub-terms
                    for t in args {
                        t.erase_payloads_subterms(true);
                    }
                }
            }
        }
    }

    pub fn add_payloads(&mut self, payload: Vec<u8>) {
        self.payloads = Option::from({
            Payloads {
                payload_0: BytesInput::new(payload.clone()),
                payload: BytesInput::new(payload),
            }
        });
        self.erase_payloads_subterms(false);
    }

    /// Return all payloads contains in a term, even under upaque terms.
    pub fn all_payloads(&self) -> Vec<&Payloads> {
        self.into_iter()
            .filter_map(|t| t.payloads.as_ref())
            .collect()
    }

    /// Return all payloads contains in a term, except those under opaque terms.
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

    // TODO_1: check this function and remove function all_payloads
    // TODO_2: check replace_bitstirng and overall archi
    // TODO_3: implement  PB::try_read_bytes(for TLS

    /// Evaluate a term without replacing the payloads (returning them instead) except when reaching
    /// an opaque term with payloads as strict sub-terms. In the latter case, evaluate each of the
    /// arguments and performing the payload replacements before evaluating the opaque function.
    /// path: current path of &self in the overall recipe
    /// also return the payloads to replace in this order: deeper first
    fn eval_until_opaque<PB>(&self, path: TermPath, ctx: &TraceContext<PB>)
        -> Result<(Box<dyn Any>, Vec<(&Payloads, TermPath)>), Error>
    where PB: ProtocolBehavior<Matcher = M>
    {
        // TODO: merge both if/ else as we need to treat the arguments themselves differently!
        let nb_payloads = self.all_payloads().len(); // maybe we count here payloads under
        // another opaque sub-terms, not a problem as we then treat each argument independently
        if self.is_opaque() && !( // if term is symbolic and has some payloads in strict sub-terms, we need to re-interpret arguments
                 nb_payloads == 0 ||
                (nb_payloads == 1 && !(self.is_symbolic()))) {
            // error!("[eval_until_opaque] Found opaque: {}", &self);
            match &self.term {
                Term::Variable(_) => {
                    Err(Error::Term(format!("eval_until_opaque: A variable is opaque. Should never happen!")))
                },
                Term::Application(func, args) => {
                    let mut dynamic_args: Vec<Box<dyn Any>> = Vec::new();
                    for (i, ti) in args.iter().enumerate() {
                        if ti.payloads_to_replace().len() == 0 { // no need to re-interpret argument ti
                            let mut pathi = path.clone();
                            pathi.push(i);
                            let (di, pis) = ti.eval_until_opaque(pathi, ctx)?;
                            assert_eq!(pis.len(), 0);
                            dynamic_args.push(di);
                        } else {
                            error!("[eval_until_opaque] Inner call of eval on term: {}\n with #{} payloads", ti, ti.payloads_to_replace().len());
                            let bi = ti.evaluate(ctx)?; // payloads in ti are consumed here!
                            let typei = func.shape().argument_types[i];
                            let di = PB::try_read_bytes(bi, typei.into()).with_context(|| format!("Failed for typeid: {}, typeid: {:?} on term (arg: {i}:\n {}", typei, TypeId::from(typei), &self)).map_err(|e| {
                                error!("Err: {}", e);
                                e
                            })?;
                            dynamic_args.push(di);
                        }
                    }
                    let dynamic_fn = &func.dynamic_fn();
                    let result: Box<dyn Any> = dynamic_fn(&dynamic_args)?;
                    if let Some(payload) = &self.payloads {
                        Ok((result, vec![(payload, path)]))
                    } else {
                        Ok((result, vec![])) // no payload as we consumed all inner payloads already
                    }
                }
            }
        } else { // non-opaque term
            match &self.term {
                Term::Variable(variable) => {
                    let d = ctx
                        .find_variable(variable.typ, &variable.query)
                        .map(|data| data.boxed_any())
                        .or_else(|| ctx.find_claim(variable.query.agent_name, variable.typ))
                        .ok_or_else(|| Error::Term(format!("Unable to find variable {}!", variable)))?;
                    if let Some(payload) = &self.payloads {
                        Ok((d, vec![(payload, path)]))
                    } else {
                        Ok((d, vec![]))
                    }
                },
                Term::Application(func, args) => {
                    let mut dynamic_args: Vec<Box<dyn Any>> = Vec::new();
                    let mut all_p = vec![];
                    for (i, ti) in args.iter().enumerate() {
                        let mut pathi = path.clone();
                        pathi.push(i);
                        let (di, mut pis) = ti.eval_until_opaque(pathi, ctx)?;
                        dynamic_args.push(di);
                        all_p.append(&mut pis);
                    }
                    let dynamic_fn = &func.dynamic_fn();
                    let result: Box<dyn Any> = dynamic_fn(&dynamic_args)?;
                    if let Some(payload) = &self.payloads {
                        all_p.push((payload, path)) // TODO: verify this one will be picked last when replacing (for loop pick it last)
                    } //TODO: remove .all_paylaods() function :)
                    Ok((result, all_p))
                }
            }
        }
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

fn display_term_at_depth<M: Matcher>(term: &Term<M>, depth:usize) -> String {
    let tabs = "\t".repeat(depth);
    match term {
        Term::Variable(ref v) => format!("{}{}", tabs, v),
        Term::Application(ref func, ref args) => {
            let op_str = remove_prefix(func.name());
            let return_type = remove_prefix(func.shape().return_type.name);
            if args.is_empty() {
                format!("{}{} -> {}", tabs, op_str, return_type)
            } else {
                let args_str = args
                    .iter()
                    .map(|arg| display_term_at_depth(&arg.term, depth + 1))
                    .join(",\n");
                format!(
                    "{}{}(\n{}\n{}) -> {}",
                    tabs, op_str, args_str, tabs, return_type
                )
            }
        }
    }
}

impl<M: Matcher> TermType<M> for TermEval<M> {
    fn resistant_id(&self) -> u32 {
        match &self.term {
            Term::Variable(v) => v.resistant_id,
            Term::Application(f, _) => f.resistant_id,
        }
    }

    fn size(&self) -> usize {
        if self.is_leaf() {
            SIZE_LEAF
        } else {
            match &self.term {
                Term::Variable(_) => SIZE_LEAF,
                Term::Application(_, ref subterms) => {
                    subterms.iter().map(|subterm| subterm.size()).sum::<usize>() + 1
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
            match &self.term {
                Term::Variable(v) => v.typ.name,
                Term::Application(function, _) => function.name(),
            }
        } else {
            BITSTRING_NAME
        }
    }

    fn mutate(&mut self, other: TermEval<M>) {
        *self = other;
    }



fn display_at_depth(&self, depth: usize) -> String {
        match self.payloads {
            None => {display_term_at_depth(&self.term, depth) },
            Some(_) => {
                let tabs = "\t".repeat(depth);
                format!(
                    "{}BITSTRING_OF:\n{}",
                    tabs,
                    display_term_at_depth(&self.term, depth)
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
        match &self.term {
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

    fn is_symbolic(&self) -> bool {
        match self.payloads {
            None => true,
            Some(_) => false, // Once it embeds payloads, a term is no longer symbolic
        }
    }


    /// Evaluate terms into bitstrings (considering Payloads)
    fn evaluate<PB: ProtocolBehavior>(
        &self,
        context: &TraceContext<PB>,
    ) -> Result<ConcreteMessage, Error>
    where
        PB: ProtocolBehavior<Matcher = M>,
    {
        error!("Context: term={}", &self);
        let (m, p_s) = self.eval_until_opaque(Vec::new(), context)?;
        let mut e =  PB::any_get_encoding(m)?;
        replace_payloads(&mut e, p_s, self)?;
        Ok(e)
        // let mut to_replace = self.evaluate_symbolic(context)?;
        // replace_bitstrings(&mut to_replace, self);
        // Ok(to_replace)
    }
}

/// Operate the payloads replacements in to_replace, whose term is the term-representation
/// payloads follow this order: deeper terms first
pub fn replace_payloads<M: Matcher>(to_replace: &mut ConcreteMessage, payloads: Vec<(&Payloads, TermPath)>, term: &TermEval<M>)
    -> Result<(), Error>{
    for (payload, path) in payloads {
        let old_b = payload.payload_0.bytes();
        let new_b = payload.payload.bytes();
        // TODO
        if let Some(start_find) = search_sub_vec(to_replace, old_b) {
            debug!("Found a bitstring {:?} to replace at bitstrinbg position {start_find} in bitstring\n{:?}", old_b, to_replace);
            // Insert in-place new_b, replacing old_b in to_replace
            let removed_elements: Vec<u8> = to_replace
                .splice(start_find..start_find + old_b.len(), new_b.to_vec())
                .collect();
            debug!(
                "Modified bitstring is:\n{:?}.\n removed elements: {:?}",
                to_replace, removed_elements
            );
            if let Some(start_find_2) =
                search_sub_vec(&to_replace[start_find + new_b.len()..], old_b)
            {
                warn!("Found twice the bitstring {:?} in term {} at both locations {start_find} and {start_find_2}", old_b, term);
            }
        } else {
            error!("[replace_payloads] Failed to find a payload.payload (len={}, path: {:?}):\n{:?}\n in(len={}):\n{:?}\nfrom recipe {}\n sub-recipe is\n {}.\nMaybe the PUT is not deterministic? Full recipe:\n{:?}", old_b.len(), path, old_b, to_replace.len(), to_replace, term,
                find_term_by_term_path(&term, &mut path.clone()).unwrap(),
                term);
            return Err(Error::Term(format!("[replace_payloads] Failed to find a payload.payload(len={}):\n{:?}\n in(len={}):\n{:?}\nfrom recipe {}.\nMaybe the PUT is not deterministic?", old_b.len(), old_b, to_replace.len(), to_replace, term)))
        }
    }
    Ok(())
}

pub fn search_sub_vec(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if haystack.len() < needle.len() {
        return None;
    }
    for i in 0..haystack.len() - needle.len() + 1 {
        if haystack[i..i + needle.len()] == needle[..] {
            return Some(i);
        }
    }
    None
}

// TO remove
// pub fn replace_bitstrings<M: Matcher>(to_replace: &mut ConcreteMessage, term: &TermEval<M>) {
//     for payload in term.all_payloads() {
//         let old_b = payload.payload_0.bytes();
//         let new_b = payload.payload.bytes();
//         if let Some(start_find) = search_sub_vec(to_replace, old_b) {
//             debug!("Found a bitstring {:?} to replace at bitstrinbg position {start_find} in bitstring\n{:?}", old_b, to_replace);
//             // Insert in-place new_b, replacing old_b in to_replace
//             let removed_elements: Vec<u8> = to_replace
//                 .splice(start_find..start_find + old_b.len(), new_b.to_vec())
//                 .collect();
//             debug!(
//                 "Modified bitstring is:\n{:?}.\n removed elements: {:?}",
//                 to_replace, removed_elements
//             );
//             if let Some(start_find_2) =
//                 search_sub_vec(&to_replace[start_find + new_b.len()..], old_b)
//             {
//                 warn!("Found twice the bitstring {:?} in term {} at both locations {start_find} and {start_find_2}", old_b, term);
//             }
//         } else {
//             error!("[replace_bitstrings] Failed to find a payload.payload\n{:?} in\n{:?}\nfrom recipe {}.\nMaybe the PUT is not deterministic?", old_b, to_replace, term);
//             // Need to go for V2 when this happens
//
//             // V2: locate where replacements need to be done precisely if not injective
//
//             // V3: modify evaluate as follows:
//             // do not evaluate_symbolic but go top_bottom:
//             // if symbol is "encryption" (add this bool to interface) with arg_i being payload and arg_2 being key,
//             // then evaluate symbolic both arguments, do the replacement on the bitstrings, and re-interpret
//             // with decode and downcast to do the Box<Any> eval of the encryption.
//             // if term.is_encryption() (calling itself: if FunnAPP.DynamicFunctionShape.is_encryption()
//             // then for all term argument arg of type T (from TypeShape):
//             //      args_replace.push(arg.evaluate_lazy.PB::encode<T>().replace_bitstrings(arg).PB::decode<T>())
//             // call dybnamy funcrion of funapp on args_replace
//         }
//     }
// }

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
