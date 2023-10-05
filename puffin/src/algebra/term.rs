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
use crate::{algebra::{dynamic_function::TypeShape, error::FnError, Matcher}, define_signature, error::Error, protocol::ProtocolBehavior, trace::TraceContext};
use crate::fuzzer::start;
use crate::fuzzer::utils::{find_term_by_term_path_mut, find_term_by_term_path, TermPath};
use crate::trace::Trace;
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
        PB: ProtocolBehavior<Matcher = M> {
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

    /// Return all payloads contains in a term, even under opaque terms.
    /// Note that we keep the invariant that a non-symbolic term cannot have payloads in struct-subterms,
    /// see `add_payloads`.
    pub fn all_payloads(&self) -> Vec<&Payloads> {
        self.into_iter()
            .filter_map(|t| t.payloads.as_ref())
            .collect()
    }

    /// Return all payloads contains in a term, except those under opaque terms.
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

    /// Evaluate a term without replacing the payloads (returning them instead) except when reaching
    /// an opaque term with payloads as strict sub-terms. In the latter case, evaluate each of the
    /// arguments and performing the payload replacements before evaluating the opaque function.
    /// @path: current path of &self in the overall recipe.
    /// Also return the payloads to replace in this order: deeper first.
    fn eval_until_opaque<PB>(&self, path: TermPath, ctx: &TraceContext<PB>, with_payloads: bool)
                             -> Result<(Box<dyn Any>, Vec<(&Payloads, TermPath)>), Error>
        where PB: ProtocolBehavior<Matcher=M>
    {
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
                    if self.is_opaque() && ti.payloads_to_replace().len() != 0 {
                        debug!("[eval_until_opaque] Inner call of eval on term: {}\n with #{} payloads", ti, ti.payloads_to_replace().len());
                        let bi = ti.evaluate(ctx)?; // payloads in ti are consumed here!
                        let typei = func.shape().argument_types[i];
                        let di = PB::try_read_bytes(bi, typei.into())
                            .with_context(||
                                format!("Failed for typeid: {}, typeid: {:?} on term (arg: {i}:\n {}",
                                        typei, TypeId::from(typei), &self))
                            .map_err(|e| {
                                error!("[eval_until_opaque] Err: {}", e);
                                e
                            })?;
                        dynamic_args.push(di); // no need to add payloads to all_p as they were consumed
                    } else {
                        let mut pathi = path.clone();
                        pathi.push(i);
                        let (di, mut pis) = ti.eval_until_opaque(pathi, ctx, with_payloads)?;
                        dynamic_args.push(di);
                        all_p.append(&mut pis);
                    }
                }
                let dynamic_fn = &func.dynamic_fn();
                let result: Box<dyn Any> = dynamic_fn(&dynamic_args)?;
                if let Some(payload) = &self.payloads {
                    all_p.push((payload, path))
                }
                Ok((result, all_p))
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
    /// Evaluate terms into bitstrings (considering Payloads)
    fn evaluate_config<PB: ProtocolBehavior>(
        &self,
        context: &TraceContext<PB>,
        with_payloads: bool,
    ) -> Result<ConcreteMessage, Error>
        where
            PB: ProtocolBehavior<Matcher = M>,
    {
        let (m, p_s) = self.eval_until_opaque(Vec::new(), context, with_payloads)?;
        let mut e =  PB::any_get_encoding(m)?;
        if with_payloads {
            replace_payloads(&mut e, p_s, self, context)?;
        }
        Ok(e)
    }


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

/// Operate the payloads replacements in to_replace, whose term is the term-representation
/// payloads follow this order: deeper terms first
pub fn replace_payloads<M, PB>(to_replace: &mut ConcreteMessage, payloads: Vec<(&Payloads, TermPath)>, term: &TermEval<M>, ctx: &TraceContext<PB>)
                               -> Result<(), Error>
    where M: Matcher,
          PB: ProtocolBehavior<Matcher=M> {
    for (payload, path) in payloads {
        replace_payload(to_replace, payload, path, term, ctx)?;
    }
    Ok(())
}

/// Return the next strict subterm along the path and the updated path (relative to the subterm)
fn next_subterm<'a, M>(term: &'a TermEval<M>, path: &mut TermPath) -> Result<&'a TermEval<M>, Error>
    where M: Matcher {
    if path.len() < 1 {
        return Err(Error::Term(format!("Trying to access next strict subterm with an empty path for term {term}")));
    } else {
        let mut pathi = path[0..1].to_owned();
        let subterm = find_term_by_term_path(term, &mut pathi).ok_or(Error::Term(format!("Not found subterm for argument #{}", path[0])))?;
        path.remove(0);
        return Ok((subterm))
    }
}

/// Returns a unique matching starting position of to_find in term.evaluate() == eval_term, following path_refine
fn find_unique_match<M, PB>(to_find: &[u8], eval_term: &[u8], term: &TermEval<M>, path: &mut TermPath, ctx: &TraceContext<PB>)
                            -> Result<usize, Error>
    where M: Matcher,
          PB: ProtocolBehavior<Matcher=M> {
    // Initially, to_find must be in eval_term = window, in case there are multiple match, we refine the windiw
    // by following the path
    let mut start_window = 0;
    let mut window = eval_term.to_vec();
    let mut current_term = term;
    loop {
        debug!("[find_unique_match] Loop1: for start_window={start_window} and for path={path:?} and term:\n{current_term}");
        if let Some((start, is_unique)) = search_sub_vec_double(&window, to_find) {
            if is_unique {
                debug!("There is a match at position {}, length = {}. total_lenhgth = {}", start_window + start, to_find.len(), window.len());
                return Ok(start_window + start)
            } else {
                debug!{"Double match!"}
                // In that case, we need to refine the window, for this we follow the path until we find a subterm
                // that, once evaluated, we can find in the current window. When found, we update the window
                let mut found_stable = false;
                while !found_stable {
                    debug!("[find_unique_match] Loop2: for path={path:?}  and term:\n{current_term}");
                    let sub = next_subterm(current_term, path)?;
                    current_term = sub;
                    let eval_sub = sub.evaluate_symbolic(ctx)?;
                    if let Some(start_sub) = search_sub_vec(&window, &eval_sub) {
                        error!("Found sub-term at pos {start_sub}");
                        found_stable = true;
                        window = eval_sub; // evaluate synbolic so WITHOUT any payloads applied :( :(
                        start_window += start_sub;
                    } else {
                        warn!("Unable to find a subterm eval in window. To be expected if subterm is list: {}", sub.is_list());
                    }
                }
            }
        } else {
            let ft = format!("[replace_payload] Failed to find a payload.payload (len={}, path:\
            {:?}):\n{:?}\n in(len={}):\n{:?}\nfrom recipe {}\n\
            Maybe the PUT is not deterministic? Full recipe:\n{:?}", to_find.len(), path, to_find,
                             eval_term.len(), eval_term, term,
                             term);
            warn!("{}", ft);
            return Err(Error::Term(ft));
        }
    }
}

pub fn replace_payload<M, PB>(to_replace: &mut ConcreteMessage, payload: &Payloads, path: TermPath, term: &TermEval<M>, ctx: &TraceContext<PB>)
                              -> Result<(), Error>
    where M: Matcher,
          PB: ProtocolBehavior<Matcher=M> {
    // error!("--------> START replace_payload with {:?} and path {path:?} on term\n{term}", payload);
    // TODO: pour le moment je gere mal le fait que mes indices vont changer au cours du temps!!!
    // + sans doute plus efficace de partir de la target en bottom up plutot que l'inverse pour trouver un unique match
    let old_b = payload.payload_0.bytes();
    let new_b = payload.payload.bytes();
    if old_b.len() > 0 {
        // let to_replace = term.evaluate_symbolic(&ctx)?;
        let mut path_mut = path.clone();
        let start_find = find_unique_match(old_b, &to_replace, term, &mut path_mut, ctx).with_context(|| "Failed to find a unique match to be able to replace payload.")?;
        // Insert in-place new_b, replacing old_b in to_replace
        debug!("About to run let removed_elements: Vec<u8> = to_replace.splice(start_find..(start_find + old_b.len()), new_b.to_vec()).collect(); with to_replace.len()={}, start_find={start_find}, end={}", to_replace.len(), (start_find + old_b.len()));
        let removed_elements: Vec<u8> = to_replace.splice(start_find..(start_find + old_b.len()), new_b.to_vec()).collect();
        debug!("Modified bitstring is:\n{:?}.\n removed elements: {:?}", to_replace, removed_elements);
        Ok(())
    } else { // Case with an empty payload to replace, need to locate the replacement window using a relative
        if new_b.len() == 0 {
            debug!("payload_0 and payload are both empty, we do nothing...");
            return Ok(())
        } else if path.len() == 0 {
            debug!("payload_0 is empty, as well the corresponding path, we skip");
            return Ok(())
        } else {
            // We locate where we need to insert new_b:
            let last_arg = path[path.len() - 1];
            let mut offset: isize = 0;
            if last_arg > 0 {
                offset = -1;
            } else { // we will have to handle the failure case here in case this was the unique argument actually!
                offset = 1;
            }
            let mut relative_path = path[0..path.len() - 1].to_owned();
            relative_path.push((last_arg as isize + offset) as usize);
            debug!("Empty payload_0, we use relative at position {relative_path:?} relative of {path:?}");

            if let Some(brother) = find_term_by_term_path(term, &mut relative_path) {
                debug!("Relative is brother {brother}");
                let eval = term.evaluate_symbolic(&ctx)?;
                let eval_brother = brother.evaluate_symbolic(ctx)?;
                let start_find_subterm = find_unique_match(&eval_brother, &eval, term, &mut relative_path, &ctx)?;
                // operate the replacement right after this brother
                let start = if offset == -1 {
                    start_find_subterm + eval_brother.len()
                } else { start_find_subterm };
                let removed_elements: Vec<u8> = to_replace
                    .splice(start..start, new_b.to_vec())
                    .collect();
                assert_eq!(removed_elements.len(), 0);
                Ok(())
            } else {
                if offset == 1 {
                    debug!("Brother failed, we try out to use the father instead.");
                    // Maybe the term was the unique argument of its parent, so we need to take the parent as relative
                    let mut relative_path = path[0..path.len() - 1].to_owned();
                    if let Some(father) = find_term_by_term_path(term, &mut relative_path) {
                        debug!("Relative is father {father}");
                        let eval = term.evaluate_symbolic(&ctx)?;
                        let eval_father = father.evaluate_symbolic(ctx)?;
                        let start_find_subterm = find_unique_match(&eval_father, &eval, term, &mut relative_path, &ctx)?;
                        // operate the replacement right after the father
                        let start = start_find_subterm + eval_father.len();
                        let removed_elements: Vec<u8> = to_replace
                            .splice(start..start, new_b.to_vec())
                            .collect();
                        assert_eq!(removed_elements.len(), 0);
                        Ok(())
                    } else {
                        let ft = format!("[replace_payload] Failed to find a father subterm argument at path {relative_path:?} in term {term}");
                        error!("{}", ft);
                        Err(Error::Term(ft))
                    }
                } else {
                    let ft = format!("[replace_payload] Unable to find a brother of a term which is not at argument 0. Path: {path:?}, term: \n{term}.");
                    debug!("{}", ft);
                    Err(Error::Term(ft))
                }
            }
        }
    }
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

/// Return the first matching position and whether it is unique or not
pub fn search_sub_vec_double(haystack: &[u8], needle: &[u8]) -> Option<(usize,bool)> {
    if haystack.len() < needle.len() {
        return None;
    }
    for i in 0..haystack.len() - needle.len() + 1 {
        if haystack[i..i + needle.len()] == needle[..] {
            for j in (i+1)..(haystack.len() - needle.len() + 1) {
                if haystack[j..j + needle.len()] == needle[..] {
                    return Some((i, false));
                }
            }
            return Some((i, true));
        }
    }
    None
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



// FOR TESTING ONLY
pub fn evaluate_lazy_test<PB,M>(
    term: & TermEval<M>,
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
