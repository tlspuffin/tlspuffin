//! This module provides[`Term`]sas well as iterators over them.

use std::cmp::max;
use std::fmt::{Debug, Display};
use std::hash::Hash;
use std::{any::Any, fmt, fmt::Formatter};
use std::any::TypeId;
use anyhow::Context;

use itertools::Itertools;
use libafl::inputs::{BytesInput, HasBytesVec};
use log::{debug, error, trace, warn};
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

    pub fn add_payload(&mut self, payload: Vec<u8>) {
        self.payloads = Option::from({
            Payloads {
                payload_0: BytesInput::new(payload.clone()),
                payload: BytesInput::new(payload),
            }
        });
        self.erase_payloads_subterms(false);
    }

    pub fn make_payload<PB>(&mut self, ctx: &TraceContext<PB>) ->
        Result<(), Error>
    where PB: ProtocolBehavior<Matcher = M> {
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
    /// Also return the payloads to replace in this order: deeper first. To each payload, we associate
    /// the path from which it originates and the offset (in # bytes) where to find the payload in the
    /// current term and the window (ConcreteMessage). The offset is always relative to the current window
    /// (ConcreteMessage).
    /// Invariant: ConcreteMessage[offset..offset+payload.payload_0.len()] == payload.payload_0
    /// Therefore, the position/offset (usize) is the position where to replace the payload in the current ConcreteMessage.
    fn eval_until_opaque<PB>(&self, path: TermPath, ctx: &TraceContext<PB>, with_payloads: bool, is_in_list: bool)
                             -> Result<(Box<dyn Any>, Vec<(&Payloads, TermPath, usize, ConcreteMessage)>), Error>
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
                    trace!("[eval_until_opaque] Add a payload for a leaf at path: {path:?}, payload is: {payload:?} and eval is: {:?}", PB::any_get_encoding(&d));
                    Ok((d, vec![(payload, path, 0, payload.payload_0.bytes().to_vec())])) // no offset for leaf
                } else {
                    trace!("[eval_until_opaque] Did not add a payload for a leaf at path: {path:?} and eval is: {:?}", PB::any_get_encoding(&d));
                    Ok((d, vec![]))
                }
            },
            Term::Application(func, args) => {
                debug!("eval_until_opaque : Application from path={path:?}");
                let mut dynamic_args: Vec<Box<dyn Any>> = Vec::new();
                let mut all_p = vec![];
                for (i, ti) in args.iter().enumerate() {
                    debug!("Treating argument # {i} from path {path:?}...");
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
                        let (di, mut pis) = ti.eval_until_opaque(pathi, ctx, with_payloads, self.is_list())?;
                        dynamic_args.push(di);
                        for p in pis {
                            all_p.push((p, i));
                        }
                    }
                }
                let dynamic_fn = &func.dynamic_fn();
                let result: Box<dyn Any> = dynamic_fn(&dynamic_args)?;
                let mut return_p = vec![]; // processed payloads to return

                // We now update the payload position on the larger term
                // (if we manage to evaluate the current term)
                if all_p.len() > 0 {
                    if let Ok(eval) = PB::any_get_encoding(&result) {
                        for (i, ((p, path_p, pos, eval_sub), num_arg)) in all_p.into_iter().enumerate() {
                            trace!("Updating payload #{i} from arg #{num_arg:?}: {p:?}, path_p={path_p:?}, pos={pos}, eval_sub={eval_sub:?}");
                            if !eval_sub.is_empty() {
                                // CURRENT WINDOW (eval_sub) is not empty --> we look for this bitstring in eval and refine the window
                                if is_in_list {
                                    // then we skip and wait until being not in the middle of a list
                                    trace!("[eval_until_opaque] Skipping searching in eval_sub since it is in a middle of a list! current path={path:?}, payload path={path_p:?}. Eval: {eval:?}, eval_sub: {eval_sub:?}");
                                    return_p.push((p, path_p, pos, eval_sub));
                                } else {
                                    // We look for the window in the current term evaluation and refine the window
                                    if let Some((start, is_unique)) = search_sub_vec_double(&eval, &eval_sub) {
                                        if is_unique {
                                            // DONE
                                            trace!("[eval_until_opaque] Found eval_sub for current path = {path:?} and payload path={path_p:?}. Update pos={} to {} for payload={:?}.\n -- We found {eval_sub:?} in {eval:?} at pos={start}", pos, pos+start, p);
                                            return_p.push((p, path_p, pos + start, eval.clone()));
                                            // todo: instead: use a global eval as a global argument of the recurisve call
                                            //  associate to payload item is just an option ConcreteMessage in case it has "lagged"
                                        } else { // We shall refine the window, using left or right brother
                                            if num_arg > 0 || num_arg < dynamic_args.len() - 1 { // there is a brother node we can compare with
                                                let index = if num_arg > 0 { num_arg - 1 } else { num_arg + 1 };
                                                // index of the arg to compare with
                                                trace!("[eval_until_opaque] [Multiple matches] Compared with brother at index {index}.");
                                                if let Ok(eval_index) = PB::any_get_encoding(&dynamic_args[index]) {
                                                    if let Some((start_brother, is_unique_brother)) = search_sub_vec_double(&eval, &eval_index) {
                                                        let window = if num_arg > 0 { &eval[start_brother + eval_index.len()..] } else { &eval[..start_brother] };
                                                        if let Some((start_retry, is_unique_retry)) = search_sub_vec_double(window, &eval_sub) {
                                                            let new_pos = if num_arg > 0 {pos + start_retry + start_brother + eval_index.len()} else {pos + start_retry};
                                                            if is_unique {
                                                                trace!("[eval_until_opaque] [Retried successful] Found eval_sub for current path = {path:?} and payload path={path_p:?}. Update pos={} to {} for payload={:?}.\n -- We found {eval_sub:?} in {eval:?} at pos={start}", pos, pos+start, p);
                                                                return_p.push((p, path_p, new_pos, eval.clone()));
                                                            } else {
                                                                debug!("[eval_until_opaque] Still not unique. WAS UNABLE TO DISAMBIGUATE RETRIED. FALL BACK TO the last non-unique solution\nFound eval_sub for current path = {path:?} and payload path={path_p:?}. Update pos={} to {} for payload={:?}.\n -- We found {eval_sub:?} in {eval:?} at pos={start}", pos, pos+start, p);
                                                                return_p.push((p, path_p, new_pos, eval.clone()));
                                                                // Could be improved with choosing another brother but I don't think it worths it
                                                            }
                                                        } else {
                                                            warn!("[eval_until_opaque] Failed to find in refined window. WAS UNABLE TO DISAMBIGUATE. FALL BACK TO first solution\nFound eval_sub for current path = {path:?} and payload path={path_p:?}. Update pos={} to {} for payload={:?}.\n -- We found {eval_sub:?} in {eval:?} at pos={start}", pos, pos+start, p);
                                                            return_p.push((p, path_p, pos + start, eval.clone()));
                                                        }
                                                    } else {
                                                        warn!("[eval_until_opaque] Failed to find brother. WAS UNABLE TO DISAMBIGUATE. FALL BACK TO first solution\nFound eval_sub for current path = {path:?} and payload path={path_p:?}. Update pos={} to {} for payload={:?}.\n -- We found {eval_sub:?} in {eval:?} at pos={start}", pos, pos+start, p);
                                                        return_p.push((p, path_p, pos + start, eval.clone()));
                                                    }
                                                } else {
                                                    warn!("[eval_until_opaque] Failed to evaluate brother. WAS UNABLE TO DISAMBIGUATE. FALL BACK TO first solution\nFound eval_sub for current path = {path:?} and payload path={path_p:?}. Update pos={} to {} for payload={:?}.\n -- We found {eval_sub:?} in {eval:?} at pos={start}", pos, pos+start, p);
                                                    return_p.push((p, path_p, pos + start, eval.clone()));
                                                }
                                            } else {
                                                debug!("[eval_until_opaque] Failed to locate brother. WAS UNABLE TO DISAMBIGUATE. FALL BACK TO first solution\nFound eval_sub for current path = {path:?} and payload path={path_p:?}. Update pos={} to {} for payload={:?}.\n -- We found {eval_sub:?} in {eval:?} at pos={start}", pos, pos+start, p);
                                                return_p.push((p, path_p, pos + start, eval.clone()));
                                            }
                                        }
                                    } else {
                                            warn!("[evaluate] Could not find eval_sub in eval for current path = {path:?} and payload path={path_p:?}. Eval_sub: {eval_sub:?} // eval: {eval:?} (for payload {:?} in upper-term\n {})", p.payload_0, &self.term);
                                            return_p.push((p, path_p, pos, eval_sub));
                                        }
                                    }
                                } else {
                                    // The current window/payload is empty --> we compute a window using left or rogth brother or the parent
                                    if num_arg > 0 || num_arg < dynamic_args.len() - 1 { // there is a brother node we can compare with
                                        let index = if num_arg > 0 { num_arg - 1 } else { num_arg + 1 };
                                        // index of the arg to compare with
                                        trace!("[eval_until_opaque] [Empty payload] Compared with brother at index {index}.");
                                        if let Ok(eval_index) = PB::any_get_encoding(&dynamic_args[index]) {
                                            let pos = if num_arg > 0 { eval_index.len() } else { 0 };
                                            trace!("Updated pos to be {pos} in brother eval: {eval_index:?}");
                                            return_p.push((p, path_p, pos, eval_index));
                                        } else {
                                            error!("[evaluate] [Empty payload] Could not evaluate argument before: num_arg={num_arg}, current path = {path:?} and payload path={path_p:?}.  DROP THIS PAYLOAD")
                                        }
                                    } else {
                                        // there is only one argument: we compare with the father
                                        trace!("[eval_until_opaque] [Empty payload] Compared with father.");
                                        let pos = eval.len();
                                        return_p.push((p, path_p, pos, eval.clone()));
                                    }
                                }
                            }
                        } else {
                            warn!("[evaluate] Could not any_get_encode a sub-term to update payload positions.\
                        If this is the last recursive call, the positions might be wrong, otherwise, we will tru again on larger terms.\
                        Current term: {}", &self.term)
                        }
                    }
                    trace!("End Application path={path:?} with eval={:?}", PB::any_get_encoding(&result));
                    // Processing the potential payload at root position
                    if let Some(payload) = &self.payloads {
                        trace!("[eval_until_opaque] Add a paylaod for an application at path: {path:?}, payload is: {payload:?} and eval is: {:?}", PB::any_get_encoding(&result));
                        return_p.push((payload, path, 0, payload.payload_0.bytes().to_vec()))  // no offset for the current payload
                    }
                    Ok((result, return_p))
                }
            }
        }
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
                Term::Variable(ref v) => format!("{}{}", tabs, v),
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
        debug!("[evaluate_config] About to evaluate {}", &self);
        let (m, p_s) = self.eval_until_opaque(Vec::new(), context, with_payloads, false)?;
        let mut e =  PB::any_get_encoding(&m)?;
        if with_payloads {
            debug!("[evaluate_config] About to replace payloads {:?} in {e:?}", &p_s);
            replace_payloads(&mut e, p_s).with_context(|| format!("failing term: {self}"))?;
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
        if true || self.is_symbolic() { // we do not display this information for now
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

/// Operate the payloads replacements in to_replace, whose term is the term-representation
/// payloads follow this order: deeper terms first
pub fn replace_payloads(to_replace: &mut ConcreteMessage, payloads: Vec<(&Payloads, TermPath, usize, ConcreteMessage)>,)
                               -> Result<(), Error>
{
    for (payload, path, pos, eval) in &payloads {
        let pos = *pos;
        trace!("--------> START replace_payload with {:?} and pos {pos} on message of length = {}", payload, to_replace.len());
        let old_b_len = payload.payload_0.bytes().len();
        let new_b = payload.payload.bytes();
        if pos+old_b_len <= to_replace.len() { // TODO: check if it is < or <=
            debug!("[replace_payload] About to splice for indices to_replace.len={}, range={pos}..{}. to_replace[pos..pos+old_b_len]={:?}.",
                to_replace.len(), pos+old_b_len, &to_replace[pos..pos+old_b_len]);
            // TO REMOVE IN PRODUCTION ! as it is costly!
            if !(to_replace[pos..pos+old_b_len].to_vec() ==  payload.payload_0.bytes()) {
                let ft = format!("[replace_payload] Payloads returned by eval_until_opaque were inconsistent!\n
                 to_replace[pos..pos+old_b_len].to_vec() = !to_replace[{pos}..{}].to_vec() = {:?}\n\
                 payload.payload_0.bytes() = {:?}\n\
                 to_replace={to_replace:?}",
                                 pos+old_b_len, to_replace[pos..pos+old_b_len].to_vec(), payload.payload_0.bytes());
                error!("{}", ft);
                return Err(Error::Term(ft))
            }
            let to_remove: Vec<u8> = to_replace.splice(pos..pos + old_b_len, new_b.to_vec()).collect();
            trace!("[replace_payload] Removed elements (len={}): {:?}", to_remove.len(), &to_remove);
        } else {
            let ft = format!("[replace_payload] Impossible to splice for indices to_replace.len={}, range={pos}..{}. Payloads: {payloads:?}", to_replace.len(), pos+old_b_len);
            error!("{}", ft);
            return Err(Error::Term(ft))
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
