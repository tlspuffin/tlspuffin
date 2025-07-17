//! This module provides[`DYTerm`]sas well as iterators over them.

use std::fmt;
use std::fmt::Debug;
use std::hash::Hash;

use anyhow::{anyhow, Context, Result};
use itertools::Itertools;
use serde::{Deserialize, Serialize};

use super::atoms::{Function, Variable};
use crate::algebra::bitstrings::{replace_payloads, EvalTree, PayloadMetadata, Payloads};
use crate::algebra::dynamic_function::TypeShape;
use crate::algebra::error::FnError;
use crate::error::Error;
use crate::fuzzer::stats_stage::{
    ALL_TERM_EVAL, ALL_TERM_EVAL_SUCCESS, EVAL_ERR_CODEC, EVAL_ERR_FN_CRYPTO,
    EVAL_ERR_FN_MALFORMED, EVAL_ERR_FN_UNKNOWN, EVAL_ERR_TERM, EVAL_ERR_TERMBUG,
};
use crate::protocol::{EvaluatedTerm, ProtocolBehavior, ProtocolTypes};
use crate::trace::TraceContext;

const SIZE_LEAF: usize = 1;
const BITSTRING_NAME: &str = "BITSTRING_";

pub type ConcreteMessage = Vec<u8>;

/// A first-order term: either a [`Variable`] or an application of an [`Function`].
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
#[serde(bound = "PT: ProtocolTypes")]
pub enum DYTerm<PT: ProtocolTypes> {
    /// A concrete but unspecified `Term` (e.g. `x`, `y`).
    /// See [`Variable`] for more information.
    Variable(Variable<PT>),
    /// An [`Function`] applied to zero or more `Term`s (e.g. (`f(x, y)`, `g()`).
    ///
    /// A `Term` that is an application of an [`Function`] with arity 0 applied to 0 `Term`s can be
    /// considered a constant.
    Application(Function<PT>, Vec<Term<PT>>),
}

impl<PT: ProtocolTypes> fmt::Display for DYTerm<PT> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", display_term_at_depth(self, 0, false, false))
    }
}

/// Trait for data we can treat as terms (either `DYTerm` or Term)
pub trait TermType<PT: ProtocolTypes>: fmt::Display + fmt::Debug + Clone {
    fn resistant_id(&self) -> u32;
    fn size(&self) -> usize;
    fn is_leaf(&self) -> bool;
    fn get_type_shape(&self) -> &TypeShape<PT>;
    fn name(&self) -> &str;
    fn mutate(&mut self, other: Self);
    fn display_at_depth(&self, depth: usize) -> String;
    fn is_symbolic(&self) -> bool;
    fn make_symbolic(&mut self); // remove all payloads
    fn get(&self, path: &[usize]) -> Result<&Self>;

    /// Evaluate terms into `ConcreteMessage` and `EvaluatedTerm` (considering Payloads or not
    /// depending on `with_payloads`) With `with_payloads, the returned `EvaluatedTerm` is
    /// without payload replacements; use the `ConcreteMessage` instead.
    fn evaluate_config<PB: ProtocolBehavior>(
        &self,
        context: &TraceContext<PB>,
        with_payloads: bool,
    ) -> Result<(ConcreteMessage, Box<dyn EvaluatedTerm<PT>>)>
    where
        PB: ProtocolBehavior<ProtocolTypes = PT>;

    /// Wrap `evaluate_config` with error stats and logging handling
    fn evaluate_config_wrap<PB: ProtocolBehavior>(
        &self,
        context: &TraceContext<PB>,
        with_payloads: bool,
    ) -> Result<(ConcreteMessage, Box<dyn EvaluatedTerm<PT>>), Error>
    where
        PB: ProtocolBehavior<ProtocolTypes = PT>,
    {
        ALL_TERM_EVAL.increment();
        match self.evaluate_config(context, with_payloads) {
            Ok(cm) => {
                ALL_TERM_EVAL_SUCCESS.increment();
                Ok(cm)
            }
            Err(e) => {
                match &e {
                    Error::Fn(FnError::Crypto(..)) => {
                        log::debug!("[evaluate_config_wrap]  FnError::Crypto Error on\n{}\n[==>] Causes: {:?}", &self, &e);
                        EVAL_ERR_FN_CRYPTO.increment();
                    }
                    Error::Fn(FnError::Malformed(..)) => {
                        log::debug!("[evaluate_config_wrap]  FnError::Malformed Error on\n{}\n[==>] Causes: {:?}", &self, &e);
                        EVAL_ERR_FN_MALFORMED.increment();
                    }
                    Error::Fn(FnError::Unknown(_fne)) => {
                        log::warn!("[evaluate_config_wrap]  FnError::Unknown Error on\n{}\n[==>] Causes: {:?}", &self, &e);
                        EVAL_ERR_FN_UNKNOWN.increment();
                    }
                    Error::Term(te) => {
                        log::debug!("[evaluate_config_wrap] Term Error {}", te);
                        EVAL_ERR_TERM.increment();
                    }
                    Error::TermBug(_) => {
                        log::error!("[evaluate_config_wrap] TermBug Error on\n{}\n[==>] Causes: {:?}", &self, &e);
                        EVAL_ERR_TERMBUG.increment();
                        #[cfg(any(debug_assertions, feature = "debug"))]
                        { // we panic in debug or test mode
                            panic!("[evaluate_config_wrap] Panic! {}", e);
                        }
                    }
                    Error::Codec(_) => {
                        EVAL_ERR_CODEC.increment();
                    }
                    _ => {
                        panic!("[evaluate] downcast error failed!");
                    }
                };
                Err(e)
            }
        }
    }

    /// Evaluate terms into `ConcreteMessage` (considering Payloads)
    fn evaluate<PB: ProtocolBehavior>(&self, ctx: &TraceContext<PB>) -> Result<ConcreteMessage>
    where
        PB: ProtocolBehavior<ProtocolTypes = PT>,
    {
        Ok(self
            .evaluate_config_wrap(ctx, ctx.config_trace.with_bit_level)?
            .0)
    }

    /// Evaluate terms into `ConcreteMessage` considering all sub-terms as symbolic (even those with
    /// Payloads)
    fn evaluate_symbolic<PB: ProtocolBehavior>(
        &self,
        ctx: &TraceContext<PB>,
    ) -> Result<ConcreteMessage>
    where
        PB: ProtocolBehavior<ProtocolTypes = PT>,
    {
        Ok(self.evaluate_config_wrap(ctx, false)?.0)
    }

    /// Evaluate terms into `EvaluatedTerm`  considering all sub-terms as symbolic (even those with
    /// Payloads)
    fn evaluate_dy<PB: ProtocolBehavior>(
        &self,
        ctx: &TraceContext<PB>,
    ) -> Result<Box<dyn EvaluatedTerm<PT>>>
    where
        PB: ProtocolBehavior<ProtocolTypes = PT>,
    {
        Ok(self.evaluate_config_wrap(ctx, false)?.1)
    }
}

fn append<'a, PT: ProtocolTypes>(term: &'a DYTerm<PT>, v: &mut Vec<&'a DYTerm<PT>>) {
    match *term {
        DYTerm::Variable(_) => {}
        DYTerm::Application(_, ref subterms) => {
            for subterm in subterms {
                append(&subterm.term, v);
            }
        }
    }

    v.push(term);
}

/// Having the same mutator for &'a mut Term is not possible in Rust:
/// * <https://stackoverflow.com/questions/49057270/is-there-a-way-to-iterate-over-a-mutable-tree-to-get-a-random-node>
/// * <https://sachanganesh.com/programming/graph-tree-traversals-in-rust/>
impl<'a, PT: ProtocolTypes> IntoIterator for &'a DYTerm<PT> {
    type IntoIter = std::vec::IntoIter<&'a DYTerm<PT>>;
    type Item = &'a DYTerm<PT>;

    fn into_iter(self) -> Self::IntoIter {
        let mut result = vec![];
        append::<PT>(self, &mut result);
        result.into_iter()
    }
}

pub trait Subterms<PT: ProtocolTypes, T>
where
    T: TermType<PT>,
{
    fn find_subterm_same_shape(&self, term: &T) -> Option<&T>;

    fn find_subterm<P: Fn(&&T) -> bool + Copy>(&self, filter: P) -> Option<&T>;

    fn filter_grand_subterms<P: Fn(&T, &T) -> bool + Copy>(
        &self,
        predicate: P,
    ) -> Vec<((usize, &T), &T)>;
}

/// `tlspuffin::term::op_impl::op_protocol_version` -> `op_protocol_version`
/// `alloc::Vec<rustls::msgs::handshake::ServerExtension>` ->
/// `Vec<rustls::msgs::handshake::ServerExtension>`
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

/// `Term`s are `Term`s equipped with optional `Payloads` when they no longer are treated as
/// symbolic terms.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
#[serde(bound = "PT: ProtocolTypes")]
pub struct Term<PT: ProtocolTypes> {
    pub term: DYTerm<PT>, // initial DY term
    pub payloads: Option<Payloads>, /* None until make_message mutation is used and fill this
                           * with term.evaluate() */
}

impl<PT: ProtocolTypes> Term<PT> {
    /// Height of term, considering non-symbolic terms as atoms
    pub fn height(&self) -> usize {
        match &self.term {
            DYTerm::Application(_, subterms) => {
                if subterms.is_empty() || !self.is_symbolic() {
                    1
                } else {
                    1 + subterms.iter().map(Self::height).max().unwrap()
                }
            }
            _ => 1,
        }
    }

    /// When the term starts with a list function symbol
    pub fn is_list(&self) -> bool {
        match &self.term {
            DYTerm::Variable(_) => false,
            DYTerm::Application(fd, _) => fd.is_list(),
        }
    }

    /// When the term starts with an opaque function symbol (like encryption)
    pub fn is_opaque(&self) -> bool {
        match &self.term {
            DYTerm::Variable(_) => false,
            DYTerm::Application(fd, _) => fd.is_opaque(),
        }
    }

    /// When the term starts with an opaque function symbol (like encryption)
    pub fn is_get(&self) -> bool {
        match &self.term {
            DYTerm::Variable(_) => false,
            DYTerm::Application(fd, _) => fd.is_get(),
        }
    }

    /// When the term starts with a `no_bit` function symbol. We will never MakeMessage on, thus
    /// disabling applying any of the bit-level mutations.
    pub fn is_no_bit(&self) -> bool {
        match &self.term {
            DYTerm::Variable(_) => false,
            DYTerm::Application(fd, _) => fd.no_bit(),
        }
    }

    /// When the term has a variable as sub-term (excluding strict0-sub-terms of readable)
    pub fn has_variable(&self) -> bool {
        match &self.term {
            DYTerm::Variable(_) => true,
            DYTerm::Application(_, args) => {
                !self.is_readable() && args.iter().any(|arg| arg.has_variable())
            }
        }
    }

    /// Whether the term is readable, i.e. whether it has a payload that will be read before
    /// evaluating
    pub fn is_readable(&self) -> bool {
        if let Some(payload) = &self.payloads {
            payload.metadata.readable
        } else {
            false
        }
    }

    /// Erase all payloads in a term, including those under opaque function symbol
    pub fn erase_payloads_subterms(&mut self, is_subterm: bool) {
        if is_subterm {
            self.payloads = None;
        }
        match &mut self.term {
            DYTerm::Variable(_) => {}
            DYTerm::Application(_, args) => {
                // Not true anymore: if opaque, we keep payloads in strict sub-terms
                for t in args {
                    t.erase_payloads_subterms(true);
                }
            }
        }
    }

    /// Add a payload at the root position and start with a new payload.payload possibly different
    /// from payload.payload_0, erase payloads in strict sub-terms not under opaque
    pub fn add_payload_with_new(
        &mut self,
        payload_0: Vec<u8>,
        payload_new: Vec<u8>,
        with_metadata: Option<PayloadMetadata>,
    ) {
        self.payloads = Option::from({
            Payloads {
                payload_0: payload_0.into(),
                payload: payload_new.into(),
                metadata: with_metadata.unwrap_or_else(|| PayloadMetadata::default()),
            }
        });
        self.erase_payloads_subterms(false);
    }

    /// Add a payload at the root position, erase payloads in strict sub-terms not under opaque
    pub fn add_payload(&mut self, payload_0: Vec<u8>) {
        self.add_payload_with_new(payload_0.clone(), payload_0, None)
    }

    /// Make and Add a payload at the root position, erase payloads in strict sub-terms
    pub fn make_payload<PB>(&mut self, ctx: &TraceContext<PB>) -> Result<()>
    where
        PB: ProtocolBehavior<ProtocolTypes = PT>,
    {
        log::debug!("make_payload: about to symbolic evaluate to get eval_0...");
        // TODO: do we still want to evaluate with paylloads under opaque terms?
        let eval_0 = self.evaluate_symbolic(ctx)?; // we compute the original encoding, without payloads!
        if self.has_payload_to_replace() {
            // specific case: we will directly put the evaluation (with existing payloads in
            // payload.payload)
            log::debug!(
                "make_payload: self has payload to replace, evaluate the term to get payload"
            );
            let eval = self.evaluate(ctx)?; // we compute the original encoding, without payloads!
            self.add_payload_with_new(eval_0, eval, None);
            Ok(())
        } else {
            self.add_payload(eval_0);
            Ok(())
        }
    }

    /// Add a payload at the root position, erase payloads in strict sub-terms and make the payload
    /// readable.
    pub fn add_payload_readable(&mut self, payload: ConcreteMessage) {
        self.add_payload_with_new(
            payload.clone(),
            payload,
            Some(PayloadMetadata {
                readable: true,
                ..PayloadMetadata::default()
            }),
        );
    }

    /// Return all payloads contains in a term, even under opaque terms.
    /// Note that we keep the invariant that a non-symbolic term cannot have payloads in
    /// strict-subterms, see `add_payload/make_payload`.
    pub fn all_payloads(&self) -> Vec<&Payloads> {
        self.into_iter()
            .filter_map(|t| t.payloads.as_ref())
            .collect()
    }

    /// Return all payloads contains in a term (mutable references), even under opaque terms.
    /// Note that we keep the invariant that a non-symbolic term cannot have payloads in
    /// strict-subterms, see `add_payload/make_payload`.
    pub fn all_payloads_mut(&mut self) -> Vec<&mut Payloads> {
        // unable to implement as_iter_map for Term due to its tree structure so:
        // do it manually instead!
        fn rec<'a, PT: ProtocolTypes>(term: &'a mut Term<PT>, acc: &mut Vec<&'a mut Payloads>) {
            if let Some(p) = &mut term.payloads {
                acc.push(p);
            }
            match &mut term.term {
                DYTerm::Variable(_) => {}
                DYTerm::Application(_, sts) => {
                    for st in sts {
                        rec(st, acc);
                    }
                }
            }
        }
        let mut acc = Vec::new();
        rec(self, &mut acc);
        acc
    }

    /// Return all payloads contained in a term, except those under opaque or readable terms.
    /// The deeper the first in the returned vector.
    pub fn payloads_to_replace(&self) -> Vec<&Payloads> {
        pub fn rec<'a, PT: ProtocolTypes>(term: &'a Term<PT>, acc: &mut Vec<&'a Payloads>) {
            match &term.term {
                DYTerm::Variable(_) => {}
                DYTerm::Application(_, args) => {
                    if !term.is_opaque() && !term.is_readable() {
                        for t in args {
                            rec(t, acc);
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

    /// Return whether there is at least one payload, except those under opaque or readable terms.
    pub fn has_payload_to_replace(&self) -> bool {
        has_payload_to_replace_rec(self, true)
    }

    /// Return whether there is at least one payload, except those under opaque terms or readable
    /// and at the root.
    pub fn has_payload_to_replace_wo_root(&self) -> bool {
        has_payload_to_replace_rec(self, false)
    }
}

pub fn has_payload_to_replace_rec<PT: ProtocolTypes>(term: &Term<PT>, include_root: bool) -> bool {
    if let (Some(_), true) = (&term.payloads, include_root) {
        return true;
    }
    match &term.term {
        DYTerm::Variable(_) => {}
        DYTerm::Application(_, args) => {
            if !term.is_opaque() && !term.is_readable() {
                for t in args {
                    if has_payload_to_replace_rec(t, true) {
                        return true;
                    }
                }
            }
        }
    }
    false
}

impl<PT: ProtocolTypes> fmt::Display for Term<PT> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.display_at_depth(0))
    }
}
impl<PT: ProtocolTypes> From<DYTerm<PT>> for Term<PT> {
    fn from(term: DYTerm<PT>) -> Self {
        Self {
            term,
            payloads: None,
        }
    }
}

impl<PT: ProtocolTypes> From<Term<PT>> for DYTerm<PT> {
    fn from(term: Term<PT>) -> Self {
        term.term
    }
}

fn display_term_at_depth<PT: ProtocolTypes>(
    term: &DYTerm<PT>,
    depth: usize,
    is_bitstring: bool,
    is_readable: bool,
) -> String {
    let tabs = "\t".repeat(depth);
    match term {
        DYTerm::Variable(ref v) => {
            let is_bitstring = if is_bitstring {
                if is_readable {
                    "BS-READ//"
                } else {
                    "BS//"
                }
            } else {
                ""
            };
            format!("{tabs}{is_bitstring}{v}")
        }
        DYTerm::Application(ref func, ref args) => {
            let op_str = remove_prefix(func.name());
            let return_type = remove_prefix(func.shape().return_type.name);
            let is_bitstring = if is_bitstring { "BS//" } else { "" };
            if args.is_empty() {
                format!("{tabs}{is_bitstring}{op_str} -> {return_type}")
            } else {
                let args_str = args
                    .iter()
                    .map(|arg| {
                        display_term_at_depth(
                            &arg.term,
                            depth + 1,
                            !arg.is_symbolic(),
                            arg.is_readable(),
                        )
                    })
                    .join(",\n");
                format!("{tabs}{is_bitstring}{op_str}(\n{args_str}\n{tabs}) -> {return_type}")
            }
        }
    }
}

fn append_eval<'a, PT: ProtocolTypes>(term_eval: &'a Term<PT>, v: &mut Vec<&'a Term<PT>>) {
    match term_eval.term {
        DYTerm::Variable(_) => {}
        DYTerm::Application(_, ref subterms) => {
            for subterm in subterms {
                append_eval(subterm, v);
            }
        }
    }

    v.push(term_eval);
}

impl<PT: ProtocolTypes> TermType<PT> for Term<PT> {
    /// Evaluate terms into bitstrings and `EvaluatedTerm` (considering Payloads)
    fn evaluate_config<PB: ProtocolBehavior>(
        &self,
        context: &TraceContext<PB>,
        with_payloads: bool,
    ) -> Result<(ConcreteMessage, Box<dyn EvaluatedTerm<PT>>)>
    where
        PB: ProtocolBehavior<ProtocolTypes = PT>,
    {
        log::trace!("[evaluate_config] About to evaluate term (with_payloads: {with_payloads}):\n{}\n===================================================================", &self);
        let mut eval_tree = EvalTree::empty();
        let (m, all_payloads) = self
            .eval_until_opaque(
                &mut eval_tree,
                context,
                with_payloads,
                false,
                self.get_type_shape(),
            )
            .with_context(|| format!("--> [evaluate_config] eval_until_opaque failed"))?;
        // if let Some(mut e) = eval {
        if with_payloads && !all_payloads.is_empty() {
            let ft = format!("[evaluate_config] About to replace for a term {}\n payloads with contexts: {}\n-------------------------------------------------------------------",
                    self, all_payloads.iter().format(","));
            log::trace!("{}", ft);
            let res = replace_payloads(self, &mut eval_tree, all_payloads).with_context(|| {
                format!(
                    "[eval_until_opaque] replace_payloads failed with:\n\
                      - eval_tree: {:?}\n Call: {ft}",
                    &eval_tree
                )
            })?;
            log::trace!(
                "        / [payload]    We successfully evaluated the root term into: {res:?}"
            );
            Ok((res, m))
        } else {
            let eval = PB::any_get_encoding(m.as_ref());
            log::trace!(
                "        / [no_payload] We successfully evaluated the root term into: {eval:?}"
            );
            Ok((eval, m))
        }
    }

    fn resistant_id(&self) -> u32 {
        match &self.term {
            DYTerm::Variable(v) => v.resistant_id,
            DYTerm::Application(f, _) => f.resistant_id,
        }
    }

    /// size of a term, considering non-symbolic terms as atoms
    fn size(&self) -> usize {
        if self.is_leaf() {
            SIZE_LEAF
        } else {
            match &self.term {
                DYTerm::Variable(_) => SIZE_LEAF,
                DYTerm::Application(_, ref subterms) => {
                    if !self.is_symbolic() {
                        SIZE_LEAF
                    } else {
                        subterms.iter().map(TermType::size).sum::<usize>() + 1
                    }
                }
            }
        }
    }

    fn is_leaf(&self) -> bool {
        if self.is_symbolic() {
            match &self.term {
                DYTerm::Variable(_) => {
                    true // variable
                }
                DYTerm::Application(_, ref subterms) => {
                    subterms.is_empty() // constant
                }
            }
        } else {
            true
        }
    }

    fn get_type_shape(&self) -> &TypeShape<PT> {
        match &self.term {
            DYTerm::Variable(v) => &v.typ,
            DYTerm::Application(function, _) => &function.shape().return_type,
        }
    }

    fn name(&self) -> &str {
        if self.is_symbolic() {
            // we do not display this information for now
            match &self.term {
                DYTerm::Variable(v) => v.typ.name,
                DYTerm::Application(function, _) => function.name(),
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

    fn mutate(&mut self, other: Self) {
        *self = other;
    }

    fn display_at_depth(&self, depth: usize) -> String {
        display_term_at_depth(&self.term, depth, !self.is_symbolic(), self.is_readable())
    }

    fn is_symbolic(&self) -> bool {
        self.payloads.is_none()
    }

    fn make_symbolic(&mut self) {
        self.erase_payloads_subterms(true); // true as we also want to remove payloads at top-level
    }

    fn get(&self, path: &[usize]) -> Result<&Self> {
        if path.is_empty() {
            return Ok(self);
        }
        match &self.term {
            DYTerm::Variable(_) => { Err(anyhow!(Error::TermBug(format!(
                    "--> [get] Should never happen! self.args.len() <= nb. Term: {self}\n, path: {path:?}"
                )))) }
            DYTerm::Application(_, args) => {
                let nb = path[0];
                let path = &path[1..];
                if args.len() <= nb {
                    return Err(anyhow!(Error::TermBug(format!(
                    "--> [get] Should never happen! self.args.len() <= nb. Term: {self}\n, path: {path:?}"
                ))));
                }
                args[nb].get(path)
            }
        }
    }
}

/// Having the same mutator for &'a mut `DYTerm` is not possible in Rust:
/// * <https://stackoverflow.com/questions/49057270/is-there-a-way-to-iterate-over-a-mutable-tree-to-get-a-random-node>
/// * <https://sachanganesh.com/programming/graph-tree-traversals-in-rust/>
impl<'a, PT: ProtocolTypes> IntoIterator for &'a Term<PT> {
    type IntoIter = std::vec::IntoIter<&'a Term<PT>>;
    type Item = &'a Term<PT>;

    fn into_iter(self) -> Self::IntoIter {
        let mut result = vec![];
        append_eval::<PT>(self, &mut result);
        result.into_iter()
    }
}

impl<PT: ProtocolTypes> Subterms<PT, Term<PT>> for Vec<Term<PT>> {
    /// Finds a subterm with the same type as `term`
    fn find_subterm_same_shape(&self, term: &Term<PT>) -> Option<&Term<PT>> {
        self.find_subterm(|subterm| term.get_type_shape() == subterm.get_type_shape())
    }

    /// Finds a subterm in this vector
    fn find_subterm<P: Fn(&&Term<PT>) -> bool + Copy>(&self, predicate: P) -> Option<&Term<PT>> {
        self.iter().find(predicate)
    }

    /// Finds all grand children/subterms which match the predicate.
    ///
    /// A grand subterm is defined as a subterm of a term in `self`.
    ///
    /// Each grand subterm is returned together with its parent and the index of the parent in
    /// `self`.
    fn filter_grand_subterms<P: Fn(&Term<PT>, &Term<PT>) -> bool + Copy>(
        &self,
        predicate: P,
    ) -> Vec<((usize, &Term<PT>), &Term<PT>)> {
        let mut found_grand_subterms = vec![];

        for (i, subterm) in self.iter().enumerate() {
            match &subterm.term {
                DYTerm::Variable(_) => {}
                DYTerm::Application(_, grand_subterms) => {
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

    #[test_log::test]
    fn test_normal() {
        assert_eq!(remove_prefix("test::test::Test"), "Test");
    }

    #[test_log::test]
    fn test_generic() {
        assert_eq!(remove_prefix("test::test::Test<Asdf>"), "Test<Asdf>");
    }

    #[test_log::test]
    fn test_generic_recursive() {
        assert_eq!(remove_prefix("test::test::Test<asdf::Asdf>"), "Test<Asdf>");
    }
}
