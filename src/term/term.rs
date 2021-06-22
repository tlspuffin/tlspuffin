//! This module provides[`Term`]sas well as iterators over them.

use std::fmt::Formatter;
use std::{any::Any, fmt};

use itertools::Itertools;
use serde::{Deserialize, Serialize};

use crate::error::Error;
use crate::term::dynamic_function::TypeShape;
use crate::tls::error::FnError;
use crate::trace::TraceContext;

use super::atoms::{Function, Variable};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Term {
    pub nodes: Vec<TermNode>, // todo make private
    pub root: TermId, // todo make private
}

impl Term {
    pub fn new(nodes: Vec<TermNode>, root: TermId) -> Self {
        Term { nodes, root }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TermNode {
    pub symbol: Symbol, // todo make private
    pub subterms: Vec<TermId>, // todo make private
}

type TermId = usize;

/// A first-order term: either a [`Variable`] or an application of an [`Function`].
#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum Symbol {
    /// A concrete but unspecified `Term` (e.g. `x`, `y`).
    /// See [`Variable`] for more information.
    ///
    Variable(Variable),
    /// An [`Function`] applied to zero or more `Term`s (e.g. (`f(x, y)`, `g()`).
    ///
    /// A `Term` that is an application of an [`Function`] with arity 0 applied to 0 `Term`s can be considered a constant.
    ///
    Application(Function),
}

impl Symbol {
    pub fn get_type_shape(&self) -> &TypeShape {
        match self {
            Symbol::Variable(v) => &v.typ,
            Symbol::Application(function) => &function.shape().return_type,
        }
    }
}

impl fmt::Display for Term {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.root_node().display_at_depth(self, 0))
    }
}

impl TermNode {
    pub fn length(&self, term: &Term) -> usize {
        if self.subterms.is_empty() {
            return 1;
        }

        self.subterms
            .iter()
            .map(|subterm_id| {
                let subterm = term.node_at(subterm_id);
                subterm.length(term)
            })
            .sum::<usize>()
            + 1
    }

    pub fn length_filtered<P: Fn(&Symbol) -> bool + Copy>(&self, term: &Term, filter: P) -> usize {
        let increment = if filter(&self.symbol) { 1 } else { 0 };
        self.subterms
            .iter()
            .map(|subterm_id| {
                let subterm = term.node_at(subterm_id);
                subterm.length_filtered(term, filter)
            })
            .sum::<usize>()
            + increment
    }

    pub fn is_leaf(&self) -> bool {
        self.subterms.is_empty()
    }

    pub fn get_symbol_shape(&self) -> &TypeShape {
        &self.symbol.get_type_shape()
    }

    pub fn name(&self) -> &str {
        match &self.symbol {
            Symbol::Variable(v) => v.typ.name,
            Symbol::Application(function) => function.name(),
        }
    }

    fn display_at_depth(&self, term: &Term, depth: usize) -> String {
        let tabs = "\t".repeat(depth);
        match &self.symbol {
            Symbol::Variable(ref v) => format!("{}{}", tabs, remove_prefix(v.typ.name)),
            Symbol::Application(ref func) => {
                let op_str = remove_prefix(func.name());
                if self.subterms.is_empty() {
                    format!("{}{}", tabs, op_str)
                } else {
                    let args_str = self
                        .subterms
                        .iter()
                        .map(|subterm_id| {
                            let subterm = term.node_at(subterm_id);
                            subterm.display_at_depth(term, depth + 1)
                        })
                        .join(",\n");
                    format!("{}{}(\n{}\n{})", tabs, op_str, args_str, tabs)
                }
            }
        }
    }

    pub fn evaluate(&self, term: &Term, context: &TraceContext) -> Result<Box<dyn Any>, Error> {
        match &self.symbol {
            Symbol::Variable(v) => context
                .get_variable_by_type_id(v.typ, v.observed_id)
                .map(|data| data.clone_box_any())
                .ok_or(Error::Term(format!("Unable to find variable {}!", v))),
            Symbol::Application(func) => {
                let mut dynamic_args: Vec<Box<dyn Any>> = Vec::new();
                for subterm_id in &self.subterms {
                    let subterm = term.node_at(subterm_id);
                    match subterm.evaluate(term, context) {
                        Ok(data) => {
                            dynamic_args.push(data);
                        }
                        Err(e) => {
                            return Err(e);
                        }
                    }
                }
                let dynamic_fn = func.dynamic_fn();
                let result: Result<Box<dyn Any>, FnError> = dynamic_fn(&dynamic_args);
                result.map_err(|err| Error::Fn(err))
            }
        }
    }
}

impl Term {
    pub fn length(&self, term: &Term) -> usize {
        self.root_node().length(term)
    }

    pub fn length_filtered<P: Fn(&Symbol) -> bool + Copy>(&self, term: &Term, filter: P) -> usize {
        self.root_node().length_filtered(term, filter)
    }

    pub fn evaluate(&self, context: &TraceContext) -> Result<Box<dyn Any>, Error> {
        self.root_node().evaluate(self, context)
    }

    pub fn root_node(&self) -> &TermNode {
        &self.nodes[self.root] // todo error check
    }

    pub fn node_at(&self, index: &TermId) -> &TermNode {
        &self.nodes[*index] // todo error check
    }

    pub fn node_at_mut(&mut self, index: &TermId) -> &mut TermNode {
        &mut self.nodes[*index] // todo error check
    }

    /// This function clones all nodes of this term into the `output` vector. It changes all the TermIndices
    /// such that the ids of the subterms are still valid. The return index is valid in the output nodes array.
    pub fn extend_vec(&self, output: &mut Vec<TermNode>) -> TermId {
        let next_id = output.len();
        for node in &self.nodes {
            let new_node = TermNode {
                symbol: node.symbol.clone(),
                subterms: node
                    .subterms
                    .iter()
                    .map(|subterm_id| next_id + subterm_id)
                    .collect(),
            };
            output.push(new_node);
        }

        next_id + self.root
    }
}

// Indexed iterating
impl IntoIterator for Term {
    type Item = TermNode;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.nodes.into_iter()
    }
}

/// `tlspuffin::term::op_impl::op_protocol_version` -> `op_protocol_version`
/// `alloc::Vec<rustls::msgs::handshake::ServerExtension>` -> `Vec<rustls::msgs::handshake::ServerExtension>`
pub(crate) fn remove_prefix(str: &str) -> String {
    let split: Option<(&str, &str)> = str.split_inclusive("<").collect_tuple();

    if let Some((non_generic, generic)) = split {
        if let Some(pos) = non_generic.rfind("::") {
            non_generic[pos + 2..].to_string() + generic
        } else {
            non_generic.to_string() + generic
        }
    } else {
        if let Some(pos) = str.rfind("::") {
            str[pos + 2..].to_string()
        } else {
            str.to_string()
        }
    }
}
