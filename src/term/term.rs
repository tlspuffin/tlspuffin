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
    pub symbols: Vec<Symbol>,
    pub index: Option<TermIndex>,
}

impl Term {
/*    pub fn new() -> Self {
        Term {
            symbols: vec![],
            index: None,
        }
    }*/

    pub fn new(symbols: Vec<Symbol>, index: TermIndex) -> Self {
        Term {
            symbols: symbols,
            index: Some(index),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TermIndex {
    pub id: usize,
    pub subterms: Vec::<TermIndex>,
}

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

impl fmt::Display for Term {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.index.unwrap().display_at_depth(self, 0))
    }
}

impl TermIndex {
    fn length(&self) -> usize {
        if self.subterms.is_empty() {
            return 1;
        }

        self.subterms
            .iter()
            .map(|subterm| subterm.length())
            .sum::<usize>()
            + 1
    }

    fn length_filtered<P: Fn(&Symbol) -> bool + Copy>(&self, term: &Term, filter: P) -> usize {
        let increment = if filter(term.symbols.get(self.id).unwrap()) { 1 } else { 0 };
        self.subterms
            .iter()
            .map(|subterm| subterm.length_filtered(term, filter))
            .sum::<usize>()
            + increment
    }

    fn is_leaf(&self) -> bool {
        self.subterms.is_empty()
    }

    fn get_type_shape<'a>(&self, term: &'a Term) -> &'a TypeShape {
        match term.symbols.get(self.id).unwrap() {
            Symbol::Variable(v) => &v.typ,
            Symbol::Application(function) => &function.shape().return_type,
        }
    }

    fn name<'a>(&self, term: &'a Term) -> &'a str {
        match term.symbols.get(self.id).unwrap() {
            Symbol::Variable(v) => v.typ.name,
            Symbol::Application(function) => function.name(),
        }
    }

    fn mutate(&mut self, other: TermIndex) {
        // iterate over term index and add new terms
    }

    fn display_at_depth(&self, term: &Term, depth: usize) -> String {
        let tabs = "\t".repeat(depth);
        match term.symbols.get(self.id).unwrap() {
            Symbol::Variable(ref v) => format!("{}{}", tabs, remove_prefix(v.typ.name)),
            Symbol::Application(ref func) => {
                let op_str = remove_prefix(func.name());
                if self.subterms.is_empty() {
                    format!("{}{}", tabs, op_str)
                } else {
                    let args_str = self.subterms
                        .iter()
                        .map(|arg| arg.display_at_depth(term, depth + 1))
                        .join(",\n");
                    format!("{}{}(\n{}\n{})", tabs, op_str, args_str, tabs)
                }
            }
        }
    }

    pub fn evaluate(&self, term: &Term, context: &TraceContext) -> Result<Box<dyn Any>, Error> {
        match term.symbols.get(self.id).unwrap() {
            Symbol::Variable(v) => context
                .get_variable_by_type_id(v.typ, v.observed_id)
                .map(|data| data.clone_box_any())
                .ok_or(Error::Term(format!("Unable to find variable {}!", v))),
            Symbol::Application(func) => {
                let mut dynamic_args: Vec<Box<dyn Any>> = Vec::new();
                for subterm in self.subterms {
                    match subterm.evaluate(term, context) {
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
                result.map_err(|err| Error::Fn(err))
            }
        }
    }
}

impl Term {
    pub fn length(&self) -> usize {
        self.index.unwrap().length()
    }

    pub fn length_filtered<P: Fn(&Symbol) -> bool + Copy>(&self, filter: P) -> usize {
        self.index.unwrap().length_filtered(self, filter)
    }

    pub fn is_leaf(&self, ) -> bool {
        todo!()
    }

    pub fn get_type_shape(&self) -> &TypeShape {
        todo!()
    }

    pub fn name(&self) -> &str {
        todo!()
    }

    pub fn mutate(&mut self, other: Term) {
        todo!()
    }

    pub fn evaluate(&self, context: &TraceContext) -> Result<Box<dyn Any>, Error> {
        self.index.unwrap().evaluate(self, context)
    }
}

impl<'a> IntoIterator for &'a Term {
    type Item = (&'a TermIndex, &'a Symbol);
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        fn append<'a>(term: &'a Term, index: &'a TermIndex, v: &mut Vec<(&'a TermIndex, &'a Symbol)>) {
            for subterm in index.subterms {
                append(term, &subterm, v);
            }

            v.push((index, term.symbols.get(index.id).unwrap()));
        }

        let mut result = vec![];
        append(&self, &self.index.unwrap(), &mut result);
        result.into_iter()
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
