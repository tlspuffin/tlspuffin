//! This module provides[`Term`]sas well as iterators over them.

use std::fmt::Formatter;
use std::{any::Any, fmt};

use itertools::Itertools;
use serde::{Deserialize, Serialize};

use crate::term::dynamic_function::TypeShape;
use crate::tls::error::FnError;
use crate::trace::TraceContext;

use super::atoms::{Function, Variable};
use crate::error::Error;
use std::rc::Rc;

/// A first-order term: either a [`Variable`] or an application of an [`Function`].
#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum Term {
    /// A concrete but unspecified `Term` (e.g. `x`, `y`).
    /// See [`Variable`] for more information.
    ///
    Variable(Variable),
    /// An [`Function`] applied to zero or more `Term`s (e.g. (`f(x, y)`, `g()`).
    ///
    /// A `Term` that is an application of an [`Function`] with arity 0 applied to 0 `Term`s can be considered a constant.
    ///
    Application(Function, Vec<Rc<Term>>),
}

impl fmt::Display for Term {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.display_at_depth(0))
    }
}

impl Term {
    pub fn length(&self) -> usize {
        match self {
            Term::Variable(_) => 1,
            Term::Application(_, ref args) => {
                if args.is_empty() {
                    return 1;
                }

                args.iter().map(|subterm| subterm.length()).sum::<usize>() + 1
            }
        }
    }
/*
    pub fn length_filtered<P: Fn(&Term) -> bool + Copy>(&self, filter: P) -> usize {
        let increment = if filter(self) {
            1
        } else {
            0
        };
        match self {
            Term::Variable(_) => increment,
            Term::Application(_, ref args) => {
                args.iter()
                    .map(|subterm| subterm.length_filtered(filter))
                    .sum::<usize>()
                    + increment
            }
        }
    }*/

    pub fn is_leaf(&self) -> bool {
        match self {
            Term::Variable(_) => {
                true // variable
            }
            Term::Application(_, ref subterms) => {
                subterms.is_empty() // constant
            }
        }
    }

    pub fn get_type_shape(&self) -> &TypeShape {
        match self {
            Term::Variable(v) => &v.typ,
            Term::Application(function, _) => &function.shape().return_type,
        }
    }

    pub fn name(&self) -> &str {
        match self {
            Term::Variable(v) => v.typ.name,
            Term::Application(function, _) => function.name(),
        }
    }

    pub fn mutate(&mut self, other: Term) {
        *self = other;
    }

    fn display_at_depth(&self, depth: usize) -> String {
        let tabs = "\t".repeat(depth);
        match self {
            Term::Variable(ref v) => format!("{}{}", tabs, remove_prefix(v.typ.name)),
            Term::Application(ref func, ref args) => {
                let op_str = remove_prefix(func.name());
                if args.is_empty() {
                    format!("{}{}", tabs, op_str)
                } else {
                    let args_str = args
                        .iter()
                        .map(|arg| arg.display_at_depth(depth + 1))
                        .join(",\n");
                    format!("{}{}(\n{}\n{})", tabs, op_str, args_str, tabs)
                }
            }
        }
    }

    pub fn evaluate(&self, context: &TraceContext) -> Result<Box<dyn Any>, Error> {
        match self {
            Term::Variable(v) => context
                .get_variable_by_type_id(v.typ, v.observed_id)
                .map(|data| data.clone_box_any())
                .ok_or(Error::Term(format!("Unable to find variable {}!", v))),
            Term::Application(func, args) => {
                let mut dynamic_args: Vec<Box<dyn Any>> = Vec::new();
                for term in args {
                    match term.evaluate(context) {
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

/// Having the same mutator for &'a mut Term is not possible in Rust:
/// * https://stackoverflow.com/questions/49057270/is-there-a-way-to-iterate-over-a-mutable-tree-to-get-a-random-node
/// * https://sachanganesh.com/programming/graph-tree-traversals-in-rust/
impl<'a> IntoIterator for &'a Term {
    type Item = &'a Term;
    type IntoIter = std::vec::IntoIter<&'a Term>;

    fn into_iter(self) -> Self::IntoIter {
        fn append<'a>(term: &'a Term, v: &mut Vec<&'a Term>) {
            match term {
                &Term::Variable(_) => {}
                &Term::Application(_, ref subterms) => {
                    for subterm in subterms {
                        append(subterm, v);
                    }
                }
            }

            v.push(term);
        }

        let mut result = vec![];
        append(self, &mut result);
        result.into_iter()
    }
}

impl<'a> IntoIterator for &'a mut Term {
    type Item = &'a mut Term;
    type IntoIter = std::vec::IntoIter<&'a mut Term>;

    fn into_iter(self) -> Self::IntoIter {
        fn append<'a>(term: &'a mut Term, v: &mut Vec<&'a mut Term>) {
            match term {
                &mut Term::Variable(_) => {}
                &mut Term::Application(_, ref mut subterms) => {
                    for subterm in subterms.iter_mut() {
                        // can we be sure that get_mut succeeds?
                        // still very similar, just that the check is moved to runtime!
                        append(Rc::<Term>::get_mut(subterm).unwrap(), v);
                    }
                }
            }

            v.push(term);
        }

        let mut result = vec![];
        append(self, &mut result);
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
