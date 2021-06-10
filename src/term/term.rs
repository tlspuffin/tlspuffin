use std::borrow::BorrowMut;
use std::fmt::Formatter;
use std::{any::Any, fmt};

use itertools::Itertools;
use serde::{Deserialize, Serialize};

use crate::term::TypeShape;
use crate::tls::error::FnError;
use crate::trace::TraceContext;

use super::{Function, Variable};

/// A first-order term: either a [`Variable`] or an application of an [`Function`].
///
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
    Application(Function, Vec<Term>),
}

impl fmt::Display for Term {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.display_at_depth(0))
    }
}

impl Term {
    pub fn length(&self) -> usize {
        match self {
            Term::Variable(ref v) => 1,
            Term::Application(ref func, ref args) => {
                if args.is_empty() {
                    return 1;
                }

                args.iter().map(|subterm| subterm.length()).sum::<usize>() + 1
            }
        }
    }

    pub fn length_of_type(&self, type_shape: &TypeShape) -> usize {
        let increment = if type_shape == self.get_type_shape() {
            1
        } else {
            0
        };
        match self {
            Term::Variable(ref v) => increment,
            Term::Application(ref func, ref args) => {
                args.iter().map(|subterm| subterm.length_of_type(type_shape)).sum::<usize>() + increment
            }
        }
    }

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

    pub fn mutate_to_variable(&mut self, variable: Variable) {
        *self = Term::Variable(variable)
    }

    pub fn mutate_to_application(&mut self, func: Function, subterms: Vec<Term>) {
        *self = Term::Application(func, subterms)
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

    pub fn evaluate(&self, context: &TraceContext) -> Result<Box<dyn Any>, FnError> {
        match self {
            Term::Variable(v) => context
                .get_variable_by_type_id(v.typ, v.observed_id)
                .map(|data| data.clone_box_any())
                .ok_or(FnError::Message(format!(
                    "Unable to find variable {} with observed id {:?} in TraceContext!",
                    v, v.observed_id
                ))),
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
                result
            }
        }
    }
}

/// Having the same mutator for &'a mut Term is not possible in Rust:
/// https://stackoverflow.com/questions/49057270/is-there-a-way-to-iterate-over-a-mutable-tree-to-get-a-random-node
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
