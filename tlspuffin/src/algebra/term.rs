//! This module provides[`Term`]sas well as iterators over them.

use std::{any::Any, fmt, fmt::Formatter, ops::Deref};

use itertools::Itertools;
use serde::{Deserialize, Serialize};

use super::atoms::{Function, Variable};
use crate::{
    algebra::dynamic_function::TypeShape,
    error::Error,
    tls::error::FnError,
    trace::{AgentClaimer, TraceContext, VecClaimer},
    variable_data::VariableData,
};

/// A first-order term: either a [`Variable`] or an application of an [`Function`].
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
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
    pub fn resistant_id(&self) -> u32 {
        match self {
            Term::Variable(v) => v.resistant_id,
            Term::Application(f, _) => f.resistant_id,
        }
    }

    pub fn size(&self) -> usize {
        match self {
            Term::Variable(_) => 1,
            Term::Application(_, ref subterms) => {
                subterms.iter().map(|subterm| subterm.size()).sum::<usize>() + 1
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

    pub fn evaluate(&self, context: &TraceContext) -> Result<Box<dyn Any>, Error> {
        match self {
            Term::Variable(v) => {
                if v.typ == TypeShape::of::<AgentClaimer>() {
                    let claimer: &VecClaimer = &context.claimer.deref().borrow();
                    let ret: Box<dyn Any> =
                        Box::new(AgentClaimer::new(claimer.clone(), v.query.agent_name));
                    Ok(ret)
                } else {
                    context
                        .find_variable(v.typ, v.query)
                        .map(|data| data.clone_box_any())
                        .ok_or_else(|| Error::Term(format!("Unable to find variable {}!", v)))
                }
            }
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
                result.map_err(Error::Fn)
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
            match *term {
                Term::Variable(_) => {}
                Term::Application(_, ref subterms) => {
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

pub trait Subterms {
    fn find_subterm_same_shape(&self, term: &Term) -> Option<&Term>;

    fn find_subterm<P: Fn(&&Term) -> bool + Copy>(&self, filter: P) -> Option<&Term>;

    fn filter_grand_subterms<P: Fn(&Term, &Term) -> bool + Copy>(
        &self,
        predicate: P,
    ) -> Vec<((usize, &Term), &Term)>;
}

impl Subterms for Vec<Term> {
    /// Finds a subterm with the same type as `term`
    fn find_subterm_same_shape(&self, term: &Term) -> Option<&Term> {
        self.find_subterm(|subterm| term.get_type_shape() == subterm.get_type_shape())
    }

    /// Finds a subterm in this vector
    fn find_subterm<P: Fn(&&Term) -> bool + Copy>(&self, predicate: P) -> Option<&Term> {
        self.iter().find(predicate)
    }

    /// Finds all grand children/subterms which match the predicate.
    ///
    /// A grand subterm is defined as a subterm of a term in `self`.
    ///
    /// Each grand subterm is returned together with its parent and the index of the parent in `self`.
    fn filter_grand_subterms<P: Fn(&Term, &Term) -> bool + Copy>(
        &self,
        predicate: P,
    ) -> Vec<((usize, &Term), &Term)> {
        let mut found_grand_subterms = vec![];

        for (i, subterm) in self.iter().enumerate() {
            match &subterm {
                Term::Variable(_) => {}
                Term::Application(_, grand_subterms) => {
                    found_grand_subterms.extend(
                        grand_subterms
                            .iter()
                            .filter(|grand_subterm| predicate(subterm, grand_subterm))
                            .map(|grand_subterm| ((i, subterm), grand_subterm)),
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
    let split: Option<(&str, &str)> = str.split_inclusive('<').collect_tuple();

    if let Some((non_generic, generic)) = split {
        if let Some(pos) = non_generic.rfind("::") {
            non_generic[pos + 2..].to_string() + generic
        } else {
            non_generic.to_string() + generic
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
