use std::fmt::Formatter;
use std::{any::Any, fmt, iter};

use itertools::Itertools;
use serde::{Deserialize, Serialize};

use crate::trace::TraceContext;

use super::{Function, Variable};
use crate::tls::FnError;

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

/// `tlspuffin::term::op_impl::op_protocol_version` -> `op_protocol_version`
/// `alloc::Vec<rustls::msgs::handshake::ServerExtension>` -> `Vec<rustls::msgs::handshake::ServerExtension>`
fn remove_prefix(str: &str) -> String {
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

impl fmt::Display for Term {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.display_at_depth(0))
    }
}

impl Term {
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

    /// Every [`Variable`] used in the `Term`.
    ///
    pub fn variables(&self) -> Vec<Variable> {
        match *self {
            Term::Variable(ref v) => vec![v.clone()],
            Term::Application(_, ref args) => args.iter().flat_map(Term::variables).collect(),
        }
    }
    /// Every [`Function`] used in the `Term`.
    ///
    pub fn functions(&self) -> Vec<Function> {
        match *self {
            Term::Variable(_) => vec![],
            Term::Application(ref func, ref args) => args
                .iter()
                .flat_map(Term::functions)
                .chain(iter::once(func.clone()))
                .collect(),
        }
    }
    /// The arguments of the `Term`.
    ///
    pub fn args(&self) -> Vec<Term> {
        match self {
            Term::Variable(_) => vec![],
            Term::Application(_, args) => args.clone(),
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
                let result = dynamic_fn(&dynamic_args);
                result.map_err(|err| FnError::Message(err.to_string()))
            }
        }
    }
}

#[macro_export]
macro_rules! app_const {
    ($sig:ident, $op:ident) => {
        Term::Application($sig.new_function(&$op),vec![])
    };
}

#[macro_export]
macro_rules! app {
    ($sig:ident, $op:ident, $($args:expr),*$(,)?) => {
        Term::Application($sig.new_function(&$op),vec![$($args,)*])
    };
}

#[macro_export]
macro_rules! app1 {
    ($sig:ident, $op:ident($($args:expr),*$(,)?)) => {
        Term::Application($sig.new_function(&$op),vec![$($args,)*])
    };
}

#[macro_export]
macro_rules! var {
    ($sig:ident, $typ:ty, $id:expr) => {
        Term::Variable($sig.new_var::<$typ>($id))
    };
}
