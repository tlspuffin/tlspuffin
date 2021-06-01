use std::{any::Any, iter};

use itertools::Itertools;
use serde::{Deserialize, Serialize};

use crate::{term::pretty::Pretty, trace::TraceContext, variable_data::VariableData};

use super::{Operator, Variable};

/// A first-order term: either a [`Variable`] or an application of an [`Operator`].
///
/// [`Variable`]: struct.Variable.html
/// [`Operator`]: struct.Operator.html
#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum Term {
    /// A concrete but unspecified `Term` (e.g. `x`, `y`).
    /// See [`Variable`] for more information.
    ///
    /// [`Variable`]: struct.Variable.html
    ///
    Variable(Variable),
    /// An [`Operator`] applied to zero or more `Term`s (e.g. (`f(x, y)`, `g()`).
    ///
    /// A `Term` that is an application of an [`Operator`] with arity 0 applied to 0 `Term`s can be considered a constant.
    ///
    /// [`Operator`]: struct.Operator.html
    Application { op: Operator, args: Vec<Term> },
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

impl Term {
    pub fn display(&self) -> String {
        self.display_at_depth(0)
    }

    fn display_at_depth(&self, depth: usize) -> String {
        let tabs = "\t".repeat(depth);
        match self {
            Term::Variable(ref v) => format!("{}{}", tabs, remove_prefix(v.typ_name.as_str())),
            Term::Application { ref op, ref args } => {
                let op_str = remove_prefix(op.name());
                if args.is_empty() {
                    format!("{}{}", tabs, op_str)
                } else {
                    let args_str = args.iter().map(|arg| arg.display_at_depth(depth + 1)).join(",\n");
                    format!("{}{}(\n{}\n{})", tabs, op_str, args_str, tabs)
                }
            }
        }
    }
    /// A human-readable serialization of the `Term`.
    pub fn pretty(&self) -> String {
        Pretty::pretty(self)
    }

    /// Every [`Variable`] used in the `Term`.
    ///
    /// [`Variable`]: struct.Variable.html
    ///
    pub fn variables(&self) -> Vec<Variable> {
        match *self {
            Term::Variable(ref v) => vec![v.clone()],
            Term::Application { ref args, .. } => args.iter().flat_map(Term::variables).collect(),
        }
    }
    /// Every [`Operator`] used in the `Term`.
    ///
    /// [`Operator`]: struct.Operator.html
    ///
    pub fn operators(&self) -> Vec<Operator> {
        match *self {
            Term::Variable(_) => vec![],
            Term::Application { ref op, ref args } => args
                .iter()
                .flat_map(Term::operators)
                .chain(iter::once(op.clone()))
                .collect(),
        }
    }
    /// The arguments of the `Term`.
    ///
    pub fn args(&self) -> Vec<Term> {
        match self {
            Term::Variable(_) => vec![],
            Term::Application { args, .. } => args.clone(),
        }
    }

    pub fn evaluate(&self, context: &TraceContext) -> Result<Box<dyn Any>, String> {
        match self {
            Term::Variable(v) => context
                .get_variable_by_type_id(v.type_shape, v.observed_id)
                .map(|data| data.clone_box_any())
                .ok_or(format!(
                    "Unable to find variable {} with observed id {:?} in TraceContext!",
                    v, v.observed_id
                )),
            Term::Application { op, args } => {
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
                let dynamic_fn = &op.dynamic_fn();
                Ok(dynamic_fn(&dynamic_args))
            }
        }
    }
}

#[macro_export]
macro_rules! app_const {
    ($sig:ident, $op:ident) => {
        Term::Application {
            op: $sig.new_op(&$op),
            args: vec![],
        }
    };
}

#[macro_export]
macro_rules! app {
    ($sig:ident, $op:ident, $($args:expr),*$(,)?) => {
        Term::Application {
            op: $sig.new_op(&$op),
            args: vec![
                $($args,)*
            ],
        }
    };
}

#[macro_export]
macro_rules! var {
    ($sig:ident, $typ:ty, $id:expr) => {
        Term::Variable($sig.new_var::<$typ>($id))
    };
}
