use std::any::Any;
use std::iter;

use itertools::Itertools;

use crate::term::pretty::Pretty;
use crate::variable_data::VariableData;

use super::{Operator, Variable};
use crate::trace::TraceContext;

/// A first-order term: either a [`Variable`] or an application of an [`Operator`].
///
/// [`Variable`]: struct.Variable.html
/// [`Operator`]: struct.Operator.html
#[derive(Clone)]
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
    ///
    Application { op: Operator, args: Vec<Term> },
}

impl Term {
    /// Serialize a `Term`.
    pub fn display(&self) -> String {
        match self {
            Term::Variable(ref v) => v.display(),
            Term::Application { ref op, ref args } => {
                let op_str = op.display();
                if args.is_empty() {
                    op_str
                } else {
                    let args_str = args.iter().map(Term::display).join(" ");
                    format!("{}({})", op_str, args_str)
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
            Term::Variable(v) => {
                let data: Option<&dyn VariableData> = context.get_variable_by_type_id(v.typ);
                data.map(|data| data.clone_any_box()).ok_or("Could not find variable".to_string())
            }
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
                let dynamic_fn = &op.dynamic_fn;
                Ok(dynamic_fn(&dynamic_args))
            }
        }
    }
}

pub trait VariableContext {
    fn find_variable_data<T: VariableData>(&self, variable: &Variable) -> Option<&T>;
}
