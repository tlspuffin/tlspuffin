use std::any::Any;
use std::borrow::Borrow;
use std::collections::HashMap;
use std::iter;

use itertools::Itertools;

use crate::agent::AgentName;
use crate::term::pretty::Pretty;
use crate::trace::TraceContext;
use crate::variable_data::{AsAny, VariableData};

use super::{Operator, Variable};

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

    pub fn evaluate(&self, context: &dyn VariableContext) -> Box<dyn Any + '_> {
        match self {
            Term::Variable(v) => context.find_variable_data(&v).unwrap().clone_data(),
            Term::Application { op, args } => {
                // todo: it would be cool not to save all arguments on the head, but I think the
                // todo: only alternative is to copy all data around
                /*let evaluated_args = args
                .iter()
                .map(|term| term.evaluate(context).as_ref())
                .collect::<Vec<&dyn Any>>();*/

                let mut dynamic_args: Vec<Box<dyn Any>> = Vec::new();

                for i in 0..args.len() {
                    let term = args.get(i).unwrap();

                    let eval = term.evaluate(context);
                    dynamic_args.push(eval);
                }

                //for i in args.iter() {
                //    let x2: Box<dyn Any> = i.evaluate(context);
                //    d.push(x2.as_any());
                //}

                let f = &op.dynamic_fn;
                //f(&vec![args.get(0).unwrap().evaluate(context).as_any()])
                f(&dynamic_args)
            }
        }
    }
}

pub trait VariableContext {
    fn find_variable_data(&self, variable: &Variable) -> Option<&dyn VariableData>;
}
