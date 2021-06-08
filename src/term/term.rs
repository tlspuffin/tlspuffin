use std::error::Error;
use std::fmt::Formatter;
use std::{any::Any, fmt, iter};

use itertools::Itertools;
use serde::{Deserialize, Serialize};

use crate::tls::FnError;
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

    fn unique_id(&self, tree_mode: bool, cluster_id: usize) -> String {
        match self {
            Term::Variable(variable) => {
                if tree_mode {
                    format!("v_{}_{}", cluster_id, variable.unique_id)
                } else {
                    format!("v_{}", variable.resistant_id)
                }
            }
            Term::Application(func, _) => {
                if tree_mode {
                    format!("f_{}_{}", cluster_id, func.unique_id)
                } else {
                    format!("f_{}", func.resistant_id)
                }
            }
        }
    }

    fn node_attributes(displayable: impl fmt::Display, color: u8, shape: &str) -> String {
        format!(
            "[label=\"{}\",style=filled,colorscheme=dark28,fillcolor={},shape={}]",
            displayable, color, shape
        )
    }

    fn collect_statements(
        term: &Term,
        tree_mode: bool,
        cluster_id: usize,
        statements: &mut Vec<String>,
    ) {
        match term {
            Term::Variable(variable) => {
                statements.push(format!(
                    "{} {};",
                    term.unique_id(tree_mode, cluster_id),
                    Self::node_attributes(variable, 1, "oval")
                ));
            }
            Term::Application(func, subterms) => {
                statements.push(format!(
                    "{} {};",
                    term.unique_id(tree_mode, cluster_id),
                    Self::node_attributes(
                        remove_prefix(func.name()),
                        if func.arity() == 0 { 1 } else { 2 },
                        "box"
                    )
                ));

                for subterm in subterms {
                    statements.push(format!(
                        "{} -- {};",
                        term.unique_id(tree_mode, cluster_id),
                        subterm.unique_id(tree_mode, cluster_id)
                    ));
                    Self::collect_statements(subterm, tree_mode, cluster_id, statements);
                }
            }
        }
    }

    /// If `tree_mode` is true then each subgraph is self-contained and does not reference other
    /// clusters or nodes outside of this subgraph. Therefore, only trees are generated. If it is
    /// false, then graphs are rendered.
    pub fn dot_subgraph(&self, tree_mode: bool, cluster_id: usize, label: &str) -> String {
        let mut statements = Vec::new();
        Self::collect_statements(self, tree_mode, cluster_id, &mut statements);
        format!(
            "subgraph cluster{} {{ label=\"{}\" \n{}\n}}",
            cluster_id,
            label,
            statements.iter().join("\n")
        )
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
    ($op:ident) => {
        Term::Application(Signature::new_function(&$op), vec![])
    };
}

#[macro_export]
macro_rules! app {
    ($op:ident, $($args:expr),*$(,)?) => {
        Term::Application(Signature::new_function(&$op),vec![$($args,)*])
    };
}

#[macro_export]
macro_rules! var {
    ($typ:ty, $id:expr) => {
        Term::Variable(Signature::new_var::<$typ>($id))
    };
}

// todo we could improve performance by not recreating these
#[macro_export]
macro_rules! term {
    // Variables
    (($step:expr, $msg:expr) / $typ:ty) => {{
        let var = crate::term::Signature::new_var::<$typ>( ($step, $msg));
        crate::term::Term::Variable(var)
    }};

    // Constants
    ($func:ident) => {{
        let func = crate::term::Signature::new_function(&$func);
        crate::term::Term::Application(func, vec![])
    }};

    // Function Applications
    ($func:ident ($($args:tt),*)) => {{
        let (shape, dynamic_fn) = crate::term::make_dynamic(&$func);
        let func = crate::term::Signature::new_function(&$func);
        crate::term::Term::Application(func, vec![$(crate::term_arg!($args)),*])
    }};
}

#[macro_export]
macro_rules! term_arg {
    // Somehow the following rules is very important
    ( ( $($e:tt)* ) ) => (term!($($e)*));
    // not sure why I should need this
    // ( ( $e:tt ) ) => (ast!($e));
    ($e:tt) => (term!($e));
}
