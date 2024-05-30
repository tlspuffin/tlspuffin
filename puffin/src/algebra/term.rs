//! This module provides[`Term`]sas well as iterators over them.

use std::{any::Any, fmt, fmt::Formatter};

use itertools::Itertools;
use serde::{Deserialize, Serialize};

use super::atoms::{Function, Variable};
use crate::{
    algebra::{dynamic_function::TypeShape, error::FnError, Matcher},
    error::Error,
    protocol::ProtocolBehavior,
    trace::TraceContext,
};

/// A first-order term: either a [`Variable`] or an application of an [`Function`].
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
#[serde(bound = "M: Matcher")]
pub enum Term<M: Matcher> {
    /// A concrete but unspecified `Term` (e.g. `x`, `y`).
    /// See [`Variable`] for more information.
    ///
    Variable(Variable<M>),
    /// An [`Function`] applied to zero or more `Term`s (e.g. (`f(x, y)`, `g()`).
    ///
    /// A `Term` that is an application of an [`Function`] with arity 0 applied to 0 `Term`s can be considered a constant.
    ///
    Application(Function, Vec<Term<M>>),
}

impl<M: Matcher> fmt::Display for Term<M> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.display_at_depth(0))
    }
}

impl<M: Matcher> Term<M> {
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

    pub fn mutate(&mut self, other: Term<M>) {
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

    pub fn evaluate<PB: ProtocolBehavior>(
        &self,
        context: &TraceContext<PB>,
    ) -> Result<Box<dyn Any>, Error>
    where
        PB: ProtocolBehavior<Matcher = M>,
    {
        match self {
            Term::Variable(variable) => context
                .find_variable(variable.typ, &variable.query)
                .map(|data| data.boxed_any())
                .or_else(|| {
                    if let Some(agent_name) = variable.query.agent_name {
                        context.find_claim(agent_name, variable.typ)
                    } else {
                        None
                    }
                })
                .ok_or_else(|| Error::Term(format!("Unable to find variable {}!", variable))),
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

fn append<'a, M: Matcher>(term: &'a Term<M>, v: &mut Vec<&'a Term<M>>) {
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

/// Having the same mutator for &'a mut Term is not possible in Rust:
/// * <https://stackoverflow.com/questions/49057270/is-there-a-way-to-iterate-over-a-mutable-tree-to-get-a-random-node>
/// * <https://sachanganesh.com/programming/graph-tree-traversals-in-rust/>
impl<'a, M: Matcher> IntoIterator for &'a Term<M> {
    type Item = &'a Term<M>;
    type IntoIter = std::vec::IntoIter<&'a Term<M>>;

    fn into_iter(self) -> Self::IntoIter {
        let mut result = vec![];
        append::<M>(self, &mut result);
        result.into_iter()
    }
}

pub trait Subterms<M: Matcher> {
    fn find_subterm_same_shape(&self, term: &Term<M>) -> Option<&Term<M>>;

    fn find_subterm<P: Fn(&&Term<M>) -> bool + Copy>(&self, filter: P) -> Option<&Term<M>>;

    fn filter_grand_subterms<P: Fn(&Term<M>, &Term<M>) -> bool + Copy>(
        &self,
        predicate: P,
    ) -> Vec<((usize, &Term<M>), &Term<M>)>;
}

impl<M: Matcher> Subterms<M> for Vec<Term<M>> {
    /// Finds a subterm with the same type as `term`
    fn find_subterm_same_shape(&self, term: &Term<M>) -> Option<&Term<M>> {
        self.find_subterm(|subterm| term.get_type_shape() == subterm.get_type_shape())
    }

    /// Finds a subterm in this vector
    fn find_subterm<P: Fn(&&Term<M>) -> bool + Copy>(&self, predicate: P) -> Option<&Term<M>> {
        self.iter().find(predicate)
    }

    /// Finds all grand children/subterms which match the predicate.
    ///
    /// A grand subterm is defined as a subterm of a term in `self`.
    ///
    /// Each grand subterm is returned together with its parent and the index of the parent in `self`.
    fn filter_grand_subterms<P: Fn(&Term<M>, &Term<M>) -> bool + Copy>(
        &self,
        predicate: P,
    ) -> Vec<((usize, &Term<M>), &Term<M>)> {
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
    let split: Option<(&str, &str)> = str.split('<').collect_tuple();

    if let Some((non_generic, generic)) = split {
        let generic = &generic[0..generic.len() - 1];

        if let Some(pos) = non_generic.rfind("::") {
            non_generic[pos + 2..].to_string() + "<" + &remove_prefix(generic) + ">"
        } else {
            non_generic.to_string() + "<" + &remove_prefix(generic) + ">"
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

#[cfg(test)]
mod tests {
    use crate::algebra::remove_prefix;

    #[test]
    fn test_normal() {
        assert_eq!(remove_prefix("test::test::Test"), "Test");
    }

    #[test]
    fn test_generic() {
        assert_eq!(remove_prefix("test::test::Test<Asdf>"), "Test<Asdf>");
    }

    #[test]
    fn test_generic_recursive() {
        assert_eq!(remove_prefix("test::test::Test<asdf::Asdf>"), "Test<Asdf>");
    }
}
