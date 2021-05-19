use std::any::TypeId;
use std::{fmt, any};
use std::hash::{Hasher};

use crate::term::type_helper::{DescribableFunction, make_dynamic};
use crate::term::Variable;

use super::Operator;

/// Records a universe of symbols.
///
/// Use [`Signature::default`] for a blank `Signature`, or [`Signature::new`] to initialize a
/// `Signature` with given [`Operator`]s.
///
/// [`Signature::default`]: #method.default
/// [`Signature::new`]: #method.new
/// [`Operator`]: struct.Operator.html
///
#[derive(Clone)]
pub struct Signature {
    pub(crate) operators: Vec<Operator>,
    pub(crate) variables: Vec<Variable>,
}

impl Signature {
    /// Construct a `Signature` with the given [`Operator`]s.
    ///
    /// [`Operator`]: struct.Operator.html
    /// [`Term`]: struct.Term.html
    ///
    pub fn new(operators: Vec<Operator>) -> Signature {
        Signature {
            operators,
            variables: vec![],
        }
    }
    /// Returns every [`Operator`] known to the `Signature`, in the order they were created.
    ///
    /// [`Operator`]: struct.Operator.html
    ///
    pub fn operators(&self) -> Vec<Operator> {
        self.operators.clone()
    }
    /// Returns every [`Variable`] known to the `Signature`, in the order they were created.
    ///
    /// [`Variable`]: struct.Variable.html
    ///
    ///
    pub fn variables(&self) -> Vec<Variable> {
        self.variables.clone()
    }

    /// Create a new [`Operator`] distinct from all existing [`Operator`]s.
    ///
    /// [`Operator`]: struct.Operator.html
    ///
    pub fn new_op<F: 'static, Types>(&mut self, f: &'static F) -> Operator
        where
            F: DescribableFunction<Types>,
    {
        let (shape, dynamic_fn) = make_dynamic(f);
        let operator = Operator {
            id: self.operators.len() as u32,
            shape,
            dynamic_fn
        };
        self.operators.push(operator.clone());
        operator
    }

    /// Create a new [`Variable`] distinct from all existing [`Variable`]s.
    ///
    /// [`Variable`]: struct.Variable.html
    ///
    pub fn new_var(&mut self, typ: TypeId, typ_name: &'static str) -> Variable {
        let variable = Variable {
            id: self.variables.len() as u32,
            typ_name,
            typ,
        };
        self.variables.push(variable.clone());
        variable
    }

    pub fn new_var_by_type<T: 'static>(&mut self) -> Variable {
        self.new_var(TypeId::of::<T>(), std::any::type_name::<T>())
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Signature{{{:?}}}", self)
    }
}

impl Default for Signature {
    fn default() -> Signature {
        Signature {
            operators: Vec::new(),
            variables: Vec::new(),
        }
    }
}

/*
TODO

impl PartialEq for Signature {
    fn eq(&self, other: &Signature) -> bool {
        self.variables.len() == other.variables.len()
            && self.operators.len() == other.operators.len()
            && self
            .operators
            .iter()
            .zip(&other.operators)
            .all(|(o1, o2)| o1.arity() == o2.arity() && o1.name().eq(o2.name()))
    }
}

impl Eq for Signature {}
*/