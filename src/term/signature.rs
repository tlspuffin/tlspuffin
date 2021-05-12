use std::any::TypeId;
use std::fmt;
use std::hash::{Hash, Hasher};

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
/// # Examples
///
/// ```
/// # use term_rewriting::{Signature};
/// // Constructing a Signature using the default
/// let mut sig1 = Signature::default();
/// let a = sig1.new_op(2, Some("A".to_string()));
/// let b = sig1.new_op(0, Some("B".to_string()));
/// let c = sig1.new_op(0, Some("C".to_string()));
///
/// // Constructing a Signature using Signature::new
/// let mut sig2 = Signature::new(vec![
///     (2, Some("A".to_string())),
///     (0, Some("B".to_string())),
///     (0, Some("C".to_string())),
/// ]);
///
/// assert_eq!(sig1, sig2);
/// ```
#[derive(Clone)]
pub struct Signature {
    /// Stores the (arity, name) for every [`Operator`].
    /// [`Operator`]: struct.Operator.html
    pub(crate) operators: Vec<Operator>,
    /// Stores the name for every [`Variable`].
    /// [`Variable`]: struct.Variable.html
    pub(crate) variables: Vec<(Option<String>, TypeId)>,
}
impl Signature {
    /// Construct a `Signature` with the given [`Operator`]s.
    ///
    /// Each [`Operator`] is specified in the form of `(arity, Some(name))` or
    /// `(arity, None)`, where `arity` is the number of arguments a [`Term`] takes
    /// (for example, an `arity` of 0 gives a "constant" [`Operator`]). A `name` for
    /// the [`Operator`] is unnecessary, but may be supplied for more readable
    /// formatting.
    ///
    /// The returned vector of [`Operator`]s corresponds to the supplied spec.
    ///
    /// [`Operator`]: struct.Operator.html
    /// [`Term`]: struct.Term.html
    ///
    /// # Examples
    ///
    /// ```
    /// # use term_rewriting::Signature;
    /// let mut sig = Signature::new(vec![
    ///     (2, Some(".".to_string())),
    ///     (0, Some("S".to_string())),
    ///     (0, Some("K".to_string())),
    /// ]);
    /// let ops = sig.operators();
    ///
    /// let op_names: Vec<String> = ops.iter().map(|op| op.display()).collect();
    /// assert_eq!(op_names, vec![".", "S", "K"]);
    ///
    /// let mut sig2 = Signature::default();
    /// let p = sig2.new_op(2, Some(".".to_string()));
    /// let s = sig2.new_op(0, Some("S".to_string()));
    /// let k = sig2.new_op(0, Some("K".to_string()));
    ///
    /// assert_eq!(sig, sig2);
    ///
    /// let mut sig = Signature::new(vec![]);
    ///
    /// let mut sig2 = Signature::default();
    ///
    /// assert_eq!(sig, sig2);
    ///```
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
    /// # Examples
    ///
    /// ```
    /// # use term_rewriting::Signature;
    /// let mut sig = Signature:: new(vec![
    ///     (2, Some(".".to_string())),
    ///     (0, Some("S".to_string())),
    ///     (0, Some("K".to_string())),
    /// ]);
    ///
    /// let ops: Vec<String> = sig.operators().iter().map(|op| op.display()).collect();;
    ///
    /// assert_eq!(ops, vec![".", "S", "K"]);
    ///```
    pub fn operators(&self) -> Vec<Operator> {
        self.operators.clone()
    }
    /// Returns every [`Variable`] known to the `Signature`, in the order they were created.
    ///
    /// [`Variable`]: struct.Variable.html
    ///
    ///
    pub fn variables(&self) -> Vec<Variable> {
        (0..self.variables.len())
            .collect::<Vec<usize>>()
            .into_iter()
            .map(|id| Variable {
                id,
                sig: self.clone(),
            })
            .collect()
    }

    /// Create a new [`Operator`] distinct from all existing [`Operator`]s.
    ///
    /// [`Operator`]: struct.Operator.html
    ///
    /// # Examples
    ///
    /// ```
    /// # use term_rewriting::{Signature};
    /// let mut sig = Signature::default();
    ///
    /// let a = sig.new_op(1, Some(".".to_string()));
    /// let s = sig.new_op(2, Some("S".to_string()));
    /// let s2 = sig.new_op(2, Some("S".to_string()));
    ///
    /// assert_ne!(a, s);
    /// assert_ne!(a, s2);
    /// assert_ne!(s, s2);
    /// ```
    pub fn new_op(&mut self, arity: u8, name: &'static str) -> Operator {
        todo!()
        //let operator = Operator { name, arity };
        //self.operators.push(operator.clone());

        //operator
    }
    /// Create a new [`Variable`] distinct from all existing [`Variable`]s.
    ///
    /// [`Variable`]: struct.Variable.html
    ///
    /// # Examples
    ///
    /// ```
    /// # use term_rewriting::{Signature};
    /// let mut sig = Signature::default();
    ///
    /// let z = sig.new_var(Some("z".to_string()));
    /// let z2 = sig.new_var(Some("z".to_string()));
    ///
    /// assert_ne!(z, z2);
    /// ```
    pub fn new_var(&mut self, typ: TypeId, name: Option<String>) -> Variable {
        self.variables.push((name, typ));
        let id = self.variables.len() - 1;
        Variable {
            id,
            sig: self.clone(),
        }
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
impl PartialEq for Signature {
    fn eq(&self, other: &Signature) -> bool {
        self.variables.len() == other.variables.len()
            && self.operators.len() == other.operators.len()
            && self
                .operators
                .iter()
                .zip(&other.operators)
                .all(|(o1, o2)| o1.arity() == o2.arity())
    }
}
impl Eq for Signature {}
