#![feature(clone_closures)]
use std::any::{TypeId, Any};

use super::Signature;
use crate::term::type_helper::{DynamicFunctionShape, DynamicFunction};

/// A symbol for an unspecified term. Only carries meaning alongside a [`Signature`].
///
/// To construct a `Variable`, use [`Signature::new_var`]
///
/// [`Signature`]: struct.Signature.html
/// [`Signature::new_var`]: struct.Signature.html#method.new_var
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Variable {
    pub(crate) id: usize,
    pub(crate) sig: Signature,
}
impl Variable {
    /// Serialize a `Variable`.
    ///
    /// # Examples
    ///
    /// ```
    /// let mut sig = Signature::default();
    /// let var = sig.new_var(Some("z".to_string()));
    ///
    /// assert_eq!(var.display(), "z_");
    /// ```
    pub fn display(&self) -> String {
        if let Some(ref name) = self.sig.variables[self.id].0 {
            format!("{}_", name)
        } else {
            format!("var{}_", self.id)
        }
    }
}

/// A symbol with fixed arity. Only carries meaning alongside a [`Signature`].
///
/// To construct an `Operator`, use [`Signature::new_op`].
///
/// [`Signature`]: struct.Signature.html
/// [`Signature::new_op`]: struct.Signature.html#method.new_op
#[derive(Clone)]
pub struct Operator {
    pub(crate) name: &'static str,
    pub(crate) arity: u8,
    pub(crate) shape: DynamicFunctionShape,
    pub(crate) dynamic_fn: Box<DynamicFunction>,
}
impl Operator {
    /// Returns an `Operator`'s arity.
    ///
    /// # Examples
    ///
    /// ```
    /// let mut sig = Signature::default();
    /// let op = sig.new_op(2, "Z");
    ///
    /// assert_eq!(op.arity(), 2);
    /// ```
    pub fn arity(&self) -> u8 {
        self.arity
    }
    /// Returns an `Operator`'s name.
    ///
    /// # Examples
    ///
    /// ```
    /// let mut sig = Signature::default();
    /// let op = sig.new_op(2, "Z");
    ///
    /// assert_eq!(op.name(), "Z");
    /// ```
    pub fn name(&self) -> &'static str {
        self.name
    }
    /// Serialize an `Operator`.
    ///
    /// # Examples
    ///
    /// ```
    /// let mut sig = Signature::default();
    /// let op = sig.new_op(2, Some("Z".to_string()));
    ///
    /// assert_eq!(op.display(), "Z");
    /// ```
    pub fn display(&self) -> String {
        format!("{}", self.name)
    }


}
