use std::fmt;
use std::fmt::Formatter;

use crate::term::type_helper::{DynamicFunction, DynamicFunctionShape};
use crate::trace::ObservedId;

use serde::{Serialize, Deserialize};
use crate::term::TypeShape;

/// A symbol for an unspecified term. Only carries meaning alongside a [`Signature`].
///
/// To construct a `Variable`, use [`Signature::new_var`]
///
/// [`Signature`]: struct.Signature.html
/// [`Signature::new_var`]: struct.Signature.html#method.new_var
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Variable {
    pub(crate) id: u32,
    pub(crate) typ_name: String,
    pub(crate) type_shape: TypeShape,
    pub(crate) observed_id: ObservedId,
}

impl fmt::Display for Variable {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "var<{}>", self.typ_name)
    }
}

/// A symbol with fixed arity. Only carries meaning alongside a [`Signature`].
///
/// To construct an `Operator`, use [`Signature::new_op`].
///
/// [`Signature`]: struct.Signature.html
/// [`Signature::new_op`]: struct.Signature.html#method.new_op
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Operator {
    pub(crate) id: u32,
    pub(crate) shape: DynamicFunctionShape,
    pub(crate) dynamic_fn: Box<dyn DynamicFunction>,
}

impl Operator {
    /// Returns an `Operator`'s arity.
    pub fn arity(&self) -> u16 {
        self.shape.arity()
    }
    /// Returns an `Operator`'s name.
    pub fn name(&self) -> & str {
        self.shape.name.as_str()
    }
    /// Serialize an `Operator`.
    pub fn display(&self) -> String {
        format!("{}", self.name())
    }
}
