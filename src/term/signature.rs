use std::fmt;

use rustls::internal::msgs::message::Message;
use serde::{Deserialize, Serialize};

use crate::{
    term::{
        dynamic_function::{make_dynamic, DescribableFunction},
        TypeShape, Variable,
    },
    trace::ObservedId,
};

use super::Function;

/// Records a universe of symbols.
///
///
#[derive(Clone, Serialize, Deserialize)]
pub struct Signature {
    pub(crate) functions: Vec<Function>,
    pub(crate) variables: Vec<Variable>,
}

impl Signature {
    /// Construct a `Signature` with the given [`Functions`]s.
    pub fn new(functions: Vec<Function>) -> Signature {
        Signature {
            functions,
            variables: vec![],
        }
    }
    /// Returns every [`Functions`] known to the `Signature`, in the order they were created.
    ///
    pub fn functions(&self) -> Vec<Function> {
        self.functions.clone()
    }
    /// Returns every [`Functions`] known to the `Signature`, in the order they were created.
    ///
    pub fn variables(&self) -> Vec<Variable> {
        self.variables.clone()
    }

    /// Create a new [`Functions`] distinct from all existing [`Functions`]s.
    ///
    pub fn new_function<F: 'static, Types>(&mut self, f: &'static F) -> Function
        where
        F: DescribableFunction<Types>,
    {
        let (shape, dynamic_fn) = make_dynamic(f);
        let func = Function::new(self.functions.len() as u32, shape, dynamic_fn);
        self.functions.push(func.clone());
        func
    }

    fn new_var_internal(
        &mut self,
        type_shape: TypeShape,
        observed_id: ObservedId,
    ) -> Variable {
        let variable = Variable {
            id: self.variables.len() as u32,
            type_shape,
            observed_id,
        };
        self.variables.push(variable.clone());
        variable
    }

    pub fn new_var<T: 'static>(&mut self, observed_id: ObservedId) -> Variable {
        self.new_var_internal(
            TypeShape::of::<T>(),
            observed_id,
        )
    }

    pub fn generate_message(&self) {
        for function in &self.functions {
            if function.shape().return_type == TypeShape::of::<Message>() {
                // function would build a Message -> lets try to build it
                let args = &(function.shape().argument_types);

                if let Some(_variable) = self
                    .variables
                    .iter()
                    .find(|variable| args.iter().any(|type_id| variable.type_shape == *type_id))
                {
                    // we found an already existing `variable` which helps us to call `function`
                }

                if let Some(_f) = self
                    .functions
                    .iter()
                    .find(|f| args.iter().any(|type_id| f.shape().return_type == *type_id))
                {
                    // we found an already existing function which helps us to call `function`
                }
            }
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
            functions: Vec::new(),
            variables: Vec::new(),
        }
    }
}
