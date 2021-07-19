use std::collections::HashMap;
use std::fmt;

use itertools::Itertools;

use crate::{
    term::{
        atoms::Variable,
        dynamic_function::{
            make_dynamic, DescribableFunction, DynamicFunction, DynamicFunctionShape, TypeShape,
        },
    },
    trace::ObservedId,
};

use super::atoms::Function;

pub type FunctionDefinition = (DynamicFunctionShape, Box<dyn DynamicFunction>);

/// Records a universe of functions.
/// Signatures are containers for types and function symbols. They hold references to the concrete
/// implementations of functions and the types of variables.
pub struct Signature {
    pub functions_by_name: HashMap<String, (DynamicFunctionShape, Box<dyn DynamicFunction>)>,
    pub functions: Vec<FunctionDefinition>,
    pub types_by_name: HashMap<&'static str, TypeShape>,
}

impl Signature {
    /// Construct a `Signature` from the given [`FunctionDefinitions`]s.
    pub fn new(definitions: Vec<FunctionDefinition>) -> Signature {
        let functions_by_name: HashMap<String, (DynamicFunctionShape, Box<dyn DynamicFunction>)> =
            definitions
                .clone()
                .into_iter()
                .map(|(shape, dynamic_fn)| (shape.name.clone(), (shape, dynamic_fn)))
                .collect();

        let types_by_name: HashMap<&'static str, TypeShape> = definitions
            .clone()
            .into_iter()
            .map(|(shape, _dynamic_fn)| {
                let types: Vec<TypeShape> = shape
                    .argument_types
                    .iter()
                    .copied()
                    .chain(vec![shape.return_type])
                    .collect::<Vec<TypeShape>>();
                types
            })
            .unique()
            .flatten()
            .map(|typ| (typ.name, typ.clone()))
            .collect();

        Signature {
            functions_by_name,
            functions: definitions,
            types_by_name,
        }
    }

    /// Create a new [`Functions`] distinct from all existing [`Functions`]s.
    ///
    pub fn new_function<F: 'static, Types>(f: &'static F) -> Function
    where
        F: DescribableFunction<Types>,
    {
        let (shape, dynamic_fn) = make_dynamic(f);
        let func = Function::new(shape.clone(), dynamic_fn.clone());
        func
    }

    fn new_var_internal(type_shape: TypeShape, observed_id: ObservedId) -> Variable {
        let variable = Variable::new(type_shape, observed_id);
        variable
    }

    pub fn new_var<T: 'static>(observed_id: ObservedId) -> Variable {
        Self::new_var_internal(TypeShape::of::<T>(), observed_id)
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Signature{{{:?}}}", self)
    }
}

#[macro_export]
macro_rules! define_signature {
    ($name_signature:ident, $($f:path),+ $(,)?) => {
        use once_cell::sync::Lazy;
        /// Signature which contains all functions defined in the `tls` module.
        pub static $name_signature: Lazy<crate::term::signature::Signature> = Lazy::new(|| {
            let definitions = vec![
                $(crate::term::dynamic_function::make_dynamic(&$f)),*
            ];
            crate::term::signature::Signature::new(definitions)
        });
    };
}
