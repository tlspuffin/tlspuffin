use std::collections::HashMap;
use std::fmt;

use itertools::Itertools;

use crate::term::{DynamicFunction, DynamicFunctionShape};
use crate::{
    term::{
        dynamic_function::{make_dynamic, DescribableFunction},
        TypeShape, Variable,
    },
    trace::ObservedId,
};

use super::Function;
use rand::random;

pub type FunctionDefinition = (DynamicFunctionShape, Box<dyn DynamicFunction>);

/// Records a universe of functions.
///
pub struct Signature {
    pub functions_by_name: HashMap<String, (Vec<TypeShape>, Box<dyn DynamicFunction>)>,
    pub types_by_name: HashMap<&'static str, TypeShape>,
}

impl Signature {
    /// Construct a `Signature` from the given [`FunctionDefinitions`]s.
    pub fn new(definitions: Vec<FunctionDefinition>) -> Signature {
        let functions_by_name: HashMap<String, (Vec<TypeShape>, Box<dyn DynamicFunction>)> =
            definitions
                .into_iter()
                .map(|(shape, dynamic_fn)| {
                    let types: Vec<crate::term::TypeShape> = shape
                        .argument_types
                        .iter()
                        .copied()
                        .chain(vec![shape.return_type])
                        .collect::<Vec<crate::term::TypeShape>>();
                    (shape.name, (types, dynamic_fn))
                })
                .collect();

        let types_by_name: HashMap<&'static str, TypeShape> = functions_by_name
            .iter()
            .map(|(_, (types, _))| types.clone())
            .unique()
            .flatten()
            .map(|typ| (typ.name, typ.clone()))
            .collect();

        Signature {
            functions_by_name,
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
        let func = Function::new(
            shape.clone(),
            dynamic_fn.clone());
        func
    }

    fn new_var_internal(type_shape: TypeShape, observed_id: ObservedId) -> Variable {
        let variable = Variable::new(
            type_shape,
            observed_id,
        );
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
        pub static $name_signature: Lazy<crate::term::Signature> = Lazy::new(|| {
            let definitions = vec![
                $(crate::term::make_dynamic(&$f)),*
            ];
            crate::term::Signature::new(definitions)
        });
    };
}
