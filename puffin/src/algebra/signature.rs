use std::{
    collections::HashMap,
    fmt::{Debug, Formatter},
};

use itertools::Itertools;
use once_cell::sync::Lazy;

use super::atoms::Function;
use crate::{
    agent::AgentName,
    algebra::{
        atoms::Variable,
        dynamic_function::{
            make_dynamic, DescribableFunction, DynamicFunction, DynamicFunctionShape, TypeShape,
        },
    },
    trace::{Query, QueryMatcher},
};

pub type FunctionDefinition = (DynamicFunctionShape, Box<dyn DynamicFunction>);

/// Records a universe of functions.
/// Signatures are containers for types and function symbols. They hold references to the concrete
/// implementations of functions and the types of variables.
pub struct Signature {
    pub functions_by_name: HashMap<&'static str, FunctionDefinition>,
    pub functions_by_typ: HashMap<TypeShape, Vec<FunctionDefinition>>,
    pub functions: Vec<FunctionDefinition>,
    pub types_by_name: HashMap<&'static str, TypeShape>,
}

impl Debug for Signature {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "functions; {:?}\n", self.functions)
    }
}

impl Signature {
    /// Construct a `Signature` from the given [`FunctionDefinitions`]s.
    pub fn new(definitions: Vec<FunctionDefinition>) -> Signature {
        let functions_by_name: HashMap<&'static str, FunctionDefinition> = definitions
            .clone()
            .into_iter()
            .map(|(shape, dynamic_fn)| (shape.name, (shape, dynamic_fn)))
            .collect();

        let functions_by_typ: HashMap<TypeShape, Vec<FunctionDefinition>> = definitions
            .clone()
            .into_iter()
            .into_group_map_by(|(shape, _dynamic_fn)| shape.return_type);

        let types_by_name: HashMap<&'static str, TypeShape> = definitions
            .clone()
            .into_iter()
            .map(|(shape, _dynamic_fn)| {
                let used_types: Vec<TypeShape> = shape // vector of the argument shapes + return type
                    .argument_types
                    .iter()
                    .copied()
                    .chain(vec![shape.return_type])
                    .collect::<Vec<TypeShape>>();
                used_types
            })
            .unique()
            .flatten()
            .map(|typ| (typ.name, typ))
            .collect();

        Signature {
            functions_by_name,
            functions_by_typ,
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

        Function::new(shape, dynamic_fn.clone())
    }

    pub fn new_var_with_type<T: 'static, QM: QueryMatcher>(
        agent_name: AgentName,
        matcher: Option<QM>,
        counter: u16,
    ) -> Variable<QM> {
        let type_shape = TypeShape::of::<T>();
        Self::new_var(type_shape, agent_name, matcher, counter)
    }

    pub fn new_var<QM: QueryMatcher>(
        type_shape: TypeShape,
        agent_name: AgentName,
        matcher: Option<QM>,
        counter: u16,
    ) -> Variable<QM> {
        let query = Query {
            agent_name,
            matcher,
            counter,
        };
        Variable::new(type_shape, query)
    }
}

pub type StaticSignature = Lazy<Signature>;

pub const fn create_static_signature(init: fn() -> Signature) -> StaticSignature {
    Lazy::new(init)
}

#[macro_export]
macro_rules! define_signature {
    ($name_signature:ident, $($f:path)+) => {
        use $crate::algebra::signature::create_static_signature;
        use $crate::algebra::signature::StaticSignature;
        use $crate::algebra::signature::Signature;

        /// Signature which contains all functions defined in the `tls` module. A signature is responsible
        /// for linking function implementations to serialized data.
        ///
        /// Note: Changes in function symbols may cause deserialization of term to fail.
        pub static $name_signature: StaticSignature = create_static_signature(|| {
            let definitions = vec![
                $($crate::algebra::dynamic_function::make_dynamic(&$f)),*
            ];
            Signature::new(definitions)
        });
    };
}
