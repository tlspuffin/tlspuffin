use std::collections::HashMap;

use itertools::Itertools;
use once_cell::sync::Lazy;

use super::atoms::Function;
use crate::algebra::atoms::Variable;
use crate::algebra::dynamic_function::{
    make_dynamic, DescribableFunction, DynamicFunction, DynamicFunctionShape, TypeShape,
};
use crate::algebra::Matcher;
use crate::protocol::ProtocolTypes;
use crate::trace::{Query, Source};

pub type FunctionDefinition<PT> = (DynamicFunctionShape<PT>, Box<dyn DynamicFunction<PT>>);

/// Records a universe of functions.
/// Signatures are containers for types and function symbols. They hold references to the concrete
/// implementations of functions and the types of variables.
pub struct Signature<PT: ProtocolTypes> {
    pub functions_by_name: HashMap<&'static str, FunctionDefinition<PT>>,
    pub functions_by_typ: HashMap<TypeShape<PT>, Vec<FunctionDefinition<PT>>>,
    pub functions: Vec<FunctionDefinition<PT>>,
    pub types_by_name: HashMap<&'static str, TypeShape<PT>>,
}

impl<PT: ProtocolTypes> std::fmt::Debug for Signature<PT> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "functions; {:?}", self.functions)
    }
}

impl<PT: ProtocolTypes> Signature<PT> {
    /// Construct a `Signature` from the given [`FunctionDefinition`]s.
    pub fn new(definitions: Vec<FunctionDefinition<PT>>) -> Signature<PT> {
        let functions_by_name: HashMap<&'static str, FunctionDefinition<PT>> = definitions
            .clone()
            .into_iter()
            .map(|(shape, dynamic_fn)| (shape.name, (shape, dynamic_fn)))
            .collect();

        let functions_by_typ: HashMap<TypeShape<PT>, Vec<FunctionDefinition<PT>>> = definitions
            .clone()
            .into_iter()
            .into_group_map_by(|(shape, _dynamic_fn)| shape.return_type.clone());

        let types_by_name: HashMap<&'static str, TypeShape<PT>> = definitions
            .clone()
            .into_iter()
            .map(|(shape, _dynamic_fn)| {
                let used_types: Vec<TypeShape<PT>> = shape // vector of the argument shapes + return type
                    .argument_types
                    .iter()
                    .cloned()
                    .chain(vec![shape.return_type])
                    .collect::<Vec<TypeShape<PT>>>();
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

    /// Create a new [`Function`] distinct from all existing [`Function`]s.
    pub fn new_function<F, Types>(f: &'static F) -> Function<PT>
    where
        F: DescribableFunction<PT, Types> + 'static,
    {
        let (shape, dynamic_fn) = make_dynamic(f);

        Function::new(shape, dynamic_fn.clone())
    }

    pub fn new_var_with_type<T: 'static, M: Matcher>(
        source: Option<Source>,
        matcher: Option<M>,
        counter: u16,
    ) -> Variable<PT>
    where
        PT: ProtocolTypes<Matcher = M>,
    {
        let type_shape = TypeShape::<PT>::of::<T>();
        Self::new_var(type_shape, source, matcher, counter)
    }

    pub fn new_var<M: Matcher>(
        type_shape: TypeShape<PT>,
        source: Option<Source>,
        matcher: Option<M>,
        counter: u16,
    ) -> Variable<PT>
    where
        PT: ProtocolTypes<Matcher = M>,
    {
        let query = Query {
            source,
            matcher,
            counter,
        };
        Variable::new(type_shape, query)
    }
}

pub type StaticSignature<PT> = Lazy<Signature<PT>>;

pub const fn create_static_signature<PT: ProtocolTypes>(
    init: fn() -> Signature<PT>,
) -> StaticSignature<PT> {
    Lazy::new(init)
}

#[macro_export]
macro_rules! define_signature {
    ($name_signature:ident<$protocol_types:ident>, $($f:path)+) => {
        use $crate::algebra::signature::create_static_signature;
        use $crate::algebra::signature::StaticSignature;
        use $crate::algebra::signature::Signature;

        /// Signature which contains all functions defined in the `tls` module. A signature is responsible
        /// for linking function implementations to serialized data.
        ///
        /// Note: Changes in function symbols may cause deserialization of term to fail.
        pub static $name_signature: StaticSignature<$protocol_types> = create_static_signature(|| {
            let definitions = vec![
                $($crate::algebra::dynamic_function::make_dynamic(&$f)),*
            ];
            Signature::new(definitions)
        });
    };
}
