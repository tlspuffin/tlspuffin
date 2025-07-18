//! This module provides an enum for terms. A term can either be a Variable or a Function.
//! This also implements the serializability of terms.
use std::fmt::{self};
use std::hash::{Hash, Hasher};

use rand::random;
use serde::{Deserialize, Serialize};

use crate::algebra::atoms::fn_container::FnContainer;
use crate::algebra::dynamic_function::{
    DynamicFunction, DynamicFunctionShape, FunctionAttributes, TypeShape,
};
use crate::algebra::remove_prefix;
use crate::protocol::ProtocolTypes;
use crate::trace::Query;

/// A variable symbol with fixed type.
#[derive(Serialize, Deserialize, Debug)]
#[serde(bound = "PT: ProtocolTypes")]
pub struct Variable<PT: ProtocolTypes> {
    /// Unique ID of this variable. Uniqueness is guaranteed across all
    /// [`Term`](crate::algebra::Term)s ever created. Cloning change this ID.
    pub unique_id: u32,
    /// ID of this variable. This id stays the same during cloning.
    pub resistant_id: u32,
    pub typ: TypeShape<PT>,
    /// The struct which holds information about how to query this variable from knowledge
    pub query: Query<PT::Matcher>,
}

impl<PT: ProtocolTypes> Hash for Variable<PT> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.typ.hash(state);
        self.query.hash(state);
    }
}

impl<PT: ProtocolTypes> Eq for Variable<PT> {}
impl<PT: ProtocolTypes> PartialEq for Variable<PT> {
    fn eq(&self, other: &Self) -> bool {
        self.typ == other.typ && self.query == other.query
    }
}

impl<PT: ProtocolTypes> Clone for Variable<PT> {
    fn clone(&self) -> Self {
        Variable {
            unique_id: random(),
            resistant_id: self.resistant_id,
            typ: self.typ.clone(),
            query: self.query.clone(),
        }
    }
}

impl<PT: ProtocolTypes> Variable<PT> {
    pub fn new(typ: TypeShape<PT>, query: Query<PT::Matcher>) -> Self {
        Self {
            unique_id: random(),
            resistant_id: random(),
            typ,
            query,
        }
    }
}

impl<PT: ProtocolTypes> fmt::Display for Variable<PT> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}/{}", self.query, remove_prefix(self.typ.name))
    }
}

/// A function symbol with fixed arity and fixed types.
#[derive(Serialize, Deserialize, Debug)]
#[serde(bound = "PT: ProtocolTypes")]
pub struct Function<PT: ProtocolTypes> {
    /// Unique ID of this function. Uniqueness is guaranteed across all
    /// [`Term`](crate::algebra::Term)s ever created. Cloning change this ID.
    pub unique_id: u32,
    /// ID of this function. This id stays the same during cloning.
    pub resistant_id: u32,
    // #[serde(flatten)] not working: https://github.com/jamesmunns/postcard/issues/29
    fn_container: FnContainer<PT>,
}

impl<PT: ProtocolTypes> Eq for Function<PT> {}
impl<PT: ProtocolTypes> Hash for Function<PT> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.fn_container.hash(state)
    }
}

impl<PT: ProtocolTypes> PartialEq for Function<PT> {
    fn eq(&self, other: &Self) -> bool {
        self.fn_container == other.fn_container
    }
}

impl<PT: ProtocolTypes> Clone for Function<PT> {
    fn clone(&self) -> Self {
        Function {
            unique_id: random(),
            resistant_id: self.resistant_id,
            fn_container: self.fn_container.clone(),
        }
    }
}

impl<PT: ProtocolTypes> Function<PT> {
    pub fn attrs(&self) -> FunctionAttributes {
        self.fn_container.attrs
    }

    pub fn is_opaque(&self) -> bool {
        self.fn_container.attrs.is_opaque
    }

    pub fn is_list(&self) -> bool {
        self.fn_container.attrs.is_list
    }

    pub fn is_get(&self) -> bool {
        self.fn_container.attrs.is_get
    }

    pub fn no_gen(&self) -> bool {
        self.fn_container.attrs.no_gen
    }

    pub fn no_bit(&self) -> bool {
        self.fn_container.attrs.no_bit
    }

    #[must_use]
    pub fn new(shape: DynamicFunctionShape<PT>, dynamic_fn: Box<dyn DynamicFunction<PT>>) -> Self {
        let attrs = PT::signature()
            .attrs_by_name
            .get(shape.name)
            .map(|attrs| *attrs)
            .unwrap_or_default(); // Default to empty attributes, use Signature::new to provide attributes
        Self {
            unique_id: random(),
            resistant_id: random(),
            fn_container: FnContainer {
                shape,
                dynamic_fn,
                attrs,
            },
        }
    }

    #[must_use]
    pub fn arity(&self) -> u16 {
        self.fn_container.shape.arity()
    }

    #[must_use]
    pub fn is_constant(&self) -> bool {
        self.fn_container.shape.is_constant()
    }

    #[must_use]
    pub const fn name(&self) -> &'static str {
        self.fn_container.shape.name
    }

    #[must_use]
    pub const fn shape(&self) -> &DynamicFunctionShape<PT> {
        &self.fn_container.shape
    }

    #[must_use]
    pub fn dynamic_fn(&self) -> &dyn DynamicFunction<PT> {
        &self.fn_container.dynamic_fn
    }

    pub fn change_function(
        &mut self,
        shape: DynamicFunctionShape<PT>,
        dynamic_fn: Box<dyn DynamicFunction<PT>>,
    ) {
        self.fn_container.shape = shape;
        self.fn_container.dynamic_fn = dynamic_fn;
    }
}

impl<PT: ProtocolTypes> fmt::Display for Function<PT> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.fn_container.shape.fmt(f)
    }
}

mod fn_container {
    use std::fmt;
    use std::hash::{Hash, Hasher};

    use serde::de::{MapAccess, SeqAccess, Visitor};
    use serde::ser::SerializeStruct;
    use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

    use crate::algebra::dynamic_function::{
        DynamicFunction, DynamicFunctionShape, FunctionAttributes, TypeShape,
    };
    use crate::algebra::signature::Signature;
    use crate::protocol::ProtocolTypes;

    const NAME: &str = "name";
    const ARGUMENTS: &str = "arguments";
    const RETURN: &str = "return";
    const FIELDS: &[&str] = &[NAME, ARGUMENTS, RETURN];

    #[derive(Clone, Debug)]
    pub struct FnContainer<PT: ProtocolTypes> {
        pub shape: DynamicFunctionShape<PT>,
        pub dynamic_fn: Box<dyn DynamicFunction<PT>>,
        pub attrs: FunctionAttributes,
    }

    impl<PT: ProtocolTypes> Hash for FnContainer<PT> {
        fn hash<H: Hasher>(&self, state: &mut H) {
            self.shape.hash(state);
        }
    }

    impl<PT: ProtocolTypes> Eq for FnContainer<PT> {}
    impl<PT: ProtocolTypes> PartialEq for FnContainer<PT> {
        fn eq(&self, other: &Self) -> bool {
            // shape already identifies the function container
            self.shape == other.shape
        }
    }

    impl<PT: ProtocolTypes> Serialize for FnContainer<PT> {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let mut state = serializer.serialize_struct("FnContainer", FIELDS.len())?;
            state.serialize_field(NAME, &self.shape.name)?;
            state.serialize_field(ARGUMENTS, &self.shape.argument_types)?;
            state.serialize_field(RETURN, &self.shape.return_type)?;
            state.end()
        }
    }

    struct FnContainerVisitor<PT: ProtocolTypes> {
        signature: &'static Signature<PT>,
    }

    impl<'de, PT: ProtocolTypes> Visitor<'de> for FnContainerVisitor<PT> {
        type Value = FnContainer<PT>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("struct FnContainer")
        }

        fn visit_seq<V>(self, mut seq: V) -> Result<FnContainer<PT>, V::Error>
        where
            V: SeqAccess<'de>,
        {
            let name: &str = seq
                .next_element()?
                .ok_or_else(|| de::Error::invalid_length(0, &self))?;
            let argument_types: Vec<TypeShape<PT>> = seq
                .next_element()?
                .ok_or_else(|| de::Error::invalid_length(1, &self))?;
            let return_type: TypeShape<PT> = seq
                .next_element()?
                .ok_or_else(|| de::Error::invalid_length(2, &self))?;

            let (shape, dynamic_fn) = self
                .signature
                .functions_by_name
                .get(name)
                .ok_or_else(|| de::Error::custom(format!("could not find function {name}")))?;

            let attrs = self
                .signature
                .attrs_by_name
                .get(name)
                .map(|attrs| *attrs)
                .ok_or_else(|| de::Error::custom(format!("could not find function {name}")))?;

            if name != shape.name {
                return Err(de::Error::custom("Function<PT> name does not match!"));
            }

            if return_type != shape.return_type || argument_types != shape.argument_types {
                return Err(de::Error::custom(
                    "Return types or argument types do not match!",
                ));
            }

            Ok(FnContainer {
                shape: shape.clone(),
                dynamic_fn: dynamic_fn.clone(),
                attrs,
            })
        }

        fn visit_map<V>(self, mut map: V) -> Result<FnContainer<PT>, V::Error>
        where
            V: MapAccess<'de>,
        {
            let mut name: Option<&'de str> = None;
            let mut arguments: Option<Vec<TypeShape<PT>>> = None;
            let mut ret: Option<TypeShape<PT>> = None;
            while let Some(key) = map.next_key()? {
                match key {
                    NAME => {
                        if name.is_some() {
                            return Err(de::Error::duplicate_field(NAME));
                        }
                        name = Some(map.next_value()?);
                    }
                    ARGUMENTS => {
                        if arguments.is_some() {
                            return Err(de::Error::duplicate_field(ARGUMENTS));
                        }
                        arguments = Some(map.next_value()?);
                    }
                    RETURN => {
                        if ret.is_some() {
                            return Err(de::Error::duplicate_field(RETURN));
                        }
                        ret = Some(map.next_value()?);
                    }
                    _ => {
                        return Err(de::Error::unknown_field(key, FIELDS));
                    }
                }
            }

            let name = name.ok_or_else(|| de::Error::missing_field(NAME))?;
            let (shape, dynamic_fn) =
                self.signature.functions_by_name.get(name).ok_or_else(|| {
                    de::Error::custom(format!(
                        "Failed to link function symbol: Could not find function {name}"
                    ))
                })?;
            let attrs = self
                .signature
                .attrs_by_name
                .get(name)
                .map(|attrs| *attrs)
                .ok_or_else(|| {
                    de::Error::custom(format!(
                        "Failed to link function symbol: Could not find function {name}"
                    ))
                })?;

            let argument_types = arguments.ok_or_else(|| de::Error::missing_field(ARGUMENTS))?;
            let return_type = ret.ok_or_else(|| de::Error::missing_field(RETURN))?;

            if name != shape.name {
                return Err(de::Error::custom("Function<PT> name does not match!"));
            }

            if return_type != shape.return_type || argument_types != shape.argument_types {
                return Err(de::Error::custom(
                    "Return types or argument types do not match!",
                ));
            }

            Ok(FnContainer {
                shape: shape.clone(),
                dynamic_fn: dynamic_fn.clone(),
                attrs,
            })
        }
    }

    impl<'de, PT: ProtocolTypes> Deserialize<'de> for FnContainer<PT> {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            deserializer.deserialize_struct(
                "FnContainer",
                FIELDS,
                FnContainerVisitor {
                    signature: PT::signature(),
                },
            )
        }
    }
}
