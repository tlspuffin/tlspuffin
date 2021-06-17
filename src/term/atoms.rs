//! This module provides an enum for terms. A term can either be a Variable or a Function.
//! This also implements the serializability of terms.
//!
use std::{fmt, fmt::Formatter};

use serde::{Deserialize, Serialize};

use crate::term::atoms::fn_container::FnContainer;
use crate::{
    term::{
        dynamic_function::{DynamicFunction, DynamicFunctionShape, TypeShape},
    },
    trace::ObservedId,
};
use rand::random;
use crate::term::remove_prefix;

/// A variable symbol with fixed type.
#[derive(Serialize, Deserialize, Debug)]
pub struct Variable {
    /// Unique ID of this variable. Uniqueness is guaranteed across all[`Term`]sever created. Cloning
    /// change this ID.
    pub unique_id: u32,
    /// ID of this variable. This id stays the same during cloning.
    pub resistant_id: u32,
    pub typ: TypeShape,
    pub observed_id: ObservedId,
}

impl Clone for Variable {
    fn clone(&self) -> Self {
        Variable {
            unique_id: random(),
            resistant_id: self.resistant_id,
            typ: self.typ.clone(),
            observed_id: self.observed_id.clone()
        }
    }
}

impl Variable {
    pub fn new(type_shape: TypeShape, observed_id: ObservedId) -> Self {
        Self {
            unique_id: random(),
            resistant_id: random(),
            typ: type_shape,
            observed_id,
        }
    }
}

impl fmt::Display for Variable {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "({},{})/{}", self.observed_id.0, self.observed_id.1, remove_prefix(self.typ.name))
    }
}

/// A function symbol with fixed arity and fixed types.
#[derive(Serialize, Deserialize, Debug)]
pub struct Function {
    /// Unique ID of this function. Uniqueness is guaranteed across all[`Term`]sever created. Cloning
    /// change this ID.
    pub unique_id: u32,
    /// ID of this function. This id stays the same during cloning.
    pub resistant_id: u32,
    // #[serde(flatten)] todo, not working: https://github.com/jamesmunns/postcard/issues/29
    fn_container: FnContainer,
}

impl Clone for Function {
    fn clone(&self) -> Self {
        Function {
            unique_id: random(),
            resistant_id: self.resistant_id,
            fn_container: self.fn_container.clone()
        }
    }
}

impl Function {
    pub fn new(
        shape: DynamicFunctionShape,
        dynamic_fn: Box<dyn DynamicFunction>,
    ) -> Self {
        Self {
            unique_id: random(),
            resistant_id: random(),
            fn_container: FnContainer { shape, dynamic_fn },
        }
    }

    pub fn arity(&self) -> u16 {
        self.fn_container.shape.arity()
    }

    pub fn name(&self) -> &str {
        self.fn_container.shape.name.as_str()
    }

    pub fn shape(&self) -> &DynamicFunctionShape {
        &self.fn_container.shape
    }

    pub fn dynamic_fn(&self) -> &Box<dyn DynamicFunction> {
        &self.fn_container.dynamic_fn
    }

    pub fn change_function(&mut self, shape: DynamicFunctionShape, dynamic_fn: Box<dyn DynamicFunction>) {
        self.fn_container.shape = shape;
        self.fn_container.dynamic_fn = dynamic_fn;
    }
}

impl fmt::Display for Function {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.fn_container.shape.fmt(f)
    }
}

mod fn_container {
    use std::fmt;

    use serde::de::{MapAccess, SeqAccess, Visitor};
    use serde::ser::SerializeStruct;
    use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

    use crate::term::dynamic_function::{DynamicFunction, DynamicFunctionShape, TypeShape};
    use crate::tls::SIGNATURE;

    const NAME: &str = "name";
    const ARGUMENTS: &str = "arguments";
    const RETURN: &str = "return";
    const FIELDS: &[&str] = &["name", "arguments", "return"];

    #[derive(Clone, Debug)]
    pub struct FnContainer {
        pub shape: DynamicFunctionShape,
        pub dynamic_fn: Box<dyn DynamicFunction>,
    }

    impl Serialize for FnContainer {
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

    struct FnContainerVisitor;

    impl<'de> Visitor<'de> for FnContainerVisitor {
        type Value = FnContainer;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("struct FnContainer")
        }

        fn visit_seq<V>(self, mut seq: V) -> Result<FnContainer, V::Error>
            where
                V: SeqAccess<'de>,
        {
            let name: &str = seq
                .next_element()?
                .ok_or_else(|| de::Error::invalid_length(0, &self))?;
            let argument_types = seq
                .next_element()?
                .ok_or_else(|| de::Error::invalid_length(1, &self))?;
            let return_type = seq
                .next_element()?
                .ok_or_else(|| de::Error::invalid_length(2, &self))?;

            let (shape, dynamic_fn) =
                SIGNATURE
                    .functions_by_name
                    .get(name)
                    .ok_or_else( || {
                        // panic!("Could not find fn: {}", name);
                        de::Error::custom(format!(
                            "could not find function {}",
                            name
                        ))
                    })?;

            if return_type != shape.return_type || argument_types != shape.argument_types {
                // panic!("Return types or argument types do not match!");
                return Err(de::Error::custom("Return types or argument types do not match!"));
            }

            Ok(FnContainer {
                shape: DynamicFunctionShape {
                    name: name.to_string(),
                    argument_types,
                    return_type,
                },
                dynamic_fn: dynamic_fn.clone(),
            })
        }

        fn visit_map<V>(self, mut map: V) -> Result<FnContainer, V::Error>
            where
                V: MapAccess<'de>,
        {
            let mut name: Option<&'de str> = None;
            let mut arguments: Option<Vec<TypeShape>> = None;
            let mut ret: Option<TypeShape> = None;
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
                SIGNATURE
                    .functions_by_name
                    .get(name)
                    .ok_or(de::Error::custom(format!(
                        "Failed to link function symbol: Could not find function {}",
                        name
                    )))?;

            let argument_types =
                arguments.ok_or_else(|| de::Error::missing_field(ARGUMENTS))?;
            let return_type = ret.ok_or_else(|| de::Error::missing_field(RETURN))?;

            if return_type != shape.return_type || argument_types != shape.argument_types {
                // panic!("Return types or argument types do not match!");
                return Err(de::Error::custom("Return types or argument types do not match!"));
            }

            Ok(FnContainer {
                shape: DynamicFunctionShape {
                    name: name.to_string(),
                    argument_types,
                    return_type,
                },
                dynamic_fn: dynamic_fn.clone(),
            })
        }
    }

    impl<'de> Deserialize<'de> for FnContainer {
        fn deserialize<D>(deserializer: D) -> Result<FnContainer, D::Error>
        where
            D: Deserializer<'de>,
        {
            deserializer.deserialize_struct("FnContainer", FIELDS, FnContainerVisitor)
        }
    }
}
