use std::{fmt, fmt::Formatter};

use serde::{Deserialize, Serialize};

use crate::term::atoms::fn_container::FnContainer;
use crate::{
    term::{
        type_helper::{DynamicFunction, DynamicFunctionShape},
        TypeShape,
    },
    trace::ObservedId,
};

/// A symbol for an unspecified term.
///
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Variable {
    pub id: u32,
    pub type_shape: TypeShape,
    pub observed_id: ObservedId,
}

impl Variable {
    pub fn new(id: u32, type_shape: TypeShape, observed_id: ObservedId) -> Self {
        Self {
            id,
            type_shape,
            observed_id,
        }
    }
}

impl fmt::Display for Variable {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "var<{}>", self.type_shape)
    }
}

/// A symbol with fixed arity.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Function {
    pub id: u32,
    fn_container: FnContainer,
}

impl Function {
    pub fn new(id: u32, shape: DynamicFunctionShape, dynamic_fn: Box<dyn DynamicFunction>) -> Self {
        Self {
            id,
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
}

mod fn_container {
    use std::fmt;

    use serde::de::{MapAccess, SeqAccess, Visitor};
    use serde::ser::SerializeStruct;
    use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

    use crate::term::{DynamicFunction, DynamicFunctionShape, TypeShape};
    use crate::tls::REGISTERED_FN;

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

    impl<'de> Deserialize<'de> for FnContainer {
        fn deserialize<D>(deserializer: D) -> Result<FnContainer, D::Error>
        where
            D: Deserializer<'de>,
        {
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

                    let (_shape, dynamic_fn) = REGISTERED_FN.get(name).ok_or(de::Error::custom(
                        format!("could not find function {}", name),
                    ))?;
                    // todo check if shape matches
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
                    let (_shape, dynamic_fn) =
                        REGISTERED_FN.get(name).ok_or(de::Error::custom(format!(
                            "Failed to link function symbol: Could not find function {}",
                            name
                        )))?;
                    // todo check if shape matches
                    let argument_types =
                        arguments.ok_or_else(|| de::Error::missing_field(ARGUMENTS))?;
                    let return_type = ret.ok_or_else(|| de::Error::missing_field(RETURN))?;
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
            deserializer.deserialize_struct("FnContainer", FIELDS, FnContainerVisitor)
        }
    }
}
