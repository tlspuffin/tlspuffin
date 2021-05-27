use std::{fmt, fmt::Formatter};

use serde::de::{MapAccess, SeqAccess, Visitor};
use serde::ser::SerializeStruct;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

use crate::term::make_dynamic;
use crate::term::op_impl::{op_certificate, OP_FUNCTIONS};
use crate::{
    term::{
        type_helper::{DynamicFunction, DynamicFunctionShape},
        TypeShape,
    },
    trace::ObservedId,
};

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
    id: u32,
    fn_container: FnContainer,
}

impl Operator {
    pub(crate) fn new(
        id: u32,
        shape: DynamicFunctionShape,
        dynamic_fn: Box<dyn DynamicFunction>,
    ) -> Operator {
        Self {
            id,
            fn_container: FnContainer { shape, dynamic_fn },
        }
    }
}

#[derive(Clone, Debug)]
struct FnContainer {
    shape: DynamicFunctionShape,
    dynamic_fn: Box<dyn DynamicFunction>,
}

const FN_CONTAINER_FIELDS: &[&str] = &["name", "arguments", "return"];

impl Serialize for FnContainer {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("FnContainer", FN_CONTAINER_FIELDS.len())?;
        state.serialize_field("name", &self.shape.name)?;
        state.serialize_field("arguments", &self.shape.argument_types)?;
        state.serialize_field("return", &self.shape.return_type)?;
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

                let (shape, dynamic_fn) = OP_FUNCTIONS
                    .get(name)
                    .ok_or(de::Error::missing_field("could not find function"))?;
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
                        "name" => {
                            if name.is_some() {
                                return Err(de::Error::duplicate_field("name"));
                            }
                            name = Some(map.next_value()?);
                        }
                        "arguments" => {
                            if arguments.is_some() {
                                return Err(de::Error::duplicate_field("arguments"));
                            }
                            arguments = Some(map.next_value()?);
                        }
                        "return" => {
                            if ret.is_some() {
                                return Err(de::Error::duplicate_field("return"));
                            }
                            ret = Some(map.next_value()?);
                        }
                        _ => {
                            return Err(de::Error::unknown_field(key, FN_CONTAINER_FIELDS));
                        }
                    }
                }

                let name = name.ok_or_else(|| de::Error::missing_field("name"))?;
                let (shape, dynamic_fn) = OP_FUNCTIONS
                    .get(name)
                    .ok_or(de::Error::missing_field("could not find function"))?;
                // todo check if shape matches
                let argument_types =
                    arguments.ok_or_else(|| de::Error::missing_field("arguments"))?;
                let return_type = ret.ok_or_else(|| de::Error::missing_field("return"))?;
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
        deserializer.deserialize_struct("FnContainer", FN_CONTAINER_FIELDS, FnContainerVisitor)
    }
}

impl Operator {
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

    /// Serialize an `Operator`.
    pub fn display(&self) -> String {
        format!("{}", self.name())
    }
}
