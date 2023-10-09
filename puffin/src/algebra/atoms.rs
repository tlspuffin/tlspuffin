//! This module provides an enum for terms. A term can either be a Variable or a Function.
//! This also implements the serializability of terms.
//!
use std::{
    fmt,
    fmt::Formatter,
    hash::{Hash, Hasher},
};
use log::error;

use rand::random;
use serde::{Deserialize, Serialize};

use crate::{
    algebra::{
        atoms::fn_container::FnContainer,
        dynamic_function::{DynamicFunction, DynamicFunctionShape, TypeShape},
        remove_prefix, Matcher,
    },
    trace::Query,
};

/// A variable symbol with fixed type.
#[derive(Serialize, Deserialize, Debug)]
pub struct Variable<M> {
    /// Unique ID of this variable. Uniqueness is guaranteed across all[`Term`]sever created. Cloning
    /// change this ID.
    pub unique_id: u32,
    /// ID of this variable. This id stays the same during cloning.
    pub resistant_id: u32,
    pub typ: TypeShape,
    /// The struct which holds information about how to query this variable from knowledge
    pub query: Query<M>,
}

impl<M: Matcher> Hash for Variable<M> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.typ.hash(state);
        self.query.hash(state);
    }
}

impl<M: Matcher> Eq for Variable<M> {}
impl<M: Matcher> PartialEq for Variable<M> {
    fn eq(&self, other: &Self) -> bool {
        self.typ == other.typ && self.query == other.query
    }
}

impl<M: Matcher> Clone for Variable<M> {
    fn clone(&self) -> Self {
        Variable {
            unique_id: random(),
            resistant_id: self.resistant_id,
            typ: self.typ,
            query: self.query.clone(),
        }
    }
}

impl<M: Matcher> Variable<M> {
    pub fn new(typ: TypeShape, query: Query<M>) -> Self {
        Self {
            unique_id: random(),
            resistant_id: random(),
            typ,
            query,
        }
    }
}

impl<M: Matcher> fmt::Display for Variable<M> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}/{}", self.query, remove_prefix(self.typ.name))
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
    // #[serde(flatten)] not working: https://github.com/jamesmunns/postcard/issues/29
    fn_container: FnContainer,
}

impl Eq for Function {}
impl Hash for Function {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.fn_container.hash(state)
    }
}
impl PartialEq for Function {
    fn eq(&self, other: &Self) -> bool {
        self.fn_container == other.fn_container
    }
}

impl Clone for Function {
    fn clone(&self) -> Self {
        Function {
            unique_id: random(),
            resistant_id: self.resistant_id,
            fn_container: self.fn_container.clone(),
        }
    }
}

impl Function {
    /// Does the function symbol computes "opaque" message such as encryption, signature, MAC, AEAD, etc?
    pub fn is_opaque(&self) -> bool {
        // TODO: have protocol-dependent implementation for this
        // debug!("Name: {}", self.fn_container.shape.name);
        self.fn_container.shape.name == "tlspuffin::tls::fn_impl::fn_utils::fn_encrypt_handshake" //TODO
        || self.fn_container.shape.name == "tlspuffin::tls::fn_impl::fn_utils::fn_encrypt12"
        || self.fn_container.shape.name == "tlspuffin::tls::fn_impl::fn_utils::fn_derive_binder"
        || self.fn_container.shape.name == "tlspuffin::tls::fn_impl::fn_utils::fn_derive_psk"
        || self.fn_container.shape.name == "tlspuffin::tls::fn_impl::fn_fields::fn_get_any_client_curve"
        || self.fn_container.shape.name == "tlspuffin::tls::fn_impl::fn_utils::fn_decode_ecdh_pubkey"
        // || self.fn_container.shape.name == "tlspuffin::tls::fn_impl::fn_cert::fn_get_context"
            || self.fn_container.shape.name == "tlspuffin::tls::fn_impl::fn_utils::fn_new_pubkey12"
            || self.fn_container.shape.name == "tlspuffin::tls::fn_impl::fn_cert::fn_rsa_sign_server"
            || self.fn_container.shape.name == "tlspuffin::tls::fn_impl::fn_cert::fn_rsa_sign_client"
    }

    /// Does the function symbol computes a list such as fn_append_certificate?
    pub fn is_list(&self) -> bool {
        // TODO: have protocol-dependent implementation for this
        // debug!("Name: {}", self.fn_container.shape.name);
        self.fn_container.shape.name.contains("_append")
    }

    pub fn new(shape: DynamicFunctionShape, dynamic_fn: Box<dyn DynamicFunction>) -> Self {
        Self {
            unique_id: random(),
            resistant_id: random(),
            fn_container: FnContainer { shape, dynamic_fn },
        }
    }

    pub fn arity(&self) -> u16 {
        self.fn_container.shape.arity()
    }

    pub fn is_constant(&self) -> bool {
        self.fn_container.shape.is_constant()
    }

    pub fn name<'a>(&'a self) -> &'static str {
        self.fn_container.shape.name
    }

    pub fn shape(&self) -> &DynamicFunctionShape {
        &self.fn_container.shape
    }

    pub fn dynamic_fn(&self) -> &dyn DynamicFunction {
        &self.fn_container.dynamic_fn
    }

    pub fn change_function(
        &mut self,
        shape: DynamicFunctionShape,
        dynamic_fn: Box<dyn DynamicFunction>,
    ) {
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
    use std::{
        fmt,
        hash::{Hash, Hasher},
    };

    use serde::{
        de,
        de::{MapAccess, SeqAccess, Visitor},
        ser::SerializeStruct,
        Deserialize, Deserializer, Serialize, Serializer,
    };

    use crate::algebra::{
        deserialize_signature,
        dynamic_function::{DynamicFunction, DynamicFunctionShape, TypeShape},
        signature::Signature,
    };

    const NAME: &str = "name";
    const ARGUMENTS: &str = "arguments";
    const RETURN: &str = "return";
    const FIELDS: &[&str] = &[NAME, ARGUMENTS, RETURN];

    #[derive(Clone, Debug)]
    pub struct FnContainer {
        pub shape: DynamicFunctionShape,
        pub dynamic_fn: Box<dyn DynamicFunction>,
    }

    impl Hash for FnContainer {
        fn hash<H: Hasher>(&self, state: &mut H) {
            self.shape.hash(state)
        }
    }

    impl Eq for FnContainer {}
    impl PartialEq for FnContainer {
        fn eq(&self, other: &Self) -> bool {
            // shape already identifies the function container
            self.shape == other.shape
        }
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

    struct FnContainerVisitor {
        signature: &'static Signature,
    }

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
            let argument_types: Vec<TypeShape> = seq
                .next_element()?
                .ok_or_else(|| de::Error::invalid_length(1, &self))?;
            let return_type: TypeShape = seq
                .next_element()?
                .ok_or_else(|| de::Error::invalid_length(2, &self))?;

            let (shape, dynamic_fn) =
                self.signature.functions_by_name.get(name).ok_or_else(|| {
                    de::Error::custom(format!("could not find function {}", name))
                })?;

            if name != shape.name {
                return Err(de::Error::custom("Function name does not match!"));
            }

            if return_type != shape.return_type || argument_types != shape.argument_types {
                return Err(de::Error::custom(
                    "Return types or argument types do not match!",
                ));
            }

            Ok(FnContainer {
                shape: shape.clone(),
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
                self.signature.functions_by_name.get(name).ok_or_else(|| {
                    de::Error::custom(format!(
                        "Failed to link function symbol: Could not find function {}",
                        name
                    ))
                })?;

            let argument_types = arguments.ok_or_else(|| de::Error::missing_field(ARGUMENTS))?;
            let return_type = ret.ok_or_else(|| de::Error::missing_field(RETURN))?;

            if name != shape.name {
                return Err(de::Error::custom("Function name does not match!"));
            }

            if return_type != shape.return_type || argument_types != shape.argument_types {
                return Err(de::Error::custom(
                    "Return types or argument types do not match!",
                ));
            }

            Ok(FnContainer {
                shape: shape.clone(),
                dynamic_fn: dynamic_fn.clone(),
            })
        }
    }

    impl<'de> Deserialize<'de> for FnContainer {
        fn deserialize<D>(deserializer: D) -> Result<FnContainer, D::Error>
        where
            D: Deserializer<'de>,
        {
            deserializer.deserialize_struct(
                "FnContainer",
                FIELDS,
                FnContainerVisitor {
                    signature: deserialize_signature(),
                },
            )
        }
    }
}
