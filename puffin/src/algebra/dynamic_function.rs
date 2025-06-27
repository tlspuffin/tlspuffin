//! This module provides traits for calling rust functions dynamically.
//!
//! All functions which implement the `DynamicFunction` trait can be called by passing an array of
//! [`EvaluatedTerm`]s to it. The return value is again of type [`EvaluatedTerm`].
//!
//! Rust is a statically typed language. That means the compiler would be able to statically verify
//! that a term evaluates without any type errors.
//!
//! While this is generally an advance, in the case of our fuzzer this is not very helpful.
//! The fuzzer should be able to mutate the term trees arbitrarily. Of course, we also have
//! to check for the types during runtime. If types are not compatible then, the evaluation
//! of the term will fail. But this is not something that can be done during compile time.
//! Therefore, we introduced a trait for dynamically typed functions on top of statically
//! typed Rust functions.
//!
//! Each function which implements the following trait can be made into a dynamic function:
//!
//! ```rust
//! use puffin::algebra::error::FnError;
//!
//! type ConcreteFunction<A1, A2, A3, R> = dyn Fn(A1, A2, A3) -> Result<R, FnError>;
//! ```
//!
//! where `A1`, `A2`, `A3` are argument types and `R` is the return type. From these statically
//! typed function we can generate dynamically types ones which implement the following trait:
//!
//! ```rust
//! use std::any::Any;
//!
//! use puffin::algebra::error::FnError;
//! use puffin::protocol::{EvaluatedTerm, ProtocolTypes};
//!
//! pub trait DynamicFunction<PT: ProtocolTypes>:
//!     Fn(&Vec<Box<dyn EvaluatedTerm<PT>>>) -> Result<Box<dyn EvaluatedTerm<PT>>, FnError>
//! {
//! }
//! ```
//!
//! Note, that both functions return a `Result` and therefore can gracefully fail.
//!
//! `DynamicFunctions` can be called with an array of any type implementing the `EvaluatedTerm`
//! trait. The result must also implement `EvaluatedTerm`. Rust offers a unique ID for each type.
//! Using this type we can check during runtime whether types are available. The types of each
//! variable, constant and function are preserved and stored alongside the `DynamicFunction`.
//!
//! The following function is a simple example for a constant:
//!
//! ```rust
//! use puffin::algebra::error::FnError;
//!
//! pub fn fn_some_value() -> Result<u32, FnError> {
//!     Ok(42)
//! }
//! ```
//!
//! It returns one possibility for the cipher suites which could be sent during a `ClientHello`.
use std::any::{type_name, TypeId};
use std::collections::hash_map::DefaultHasher;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::marker::PhantomData;

use itertools::Itertools;
use serde::de::Visitor;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

use super::error::FnError;
use crate::protocol::{EvaluatedTerm, ProtocolTypes};

/// Describes the attributes of a [`DynamicFunction`]
#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub struct FunctionAttributes {
    /// Whether the function symbol computes "opaque" message such as encryption, signature,
    /// MAC, AEAD, Formally: all symbols whose concretization does not contain a single
    /// conretization of its arguments
    pub is_opaque: bool,
    /// Whether the function symbol computes a list such as `fn_append_certificate`.
    pub is_list: bool,
    /// Whether the function symbol computes a strict sub-term (accessed function symbols).
    /// Incidentally, its concretization does not contain all the conretizations of its arguments.
    /// Examples: `fn_get_server_key_share`.
    pub is_get: bool,
    /// Whether we usually fail and thus prevent from trying to generate terms with that function
    /// symbols at top-level. This will reduce the scope of the GenerateMutator.
    pub no_gen: bool,
    /// Symbols we will never MakeMessage on, thus disabling applying any of the bit-level
    /// mutations.
    pub no_bit: bool,
}
// TODO: add a uni test for making sure the given attributes are correct

impl Default for FunctionAttributes {
    fn default() -> Self {
        Self {
            is_opaque: false,
            is_list: false,
            is_get: false,
            no_gen: false,
            no_bit: false,
        }
    }
}

/// Describes the shape of a [`DynamicFunction`]
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(bound = "PT: ProtocolTypes")]
pub struct DynamicFunctionShape<PT: ProtocolTypes> {
    pub name: &'static str,
    pub argument_types: Vec<TypeShape<PT>>,
    pub return_type: TypeShape<PT>,
}

impl<PT: ProtocolTypes> Eq for DynamicFunctionShape<PT> {}
impl<PT: ProtocolTypes> PartialEq for DynamicFunctionShape<PT> {
    fn eq(&self, other: &Self) -> bool {
        self.name.eq(other.name) // name is unique
    }
}

impl<PT: ProtocolTypes> Hash for DynamicFunctionShape<PT> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.name.hash(state);
    }
}

impl<PT: ProtocolTypes> DynamicFunctionShape<PT> {
    #[must_use]
    pub fn arity(&self) -> u16 {
        self.argument_types.len() as u16
    }

    #[must_use]
    pub fn is_constant(&self) -> bool {
        self.arity() == 0
    }
}

impl<PT: ProtocolTypes> fmt::Display for DynamicFunctionShape<PT> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}({}) -> {}",
            self.name,
            self.argument_types
                .iter()
                .map(|typ| typ.name.to_string())
                .join(","),
            self.return_type.name
        )
    }
}

/// Hashes [`TypeId`]s to be more readable
fn hash_type_id(type_id: &TypeId) -> u64 {
    let mut hasher = DefaultHasher::new();
    type_id.hash(&mut hasher);
    hasher.finish()
}

fn format_args<PT: ProtocolTypes, P: AsRef<dyn EvaluatedTerm<PT>>>(anys: &[P]) -> String {
    format!(
        "({})",
        anys.iter()
            .map(|any| {
                let id = &any.as_ref().as_any().type_id();
                format!("{:x}", hash_type_id(id))
            })
            .join(",")
    )
}

/// Cloneable type for dynamic functions. This trait is automatically implemented for arbitrary
/// closures and functions of the form: `Fn(&Vec<Box<dyn Any>>) -> Box<dyn Any>`
///
/// [`Clone`] is implemented for `Box<dyn DynamicFunction>` using this trick:
/// <https://users.rust-lang.org/t/how-to-clone-a-boxed-closure/31035/25>
///
/// We want to use Any here and not `VariableData` (which implements Clone). Else all returned types
/// in functions `op_impl.rs` would need to return a cloneable struct. Message for example is not.
pub trait DynamicFunction<PT: ProtocolTypes>:
    Fn(&Vec<Box<dyn EvaluatedTerm<PT>>>) -> Result<Box<dyn EvaluatedTerm<PT>>, FnError> + Send + Sync
{
    fn clone_box(&self) -> Box<dyn DynamicFunction<PT>>;
}

impl<F, PT: ProtocolTypes> DynamicFunction<PT> for F
where
    F: 'static
        + Fn(&Vec<Box<dyn EvaluatedTerm<PT>>>) -> Result<Box<dyn EvaluatedTerm<PT>>, FnError>
        + Clone
        + Send
        + Sync,
{
    fn clone_box(&self) -> Box<dyn DynamicFunction<PT>> {
        Box::new(self.clone())
    }
}

impl<PT: ProtocolTypes> fmt::Debug for Box<dyn DynamicFunction<PT>> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DynamicFunction")
    }
}

impl<PT: ProtocolTypes> fmt::Display for Box<dyn DynamicFunction<PT>> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "DynamicFunction")
    }
}

impl<PT: ProtocolTypes> Clone for Box<dyn DynamicFunction<PT>> {
    fn clone(&self) -> Self {
        (**self).clone_box()
    }
}

/// This trait is implemented for function traits in order to:
/// * describe their shape during runtime
/// * wrap them into a [`DynamicFunction`] which is callable with arbitrary data
///
/// Adapted from <https://jsdw.me/posts/rust-fn-traits/> but using type ids
pub trait DescribableFunction<PT: ProtocolTypes, Types> {
    fn name(&'static self) -> &'static str;
    fn shape() -> DynamicFunctionShape<PT>;
    fn make_dynamic(&'static self) -> Box<dyn DynamicFunction<PT>>;
}

macro_rules! dynamic_fn {
    ($($arg:ident)* => $res:ident) => (
    impl<F,PT : ProtocolTypes, $res: 'static, $($arg: 'static),*>
        DescribableFunction<PT, ($res, $($arg),*)> for F
    where
        F: (Fn($(&$arg),*)  -> Result<$res, FnError>) + Send + Sync,
        $res: Send + Sync,
        R: EvaluatedTerm<PT>,
        $($arg: Send + Sync),*
    {
        fn shape() -> DynamicFunctionShape<PT> {
            DynamicFunctionShape::<PT> {
                name: std::any::type_name::<F>(),
                argument_types: vec![$(TypeShape::<PT>::of::<$arg>()),*],
                return_type: TypeShape::<PT>::of::<$res>(),
            }
        }

        fn name(&'static self) -> &'static str {
            std::any::type_name::<F>()
        }

        fn make_dynamic(&'static self) -> Box<dyn DynamicFunction<PT>> {
            #[allow(unused_variables)]
            Box::new(move |args: &Vec<Box<dyn EvaluatedTerm<PT>>>| {
                #[allow(unused_mut)]
                let mut index = 0;

                let result: Result<$res, FnError> = self($(
                       #[allow(unused_assignments)]
                       #[allow(clippy::mixed_read_write_in_expression)]
                       {
                           if let Some(arg_) = args.get(index)
                                    .ok_or_else(|| {
                                        let shape = Self::shape();
                                        FnError::Malformed(format!("Missing argument #{} while calling {}.", index + 1, shape.name))
                                    })?
                                    .as_any().downcast_ref::<$arg>() {
                               index += 1;
                               arg_
                           } else {
                               let shape = Self::shape();
                               return Err(FnError::Malformed(format!(
                                    "Passed argument #{} of {} did not match the shape {}. Hashes of passed types are {}.",
                                    index + 1,
                                    shape.name,
                                    shape,
                                    format_args(args)
                               )));
                           }
                       }
                ),*);

                result.map(|result| Box::new(result) as Box<dyn EvaluatedTerm<PT>>)
            })
        }
    }
    )
}

dynamic_fn!( => R);
dynamic_fn!(T1 => R);
dynamic_fn!(T1 T2 => R);
dynamic_fn!(T1 T2 T3 => R);
dynamic_fn!(T1 T2 T3 T4 => R);
dynamic_fn!(T1 T2 T3 T4 T5 => R);
dynamic_fn!(T1 T2 T3 T4 T5 T6 => R);
dynamic_fn!(T1 T2 T3 T4 T5 T6 T7 => R);
dynamic_fn!(T1 T2 T3 T4 T5 T6 T7 T8 => R);
dynamic_fn!(T1 T2 T3 T4 T5 T6 T7 T8 T9 => R);
dynamic_fn!(T1 T2 T3 T4 T5 T6 T7 T8 T9 T10 => R);

pub fn make_dynamic<F: 'static, PT: ProtocolTypes, Types>(
    f: &'static F,
) -> (DynamicFunctionShape<PT>, Box<dyn DynamicFunction<PT>>)
where
    F: DescribableFunction<PT, Types>,
{
    (F::shape(), f.make_dynamic())
}

#[derive(Copy, Clone, Debug)]
pub struct TypeShape<PT: ProtocolTypes> {
    inner_type_id: TypeId,
    pub name: &'static str,
    phantom: PhantomData<PT>,
}

impl<PT: ProtocolTypes> TypeShape<PT> {
    #[must_use]
    pub fn of<T: 'static>() -> Self {
        Self {
            inner_type_id: TypeId::of::<T>(),
            name: type_name::<T>(),
            phantom: PhantomData,
        }
    }
}

impl<PT: ProtocolTypes> From<TypeShape<PT>> for TypeId {
    fn from(shape: TypeShape<PT>) -> Self {
        shape.inner_type_id
    }
}

impl<PT: ProtocolTypes> Eq for TypeShape<PT> {}
impl<PT: ProtocolTypes> PartialEq for TypeShape<PT> {
    fn eq(&self, other: &Self) -> bool {
        self.inner_type_id == other.inner_type_id
    }
}

impl<PT: ProtocolTypes> Hash for TypeShape<PT> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.inner_type_id.hash(state);
    }
}

impl<PT: ProtocolTypes> fmt::Display for TypeShape<PT> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name)
    }
}

impl<PT: ProtocolTypes> Serialize for TypeShape<PT> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.name)
    }
}

impl<'de, PT: ProtocolTypes> Deserialize<'de> for TypeShape<PT> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct TypeShapeVisitor<PT: ProtocolTypes>(PhantomData<PT>);

        impl<'de, PT: ProtocolTypes> Visitor<'de> for TypeShapeVisitor<PT> {
            type Value = TypeShape<PT>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a TypeShape")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let typ = PT::signature()
                    .types_by_name
                    .get(v)
                    .ok_or_else(|| de::Error::missing_field("could not find type"))?;
                Ok(typ.clone())
            }
        }

        deserializer.deserialize_str(TypeShapeVisitor(PhantomData))
    }
}
