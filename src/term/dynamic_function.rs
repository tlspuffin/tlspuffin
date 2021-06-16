use std::{
    any::{type_name, Any, TypeId},
    collections::hash_map::DefaultHasher,
    fmt,
    fmt::Formatter,
    hash::{Hash, Hasher},
};

use itertools::Itertools;
use serde::{de, de::Visitor, Deserialize, Deserializer, Serialize, Serializer};

use crate::tls::{SIGNATURE, error::FnError};

/// Describes the shape of a [`DynamicFunction`]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DynamicFunctionShape {
    pub name: String,
    pub argument_types: Vec<TypeShape>,
    pub return_type: TypeShape,
}

impl DynamicFunctionShape {
    pub fn arity(&self) -> u16 {
        self.argument_types.len() as u16
    }
}

impl fmt::Display for DynamicFunctionShape {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}({}) -> {}",
            self.name,
            self.argument_types
                .iter()
                .map(|typ| format!("{}", typ.name))
                .join(","),
            self.return_type.name
        )
    }
}

/// Hashes [`TypeId`]s to be more readable
///
fn hash_type_id(type_id: &TypeId) -> u64 {
    let mut hasher = DefaultHasher::new();
    type_id.hash(&mut hasher);
    hasher.finish()
}

pub fn format_args<P: AsRef<dyn Any>>(anys: &[P]) -> String {
    format!(
        "({})",
        anys.iter()
            .map(|any| {
                let id = any.as_ref().type_id().clone();
                format!("{:x}", hash_type_id(&id))
            })
            .join(",")
    )
}

// The type of dynamically typed functions is:

/// Cloneable type for dynamic functions. This trait is automatically implemented for arbitrary
/// closures and functions of the form: `Fn(&Vec<Box<dyn Any>>) -> Box<dyn Any>`
///
/// [`Clone`] is implemented for `Box<dyn DynamicFunction>` using this trick:
/// https://users.rust-lang.org/t/how-to-clone-a-boxed-closure/31035/25
///
/// We want to use Any here and not VariableData (which implements Clone). Else all returned types
/// in functions op_impl.rs would need to return a cloneable struct. Message for example is not.
pub trait DynamicFunction: Fn(&Vec<Box<dyn Any>>) -> Result<Box<dyn Any>, FnError> + Send + Sync {
    fn clone_box(&self) -> Box<dyn DynamicFunction>;
}

impl<T> DynamicFunction for T
where
    T: 'static + Fn(&Vec<Box<dyn Any>>) ->  Result<Box<dyn Any>, FnError> + Clone + Send + Sync,
{
    fn clone_box(&self) -> Box<dyn DynamicFunction> {
        Box::new(self.clone())
    }
}

impl fmt::Debug for Box<dyn DynamicFunction> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "DynamicFunction")
    }
}

impl fmt::Display for Box<dyn DynamicFunction> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DynamicFunction")
    }
}

impl Clone for Box<dyn DynamicFunction> {
    fn clone(&self) -> Self {
        (**self).clone_box()
    }
}

/// This trait is implemented for function traits in order to:
/// * describe their shape during runtime
/// * wrap them into a [`DynamicFunction`] which is callable with arbitrary data
///
/// Adapted from https://jsdw.me/posts/rust-fn-traits/ but using type ids
pub trait DescribableFunction<Types> {
    fn shape() -> DynamicFunctionShape;
    fn make_dynamic(&'static self) -> Box<dyn DynamicFunction>;
}

macro_rules! dynamic_fn {
    ($($arg:ident)* => $res:ident) => (
    impl<F, $res: 'static, $($arg: 'static),*>
        DescribableFunction<($res, $($arg),*)> for F
    where
        F: (Fn($(&$arg),*)  -> Result<$res, FnError>) + Send + Sync,
        $res: Send + Sync,
        $($arg: Send + Sync),*
    {
        fn shape() -> DynamicFunctionShape {
            DynamicFunctionShape {
                name: std::any::type_name::<F>().to_string(),
                argument_types: vec![$(TypeShape::of::<$arg>()),*],
                return_type: TypeShape::of::<$res>(),
            }
        }

        fn make_dynamic(&'static self) -> Box<dyn DynamicFunction> {
            #[allow(unused_variables)]
            Box::new(move |args: &Vec<Box<dyn Any>>| {
                #[allow(unused_mut)]
                let mut index = 0;

                let result: Result<$res, FnError> = self($(
                       #[allow(unused_assignments)]
                       {
                           if let Some(arg_) = args.get(index)
                                    .ok_or_else(|| {
                                        let shape = Self::shape();
                                        FnError::Unknown(format!("Missing argument #{} while calling {}.", index + 1, shape.name))
                                    })?
                                    .as_ref().downcast_ref::<$arg>() {
                               index = index + 1;
                               arg_
                           } else {
                               let shape = Self::shape();
                               return Err(FnError::Unknown(format!(
                                    "Passed argument #{} of {} did not match the shape {}. Hashes of passed types are {}.",
                                    index + 1,
                                    shape.name,
                                    shape,
                                    format_args(args)
                               )));
                           }
                       }
                ),*);

                result.map(|result| Box::new(result) as Box<dyn std::any::Any>)
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

pub fn make_dynamic<F: 'static, Types>(
    f: &'static F,
) -> (DynamicFunctionShape, Box<dyn DynamicFunction>)
where
    F: DescribableFunction<Types>,
{
    (F::shape(), f.make_dynamic())
}

#[derive(Copy, Clone, Debug)]
pub struct TypeShape {
    inner_type_id: TypeId,
    pub name: &'static str,
}

impl TypeShape {
    pub fn of<T: 'static>() -> TypeShape {
        Self {
            inner_type_id: TypeId::of::<T>(),
            name: type_name::<T>(),
        }
    }
}

impl Into<TypeId> for TypeShape {
    fn into(self) -> TypeId {
        self.inner_type_id
    }
}

impl Eq for TypeShape {}

impl PartialEq for TypeShape {
    fn eq(&self, other: &Self) -> bool {
        self.inner_type_id == other.inner_type_id
    }
}

impl Hash for TypeShape {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.inner_type_id.hash(state);
    }
}

impl fmt::Display for TypeShape {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name)
    }
}

impl Serialize for TypeShape {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.name)
    }
}

impl<'de> Deserialize<'de> for TypeShape {
    fn deserialize<D>(deserializer: D) -> Result<TypeShape, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct TypeShapeVisitor;

        impl<'de> Visitor<'de> for TypeShapeVisitor {
            type Value = TypeShape;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a TypeShape")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let typ = SIGNATURE.types_by_name
                    .get(v)
                    .ok_or(de::Error::missing_field("could not find type"))?;
                Ok(typ.clone())
            }
        }

        deserializer.deserialize_str(TypeShapeVisitor)
    }
}
