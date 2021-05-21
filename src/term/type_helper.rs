use std::any::{type_name, Any, TypeId};
use std::collections::hash_map::DefaultHasher;
use std::fmt;
use std::hash::{Hash, Hasher};

use itertools::Itertools;
use serde::{Deserialize, Serialize, Serializer, Deserializer};

/// Describes the shape of a [`DynamicFunction`]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DynamicFunctionShape {
    pub name: String,
    pub argument_types: Vec<TypeShape>,
    pub argument_type_names: Vec<String>,
    pub return_type: TypeShape,
    pub return_type_name: String,
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
            "({}) -> {}",
            self.argument_type_names
                .iter()
                .map(|name| format!("{}", name))
                .join(","),
            self.return_type_name
        )
    }
}

/// Hashes [`TypeId`]s to be more readable
///
pub fn hash_type_id(type_id: &TypeId) -> u64 {
    let mut hasher = DefaultHasher::new();
    type_id.hash(&mut hasher);
    hasher.finish()
}

pub fn format_args<P: 'static + AsRef<dyn Any>>(anys: &Vec<P>) -> String {
    format!(
        "({})",
        anys.iter()
            .map(|any| {
                let id = any.type_id();
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
pub trait DynamicFunction: Fn(&Vec<Box<dyn Any>>) -> Box<dyn Any> {
    fn clone_box(&self) -> Box<dyn DynamicFunction>;
}

impl<T> DynamicFunction for T
where
    T: 'static + Fn(&Vec<Box<dyn Any>>) -> Box<dyn Any> + Clone,
{
    fn clone_box(&self) -> Box<dyn DynamicFunction> {
        Box::new(self.clone())
    }
}

impl Clone for Box<dyn DynamicFunction> {
    fn clone(&self) -> Self {
        (**self).clone_box()
    }
}

impl Serialize for Box<dyn DynamicFunction> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
    {
        // todo
        serializer.serialize_u64(1)
    }
}

impl<'de> Deserialize<'de> for Box<dyn DynamicFunction> {
    fn deserialize<D>(deserializer: D) -> Result<Box<dyn DynamicFunction>, D::Error>
        where
            D: Deserializer<'de>,
    {
        // todo
        Ok(Box::new(make_dynamic(&crate::term::op_server_hello).1))
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
    impl<F, $res: 'static, $($arg: 'static),*> // 'static missing
        DescribableFunction<($res, $($arg),*)> for F
    where
        F: Fn($(&$arg),*) -> $res
    {
        fn shape() -> DynamicFunctionShape {
            DynamicFunctionShape {
                name: std::any::type_name::<F>().to_string(),
                argument_types: vec![$(TypeShape::of::<$arg>()),*],
                argument_type_names: vec![$(type_name::<$arg>().to_string()),*],
                return_type: TypeShape::of::<$res>(),
                return_type_name: type_name::<$res>().to_string(),
            }
        }

        fn make_dynamic(&'static self) -> Box<dyn DynamicFunction> {
            #[allow(unused_variables)]
            Box::new(move |args: &Vec<Box<dyn Any>>| {
                #[allow(unused_mut)]
                let mut index = 0;

                Box::new(self($(
                       #[allow(unused_assignments)]
                       {
                           if let Some(arg_) = args.get(index)
                                    .unwrap_or_else(|| {
                                        let shape = Self::shape();
                                        panic!("Missing argument #{} while calling {}.", index + 1, shape.name)
                                    })
                                    .as_ref().downcast_ref::<$arg>() {
                               index = index + 1;
                               arg_
                           } else {
                               let shape = Self::shape();
                               panic!(
                                    "Passed argument #{} of {} did not match the shape {}. Hashes of passed types are {}.",
                                    index + 1,
                                    shape.name,
                                    shape,
                                    format_args(args)
                               )
                           }
                       }
                ),*))
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

#[derive(Serialize, Deserialize, Copy, Clone, Debug)]
pub struct TypeShape {
    #[serde(skip, default = "TypeShape::default_type_id")]
    pub inner_type_id: TypeId,
}



struct UnknownType;

impl TypeShape {
    pub fn of<T: 'static>() -> TypeShape {
        Self {
            inner_type_id: TypeId::of::<T>()
        }
    }

    fn default_type_id() -> TypeId {
        TypeId::of::<UnknownType>()
    }
}

impl PartialEq for TypeShape {
    fn eq(&self, other: &Self) -> bool {
        self.inner_type_id == other.inner_type_id
    }
}