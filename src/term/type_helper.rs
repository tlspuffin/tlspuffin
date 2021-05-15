use std::any::{type_name, Any, TypeId};
use std::collections::hash_map::DefaultHasher;
use std::fmt;
use std::hash::{Hash, Hasher};

use itertools::Itertools;

/// Describes the shape of a [`DynamicFunction`]
#[derive(Debug, Clone)]
pub struct DynamicFunctionShape {
    argument_types: Vec<TypeId>,
    argument_type_names: Vec<&'static str>,
    return_type: TypeId,
    return_type_name: &'static str,
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

pub fn format_anys<P: 'static + AsRef<dyn Any>>(anys: &Vec<P>) -> String {
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

/// This trait is implemented for function traits in order to:
/// * describe their shape during runtime
/// * wrap them into a [`DynamicFunction`] which is callable with arbitrary data
///
/// Adapted from https://jsdw.me/posts/rust-fn-traits/ but using type ids
pub trait DescribableFunction<Types> {
    fn shape() -> DynamicFunctionShape;
    fn wrap(&'static self) -> Box<dyn DynamicFunction>;
}

impl<F, R: 'static> DescribableFunction<(R,)> for F
where
    F: Fn() -> R,
{
    fn shape() -> DynamicFunctionShape {
        DynamicFunctionShape {
            argument_types: vec![],
            argument_type_names: vec![],
            return_type: TypeId::of::<R>(),
            return_type_name: type_name::<R>(),
        }
    }

    fn wrap(&'static self) -> Box<dyn DynamicFunction> {
        Box::new(move |_: &Vec<Box<dyn Any>>| Box::new(self()))
    }
}

impl<F, T1: 'static, R: 'static> DescribableFunction<(T1, R)> for F
where
    F: Fn(&T1) -> R,
{
    fn shape() -> DynamicFunctionShape {
        DynamicFunctionShape {
            argument_types: vec![TypeId::of::<T1>()],
            argument_type_names: vec![type_name::<T1>()],
            return_type: TypeId::of::<R>(),
            return_type_name: type_name::<R>(),
        }
    }

    fn wrap(&'static self) -> Box<dyn DynamicFunction> {
        let closure = move |args: &Vec<Box<dyn Any>>| {
            if let Some(a1) = args[0].as_ref().downcast_ref::<T1>() {
                Box::new(self(a1)) as Box<dyn Any>
            } else {
                panic!(
                    "Passed arguments did not match the shape {}. Passed arguments are {:?}",
                    Self::shape(),
                    format_anys(args)
                )
            }
        };

        // The closure is cloneable and therefore compatible with DynamicFunction because:
        // self is cloneable as it is a 'static reference
        Box::new(closure)
    }
}

impl<F, T1: 'static, T2: 'static, R: 'static> DescribableFunction<(T1, T2, R)> for F
where
    F: Fn(&T1, &T2) -> R,
{
    fn shape() -> DynamicFunctionShape {
        DynamicFunctionShape {
            argument_types: vec![TypeId::of::<T1>(), TypeId::of::<T2>()],
            argument_type_names: vec![type_name::<T1>(), type_name::<T2>()],
            return_type: TypeId::of::<R>(),
            return_type_name: type_name::<R>(),
        }
    }

    fn wrap(&'static self) -> Box<dyn DynamicFunction> {
        Box::new(move |args: &Vec<Box<dyn Any>>| {
            if let (Some(a1), Some(a2)) = (
                args[0].as_ref().downcast_ref::<T1>(),
                args[1].as_ref().downcast_ref::<T2>(),
            ) {
                Box::new(self(a1, a2))
            } else {
                panic!(
                    "Passed arguments did not match the shape {}. Passed arguments are {:?}",
                    Self::shape(),
                    format_anys(args)
                )
            }
        })
    }
}

impl<F, T1: 'static, T2: 'static, T3: 'static, R: 'static> DescribableFunction<(T1, T2, T3, R)>
    for F
where
    F: Fn(&T1, &T2, &T3) -> R,
{
    fn shape() -> DynamicFunctionShape {
        DynamicFunctionShape {
            argument_types: vec![TypeId::of::<T1>(), TypeId::of::<T2>(), TypeId::of::<T3>()],
            argument_type_names: vec![type_name::<T1>(), type_name::<T2>(), type_name::<T3>()],
            return_type: TypeId::of::<R>(),
            return_type_name: type_name::<R>(),
        }
    }

    fn wrap(&'static self) -> Box<dyn DynamicFunction> {
        Box::new(move |args: &Vec<Box<dyn Any>>| {
            if let (Some(a1), Some(a2), Some(a3)) = (
                args[0].as_ref().downcast_ref::<T1>(),
                args[1].as_ref().downcast_ref::<T2>(),
                args[1].as_ref().downcast_ref::<T3>(),
            ) {
                Box::new(self(a1, a2, a3))
            } else {
                panic!(
                    "Passed arguments did not match the shape {}. Passed arguments are {:?}",
                    Self::shape(),
                    format_anys(args)
                )
            }
        })
    }
}

pub fn make_dynamic<F: 'static, Types>(
    f: &'static F,
) -> (DynamicFunctionShape, Box<dyn DynamicFunction>)
where
    F: DescribableFunction<Types>,
{
    (F::shape(), f.wrap())
}
