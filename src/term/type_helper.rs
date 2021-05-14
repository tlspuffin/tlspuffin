use std::any::{Any, TypeId};
use std::collections::hash_map::DefaultHasher;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::ptr::hash;

#[derive(Debug, Clone)]
pub struct DynamicFunctionShape {
    argument_types: Vec<TypeId>,
    return_type: TypeId,
}

impl DynamicFunctionShape {
    pub fn arity(&self) -> u16 {
        self.argument_types.len() as u16
    }
}

pub fn hash_type_id(type_id: &TypeId) -> u64 {
    let mut hasher = DefaultHasher::new();
    type_id.hash(&mut hasher);
    hasher.finish()
}

impl fmt::Display for DynamicFunctionShape {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Arguments:\t{:?}\nReturn:\t{:x}",
            self.argument_types
                .iter()
                .map(|type_id| format!("{:x}", hash_type_id(type_id)))
                .collect::<Vec<String>>(),
            hash_type_id(&self.return_type)
        )
    }
}

// The type of dynamically typed functions is:
// Fn(Vec<&dyn Any>) -> Box<dyn Any>

// Make DynamicFunction cloneable
// https://users.rust-lang.org/t/how-to-clone-a-boxed-closure/31035/25
pub trait DynamicFunction: Fn(Vec<&dyn Any>) -> Box<dyn Any> {
    fn clone_box(&self) -> Box<dyn DynamicFunction>;
}

impl<T> DynamicFunction for T
where
    T: 'static + Fn(Vec<&dyn Any>) -> Box<dyn Any> + Clone,
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

/// Adapted from https://jsdw.me/posts/rust-fn-traits/ but using type ids
pub trait DescribableFunction<Types> {
    fn shape() -> DynamicFunctionShape;
    fn wrap(&'static self) -> Box<dyn DynamicFunction>;
}

impl<F, T1: 'static, T2: 'static> DescribableFunction<(T1, T2)> for F
where
    F: Fn(&T1) -> T2,
{
    fn shape() -> DynamicFunctionShape {
        DynamicFunctionShape {
            argument_types: vec![TypeId::of::<T1>()],
            return_type: TypeId::of::<T2>(),
        }
    }

    fn wrap(&'static self) -> Box<dyn DynamicFunction> {
        let f = move |args: Vec<&dyn Any>| {
            let ret: T2 = self(args[0].downcast_ref::<T1>().unwrap());
            return Box::new(ret) as Box<dyn Any>;
        };

        // The closure f is cloneable and therefore compatible with DynamicFunction because:
        // self is cloneable as it is a 'static reference
        Box::new(f)
    }
}

impl<F, T1: 'static, T2: 'static, T3: 'static> DescribableFunction<(T1, T2, T3)> for F
where
    F: Fn(&T1, &T2) -> T3,
{
    fn shape() -> DynamicFunctionShape {
        DynamicFunctionShape {
            argument_types: vec![TypeId::of::<T1>(), TypeId::of::<T2>()],
            return_type: TypeId::of::<T3>(),
        }
    }

    fn wrap(&'static self) -> Box<dyn DynamicFunction> {
        Box::new(move |args: Vec<&dyn Any>| {
            Box::new(self(
                args[0].downcast_ref::<T1>().unwrap(),
                args[1].downcast_ref::<T2>().unwrap(),
            ))
        })
    }
}

pub fn function_shape<F, Types>(_: F) -> DynamicFunctionShape
where
    F: DescribableFunction<Types>,
{
    F::shape()
}

pub fn make_dynamic<F: 'static, Types>(
    f: &'static F,
) -> (DynamicFunctionShape, Box<dyn DynamicFunction>)
where
    F: DescribableFunction<Types>,
{
    (F::shape(), f.wrap())
}

pub fn print_type_of<T>(_: &T) {
    println!("{}", std::any::type_name::<T>())
}
