use std::any::{Any, TypeId};

pub type DynamicFunctionShape = (Vec<TypeId>, TypeId);
pub type DynamicFunction = dyn Fn(Vec<&dyn Any>) -> Box<dyn Any>;

/// Adapted from https://jsdw.me/posts/rust-fn-traits/ but using type ids
pub trait Describable<Types> {
    fn describe() -> DynamicFunctionShape;
    fn wrap(&'static self) -> Box<DynamicFunction>;
}

impl<F, T1: 'static, T2: 'static> Describable<(T1, T2)> for F
where
    F: Fn(&T1) -> T2,
{
    fn describe() -> DynamicFunctionShape {
        (vec![TypeId::of::<T1>()], TypeId::of::<T2>())
    }

    fn wrap(&'static self) -> Box<DynamicFunction> {
        Box::new(move |args: Vec<&dyn Any>| {
            let ret: T2 = self(
                args[0].downcast_ref::<T1>().unwrap()
            );
            Box::new(ret)
        })
    }
}

impl<F, T1: 'static, T2: 'static, T3: 'static> Describable<(T1, T2, T3)> for F
where
    F: Fn(&T1, &T2) -> T3,
{
    fn describe() -> (Vec<TypeId>, TypeId) {
        (
            vec![TypeId::of::<T1>(), TypeId::of::<T2>()],
            TypeId::of::<T3>(),
        )
    }

    fn wrap(&'static self) -> Box<DynamicFunction> {
        Box::new(move |args: Vec<&dyn Any>| {
            let ret: T3 = self(
                args[0].downcast_ref::<T1>().unwrap(),
                args[1].downcast_ref::<T2>().unwrap(),
            );
            Box::new(ret)
        })
    }
}

pub fn inspect_any<T>(_: T)
where
    T: Describable<()>,
{
    println!("shape: {:?}", T::describe());
}

pub fn inspect_function<F, Types>(_: F)
where
    F: Describable<Types>,
{
    println!("This function has the shape: {:?}", F::describe());
}

pub fn wrap_function<F: 'static, Types>(
    f: &'static F,
) -> (
    DynamicFunctionShape,
    Box<dyn Fn(Vec<&dyn Any>) -> Box<dyn Any>>,
)
where
    F: Describable<Types>,
{
    (F::describe(), f.wrap())
}

pub fn print_type_of<T>(_: &T) {
    println!("{}", std::any::type_name::<T>())
}
