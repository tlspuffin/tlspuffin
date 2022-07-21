#[macro_export]
macro_rules! mutator {
    ($(#[$attr:meta])* <$($generic_name:ident : $generic_type:ident),*>, $name:ident, <$($input_generic_name:ident : $input_generic_type:ident),*>, $input_type:ty, $impl:item, $($arg_name:ident : $arg_type:ty),*) => {
        $(#[$attr])*
        pub struct $name<S, $($generic_name: $generic_type,)*>
        where
            S: libafl::state::HasRand,
        {
            $($arg_name: $arg_type,)*
            phantom_s: std::marker::PhantomData<S>,
        }

        impl<S, $($generic_name: $generic_type,)*> $name<S, $($generic_name,)*>
        where
            S: libafl::state::HasRand,
        {
            #[must_use]
            pub fn new($($arg_name: $arg_type,)*) -> Self {
                Self {
                    $($arg_name,)*
                    phantom_s: std::marker::PhantomData,
                }
            }
        }

        impl<S, $($generic_name: $generic_type,)* $($input_generic_name: $input_generic_type,)*> libafl::mutators::Mutator<$input_type, S> for $name<S, $($generic_name,)*>
        where
            S: libafl::state::HasRand,
        {
            $impl
        }

        impl<S, $($generic_name: $generic_type,)*> libafl::bolts::tuples::Named for $name<S, $($generic_name,)*>
        where
            S: libafl::state::HasRand,
        {
            fn name(&self) -> &str {
                std::any::type_name::<$name<S>>()
            }
        }

    };
}
