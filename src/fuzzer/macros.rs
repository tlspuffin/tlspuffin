#[macro_export]
macro_rules! mutator {
    ($(#[$attr:meta])* $name:ident, $input_type:ident, $impl:item, $($arg_name:ident : $arg_type:ty),*) => {
        #[derive(Default)]
        $(#[$attr])*
        pub struct $name<S>
        where
            S: libafl::state::HasRand,
        {
            $($arg_name: $arg_type,)*
            phantom: std::marker::PhantomData<(S)>,
        }

        impl<S> $name<S>
        where
            S: libafl::state::HasRand,
        {
            #[must_use]
            pub fn new($($arg_name: $arg_type,)*) -> Self {
                Self {
                    $($arg_name,)*
                    phantom: std::marker::PhantomData,
                }
            }
        }

        impl<S> libafl::mutators::Mutator<$input_type, S> for $name<S>
        where
            S: libafl::state::HasRand,
        {
            $impl
        }

        impl<S> libafl::bolts::tuples::Named for $name<S>
        where
            S: libafl::state::HasRand,
        {
            fn name(&self) -> &str {
                std::any::type_name::<$name<S>>()
            }
        }

    };
}
