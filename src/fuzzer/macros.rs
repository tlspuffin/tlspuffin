
#[macro_export]
macro_rules! mutator {
    ($(#[$attr:meta])* $name:ident, $input_type:ident, $impl:item, $($arg_name:ident : $arg_type:ty),*) => {
        #[derive(Default)]
        $(#[$attr])*
        pub struct $name<R, S>
        where
            S: libafl::state::HasRand<R>,
            R: libafl::bolts::rands::Rand,
        {
            $($arg_name: $arg_type,)*
            phantom: std::marker::PhantomData<(R, S)>,
        }

        impl<R, S> $name<R, S>
        where
            S: libafl::state::HasRand<R>,
            R: libafl::bolts::rands::Rand,
        {
            #[must_use]
            pub fn new($($arg_name: $arg_type,)*) -> Self {
                Self {
                    $($arg_name,)*
                    phantom: std::marker::PhantomData,
                }
            }
        }

        impl<R, S> libafl::mutators::Mutator<$input_type, S> for $name<R, S>
        where
            S: libafl::state::HasRand<R>,
            R: libafl::bolts::rands::Rand,
        {
            $impl
        }

        impl<R, S> libafl::bolts::tuples::Named for $name<R, S>
        where
            S: libafl::state::HasRand<R>,
            R: libafl::bolts::rands::Rand,
        {
            fn name(&self) -> &str {
                std::any::type_name::<$name<R, S>>()
            }
        }

    };
}