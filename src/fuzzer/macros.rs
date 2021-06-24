
#[macro_export]
macro_rules! mutator {
    ($(#[$attr:meta])* $name:ident, $impl:item) => {

        #[derive(Default)]
        $(#[$attr])*
        pub struct $name<R, S>
        where
            S: HasRand<R>,
            R: Rand,
        {
            phantom: PhantomData<(R, S)>,
        }

        impl<R, S> $name<R, S>
        where
            S: HasRand<R>,
            R: Rand,
        {
            #[must_use]
            pub fn new() -> Self {
                Self {
                    phantom: PhantomData,
                }
            }
        }

        impl<R, S> Mutator<Trace, S> for $name<R, S>
        where
            S: HasRand<R>,
            R: Rand,
        {
            $impl
        }

        impl<R, S> Named for $name<R, S>
        where
            S: HasRand<R>,
            R: Rand,
        {
            fn name(&self) -> &str {
                std::any::type_name::<$name<R, S>>()
            }
        }

    };
}