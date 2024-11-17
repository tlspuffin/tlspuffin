use crate::algebra::term::TermType;
use crate::algebra::{DYTerm, Term};
use crate::execution::{ExecutionStatus, ForkError};
use crate::graphviz::write_graphviz;
use crate::protocol::ProtocolTypes;
use crate::trace::{Action, Trace};

impl<PT: ProtocolTypes> Trace<PT> {
    #[must_use]
    pub fn count_functions_by_name(&self, find_name: &'static str) -> usize {
        self.steps
            .iter()
            .map(|step| match &step.action {
                Action::Input(input) => input.recipe.count_functions_by_name(find_name),
                Action::Output(_) => 0,
            })
            .sum()
    }

    #[must_use]
    pub fn count_functions(&self) -> usize {
        self.steps
            .iter()
            .filter_map(|step| match &step.action {
                Action::Input(input) => Some(&input.recipe),
                Action::Output(_) => None,
            })
            .map(|term| term.size())
            .sum()
    }

    pub fn write_plots(&self, i: u16) {
        write_graphviz(
            format!("test_mutation{i}.svg").as_str(),
            "svg",
            self.dot_graph(true).as_str(),
        )
        .unwrap();
    }
}

impl<PT: ProtocolTypes> Term<PT> {
    pub fn count_functions_by_name(&self, find_name: &'static str) -> usize {
        let mut found = 0;
        for term in self {
            if let DYTerm::Application(func, _) = &term.term {
                if func.name() == find_name {
                    found += 1;
                }
            }
        }
        found
    }
}

pub trait AssertExecution {
    fn expect_crash(self);
}

impl AssertExecution for Result<ExecutionStatus, ForkError> {
    fn expect_crash(self) {
        use ExecutionStatus as S;
        match self {
            Ok(S::Crashed) => (),
            Ok(S::Failure(_)) => panic!("invalid trace"),
            Ok(S::Timeout) => panic!("trace execution timed out"),
            Ok(S::Interrupted) => panic!("trace execution interrupted"),
            Ok(S::Success) => panic!("expected trace execution to crash, but succeeded"),
            Err(reason) => panic!("trace execution error: {reason}"),
        }
    }
}

#[macro_export]
macro_rules! test_puts {
    // handle default arguments
    ( $func:ident) => { test_puts!( $func, attrs = [], filter = all() ); };
    ( $func:ident, puts = $puts:tt ) => { test_puts!( $func, puts = $puts, attrs = [], filter = all() ); };
    ( $func:ident, puts = $puts:tt, attrs = $attrs:tt ) => { test_puts!( $func, puts = $puts, attrs = $attrs, filter = all() ); };
    ( $func:ident, puts = $puts:tt, filter = $filter:meta ) => { test_puts!( $func, puts = $puts, attrs = [], filter = $filter ); };
    ( $func:ident, attrs = $attrs:tt  ) => { test_puts!( $func, puts = all, attrs = $attrs, filter = all() ); };
    ( $func:ident, filter = $filter:meta ) => { test_puts!( $func, puts = all, attrs = [], filter = $filter ); };
    ( $func:ident, attrs = $attrs:tt, filter = $filter:meta ) => { test_puts!( $func, puts = all, attrs = $attrs, filter = $filter ); };

    // put arguments in a canonical order
    ( $func:ident, attrs = $attrs:tt, puts = $puts:tt, filter = $filter:meta ) => { test_puts!($func, puts = $puts, attrs = $attrs, filter = $filter); };
    ( $func:ident, attrs = $attrs:tt, filter = $filter:meta, puts = $puts:tt ) => { test_puts!($func, puts = $puts, attrs = $attrs, filter = $filter); };
    ( $func:ident, filter = $filter:meta, puts = $puts:tt, attrs = $attrs:tt ) => { test_puts!($func, puts = $puts, attrs = $attrs, filter = $filter); };
    ( $func:ident, filter = $filter:meta, attrs = $attrs:tt, puts = $puts:tt ) => { test_puts!($func, puts = $puts, attrs = $attrs, filter = $filter); };
    ( $func:ident, puts = $puts:tt, filter = $filter:meta, attrs = $attrs:tt ) => { test_puts!($func, puts = $puts, attrs = $attrs, filter = $filter); };

    // expand `puts` argument when `all` was requested
    ( $func:ident, puts = all, attrs = $attrs:tt, filter = $filter:meta ) => {
        mod $func {
            #![allow(unused_imports)]
            #![allow(unexpected_cfgs)]

            use super::$func;
            use super::for_puts;
            use super::test_puts;
            use puffin_macros::expand_cfg;

            for_puts!(
                test_puts!(@expand-one $func, put = __PUT__:__PUTSTR__, attrs = $attrs, filter = $filter);
            );
        }
    };

    // actual expansion with canonical arguments
    ( $func:ident, puts = [ $($put:ident : $putstr:literal),* ], attrs = $attrs:tt, filter = $filter:meta ) => {
        mod $func {
            #![allow(unused_imports)]
            #![allow(unexpected_cfgs)]

            use super::$func;
            use super::test_puts;
            use puffin_macros::expand_cfg;

            $(
                test_puts!(@expand-one $func, put = $put : $putstr, attrs = $attrs, filter = $filter);
            )*
        }
    };

    (@expand-one $func:ident, put = $put:ident : $putstr:literal, attrs = [ $( $attr:meta ),* ], filter = $filter:meta) => {
        #[cfg(has_put = $putstr)]
        #[expand_cfg($putstr, $filter)]
        #[test_log::test]
        $( #[$attr] )*
        fn $put() {
            $func($putstr);
        }
    };
}

#[macro_export]
macro_rules! supports {
    ($put:expr, $cap:expr) => {{
        use crate::put_registry::tls_registry;

        tls_registry()
            .find_by_id($put)
            .expect("PUT was not found")
            .supports($cap)
    }};
}

#[allow(unused_imports)]
pub(crate) use {supports, test_puts};
