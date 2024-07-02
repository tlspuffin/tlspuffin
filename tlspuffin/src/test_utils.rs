use std::time::Duration;

use puffin::{
    execution::{forked_execution, ExecutionStatus},
    put_registry::PutDescriptor,
    trace::{Trace, TraceContext, TraceExecutor},
};

use crate::{put_registry::tls_registry, query::TlsQueryMatcher};

// TODO refactor forked execution into a build pattern
//
//     Because we now have several optional arguments to execute a trace and
//     several more in [`forked_execution()`], the API is difficult to read at
//     call site.
//
//     It would make sense to group everything into a builder pattern for
//     creating an trace execution. This would give something like:
//
//     Execution::builder(trace, options)
//         .timeout(Duration::from_secs(10))
//         .retry(5)
//         .expect_crash()
#[allow(dead_code)]
pub fn expect_trace_crash(
    trace: Trace<TlsQueryMatcher>,
    put: PutDescriptor,
    timeout: Option<Duration>,
    retry: Option<usize>,
) {
    let nb_retry = retry.unwrap_or(1);

    let _ = std::iter::repeat(())
        .take(nb_retry)
        .map(|_| {
            forked_execution(
                || {
                    // NOTE we ignore Rust errors because we expect a crash
                    let _ = TraceContext::builder(&tls_registry())
                        .set_default_put(put.clone())
                        .execute(&trace.clone());
                },
                timeout,
            )
        })
        .map(|status| {
            use ExecutionStatus as S;
            match &status {
                Ok(S::Failure(_)) | Ok(S::Crashed) => log::info!("trace execution crashed"),
                Ok(S::Timeout) => log::info!("trace execution timed out"),
                Ok(S::Success) => log::info!("expected trace execution to crash, but succeeded"),
                Err(reason) => log::info!("trace execution error: {reason}"),
            };
            status
        })
        .take_while(|status| {
            matches!(
                status,
                Ok(ExecutionStatus::Failure(_)) | Ok(ExecutionStatus::Crashed)
            )
        })
        .next()
        .unwrap_or_else(|| {
            panic!(
                "expected trace execution to crash (retried {} times)",
                nb_retry
            )
        });
}

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
        test_puts!($func, puts = [
                cput,
                openssl312,
                openssl111u,
                openssl111k,
                openssl111j,
                openssl102u,
                openssl101f,
                libressl333,
                wolfssl540,
                wolfssl530,
                wolfssl520,
                wolfssl510,
                wolfssl430,
                boringssl202403,
                boringssl202311
            ], attrs = $attrs, filter = $filter
        );
    };

    // actual expansion with canonical arguments
    ( $func:ident, puts = [ $($put:ident),* ], attrs = $attrs:tt, filter = $filter:meta ) => {
        mod $func {
            #![allow(unused_imports)]

            use super::$func;
            use super::test_puts;
            use tlspuffin_macros::expand_cfg;

            $(
                test_puts!(@expand-one $func, put = $put, attrs = $attrs, filter = $filter);
            )*
        }
    };

    (@expand-one $func:ident, put = $put:ident, attrs = [ $( $attr:meta ),* ], filter = $filter:meta) => {
        #[cfg($put)]
        #[expand_cfg($put, $filter)]
        #[test_log::test]
        $( #[$attr] )*
        fn $put() {
            $func(stringify!($put));
        }
    };
}

macro_rules! supports {
    ( $put:expr, $cap:expr ) => {{
        use crate::put_registry::tls_registry;

        tls_registry()
            .find_by_id($put)
            .expect("PUT was not found")
            .supports($cap)
    }};
}

pub(crate) use supports;
pub(crate) use test_puts;
