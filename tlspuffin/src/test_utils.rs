use std::time::Duration;

use puffin::{
    execution::{forked_execution, AssertExecution},
    put::PutOptions,
    trace::Trace,
};

use crate::{put_registry::TLS_PUT_REGISTRY, query::TlsQueryMatcher};

#[allow(dead_code)]
pub fn expect_trace_crash(
    trace: Trace<TlsQueryMatcher>,
    default_put_options: PutOptions,
    timeout: Option<Duration>,
) {
    forked_execution(
        move || {
            // Ignore Rust errors
            let _ = trace.execute_deterministic(&TLS_PUT_REGISTRY, default_put_options);
        },
        timeout,
    )
    .expect_crash();
}
