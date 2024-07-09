use std::time::Duration;

use puffin::{
    execution::{forked_execution, ExecutionStatus},
    put_registry::PutDescriptor,
    trace::Trace,
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
                    // Ignore Rust errors
                    let _ = trace
                        .clone()
                        .execute_deterministic(&tls_registry(), put.clone());
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
