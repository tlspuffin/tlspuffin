use std::time::Duration;

use puffin::execution::{forked_execution, ExecutionStatus};
use puffin::put::PutOptions;
use puffin::trace::Trace;

use crate::put_registry::tls_registry;
use crate::query::TlsQueryMatcher;

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
    default_put_options: PutOptions,
    timeout: Option<Duration>,
    retry: Option<usize>,
) {
    let nb_retry = retry.unwrap_or(1);

    let _ = std::iter::repeat(())
        .take(nb_retry)
        .enumerate()
        .map(|(i, _)| {
            log::debug!("expect_trace_crash at retry {}", i);
            forked_execution(
                || {
                    // Ignore Rust errors
                    let _ = trace
                        .clone()
                        .execute_deterministic(&tls_registry(), default_put_options.clone());
                },
                timeout,
            )
        })
        .inspect(|status| {
            use ExecutionStatus as S;
            match status {
                Ok(S::Failure(_)) | Ok(S::Crashed) => log::info!("trace execution crashed"),
                Ok(S::Timeout) => log::info!("trace execution timed out"),
                Ok(S::Success) => log::info!("expected trace execution to crash, but succeeded"),
                Err(reason) => log::info!("trace execution error: {reason}"),
            };
        })
        .find(|status| {
            matches!(
                status,
                Ok(ExecutionStatus::Failure(_)) | Ok(ExecutionStatus::Crashed)
            )
        })
        .unwrap_or_else(|| {
            panic!(
                "expected trace execution to crash (retried {} times)",
                nb_retry
            )
        });
}
