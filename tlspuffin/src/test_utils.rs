use std::time::Duration;

use log::info;
use puffin::{
    execution::{forked_execution, ExecutionStatus},
    put::PutOptions,
    trace::{Trace, TraceContext},
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
    default_put_options: PutOptions,
    timeout: Option<Duration>,
    retry: Option<usize>,
) {
    let nb_retry = retry.unwrap_or(1);

    let _ = std::iter::repeat(())
        .take(nb_retry)
        .map(|_| {
            forked_execution(
                || {
                    let mut context = TraceContext::builder(&tls_registry())
                        .set_default_put_options(default_put_options.clone())
                        .set_deterministic(true)
                        .build();

                    // NOTE: we ignore Rust errors because we expect a crash
                    let _ = trace.clone().execute(&mut context);
                },
                timeout,
            )
        })
        .map(|status| {
            use ExecutionStatus as S;
            match &status {
                Ok(S::Failure(_)) | Ok(S::Crashed) => info!("trace execution crashed"),
                Ok(S::Timeout) => info!("trace execution timed out"),
                Ok(S::Success) => info!("expected trace execution to crash, but succeeded"),
                Err(reason) => info!("trace execution error: {reason}"),
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
