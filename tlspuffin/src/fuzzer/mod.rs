//! The fuzzer module setups the fuzzing loop. It also is responsible for gathering feedback from
//! runs and restarting processes if they crash.

use libafl::{bolts::HasLen, inputs::Input};

use crate::trace::Trace;

mod harness;
mod libafl_setup;
mod macros;
pub mod sanitizer;
mod stages;
mod stats_monitor;
mod stats_stage;
mod term_zoo;
// Public for benchmarks
pub mod mutations;
pub mod tracing_stage;

pub use libafl_setup::{start, FuzzerConfig};

// LibAFL support
impl Input for Trace {
    fn generate_name(&self, idx: usize) -> String {
        format!("{id}.trace", id = idx)
    }
}

impl HasLen for Trace {
    fn len(&self) -> usize {
        self.steps.len()
    }
}
