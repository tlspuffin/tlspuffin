//! The fuzzer module setups the fuzzing loop. It also is responsible for gathering feedback from
//! runs and restarting processes if they crash.

use libafl::{bolts::HasLen, inputs::Input};

use crate::trace::Trace;

pub mod harness;
mod libafl_setup;
pub mod sanitizer;
mod stages;
mod stats_monitor;
mod stats_stage;
pub mod term_zoo;
// Public for benchmarks
pub mod mutations;

pub use libafl_setup::{start, FuzzerConfig};

use crate::algebra::Matcher;

// LibAFL support
impl<M: Matcher> Input for Trace<M> {
    fn generate_name(&self, idx: usize) -> String {
        format!("{id}.trace", id = idx)
    }
}

impl<M: Matcher> HasLen for Trace<M> {
    fn len(&self) -> usize {
        self.steps.len()
    }
}
