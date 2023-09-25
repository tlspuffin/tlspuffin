//! The fuzzer module setups the fuzzing loop. It also is responsible for gathering feedback from
//! runs and restarting processes if they crash.

use std::hash::{BuildHasher, Hash, Hasher};

use chrono::Utc;
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
pub mod bit_mutations;
pub mod mutations;
pub mod utils;

pub use libafl_setup::{start, FuzzerConfig};

use crate::algebra::Matcher;

// LibAFL support
impl<M: Matcher> Input for Trace<M> {
    fn generate_name(&self, _idx: usize) -> String {
        let now = Utc::now();
        let mut hasher = ahash::RandomState::with_seeds(0, 0, 0, 0).build_hasher();
        self.hash(&mut hasher);
        format!(
            "{time}-{hash:016x}.trace",
            hash = hasher.finish(),
            time = now.format("%Y%m%d-%H%M%S%3f")
        )
    }
}

impl<M: Matcher> HasLen for Trace<M> {
    fn len(&self) -> usize {
        self.steps.len()
    }
}
