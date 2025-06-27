//! The fuzzer module setups the fuzzing loop. It also is responsible for gathering feedback from
//! runs and restarting processes if they crash.

use std::hash::{BuildHasher, Hash, Hasher};

use chrono::Utc;
use libafl::inputs::Input;
use libafl_bolts::HasLen;

use crate::protocol::ProtocolTypes;
use crate::trace::Trace;

pub mod harness;
mod libafl_setup;
pub mod sanitizer;
pub mod stages;
mod stats_monitor;
mod stats_stage;
pub mod term_zoo;
// Public for benchmarks
pub mod bit_mutations;
pub mod mutations;
pub mod utils;

pub use libafl_setup::{start, FuzzerConfig};

// LibAFL support
impl<PT: ProtocolTypes> Input for Trace<PT> {
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

impl<PT: ProtocolTypes> HasLen for Trace<PT> {
    fn len(&self) -> usize {
        self.steps.len()
    }
}
