//! The fuzzer module setups the fuzzing loop. It also is responsible for gathering feedback from
//! runs and restarting processes if they crash.

mod harness;
mod libafl_setup;
pub mod mutations;
pub mod seeds;
mod stats;
#[cfg(test)]
mod tests;

use libafl::bolts::HasLen;
pub use libafl_setup::start;

// Link against correct sancov impl
#[cfg(all(feature = "sancov_pcguard_log", feature = "sancov_libafl"))]
compile_error!("`sancov_pcguard_log` and `sancov_libafl` features are mutually exclusive.");

/*#[cfg(all(any(feature = "sancov_pcguard_log", feature = "sancov_libafl"), test))]
compile_error!(
    "you can not enable `sancov_pcguard_log` or `sancov_libafl` in tests"
);*/

// Use log if explicitely enabled
#[cfg(all(not(test), feature = "sancov_pcguard_log"))]
mod sancov_pcguard_log;

// Use dummy in tests
mod macros;
#[cfg(test)]
mod sancov_dummy;
mod stages;
mod stats_observer;
mod term_zoo;

use crate::trace::Trace;
use libafl::inputs::Input;
#[cfg(all(not(test), feature = "sancov_libafl"))]
// This import achieves that OpenSSl compiled with -fsanitize-coverage=trace-pc-guard can link
pub(crate) use libafl_targets::{EDGES_MAP, MAX_EDGES_NUM};

#[cfg(any(test, not(feature = "sancov_libafl")))]
pub(crate) const EDGES_MAP_SIZE: usize = 65536;
#[cfg(any(test, not(feature = "sancov_libafl")))]
pub(crate) static mut EDGES_MAP: [u8; EDGES_MAP_SIZE] = [0; EDGES_MAP_SIZE];
#[cfg(any(test, not(feature = "sancov_libafl")))]
pub(crate) static mut MAX_EDGES_NUM: usize = 0;
#[cfg(any(test, not(feature = "sancov_libafl")))]
pub(crate) const CMP_MAP_SIZE: usize = 65536;
#[cfg(any(test, not(feature = "sancov_libafl")))]
pub(crate) static mut CMP_MAP: [u8; CMP_MAP_SIZE] = [0; CMP_MAP_SIZE];

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

impl std::hash::Hash for Trace {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        todo!()
    }
}
