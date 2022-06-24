#[cfg(all(feature = "sancov_pcguard_log", feature = "sancov_libafl"))]
compile_error!("`sancov_pcguard_log` and `sancov_libafl` features are mutually exclusive.");

#[cfg(test)]
// Use dummy in tests
pub mod sancov_dummy;
#[cfg(all(not(test), feature = "sancov_pcguard_log"))]
pub mod sancov_pcguard_log;

#[cfg(all(not(test), feature = "sancov_libafl"))]
// This import achieves that OpenSSl compiled with -fsanitize-coverage=trace-pc-guard can link
pub use libafl_targets::{EDGES_MAP, MAX_EDGES_NUM};

#[cfg(any(test, not(feature = "sancov_libafl")))]
pub const EDGES_MAP_SIZE: usize = 65536;
#[cfg(any(test, not(feature = "sancov_libafl")))]
pub static mut EDGES_MAP: [u8; EDGES_MAP_SIZE] = [0; EDGES_MAP_SIZE];
#[cfg(any(test, not(feature = "sancov_libafl")))]
pub static mut MAX_EDGES_NUM: usize = 0;
#[cfg(any(test, not(feature = "sancov_libafl")))]
pub const CMP_MAP_SIZE: usize = 65536;
#[cfg(any(test, not(feature = "sancov_libafl")))]
pub static mut CMP_MAP: [u8; CMP_MAP_SIZE] = [0; CMP_MAP_SIZE];
