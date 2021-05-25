// Provides a dummy implementation for sancov for usage in tests

#[no_mangle]
pub unsafe extern "C" fn __sanitizer_cov_trace_pc_guard(_guard: *mut u32) {}

#[no_mangle]
pub unsafe extern "C" fn __sanitizer_cov_trace_pc_guard_init(_start: *mut u32, _stop: *mut u32) {}
