// Provides a dummy implementation for sancov for usage in tests

#[no_mangle]
pub unsafe extern "C" fn __sanitizer_cov_trace_pc_guard(guard: *mut u32) {}

#[no_mangle]
pub unsafe extern "C" fn __sanitizer_cov_trace_pc_guard_init(mut start: *mut u32, stop: *mut u32) {}
