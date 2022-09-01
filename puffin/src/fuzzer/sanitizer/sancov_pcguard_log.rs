// Alternative to using libafl_targets for testing

use log::trace;

#[no_mangle]
pub unsafe extern "C" fn __sanitizer_cov_trace_pc_guard(guard: *mut u32) {
    trace!("__sanitizer_cov_trace_pc_guard");
}

#[no_mangle]
pub unsafe extern "C" fn __sanitizer_cov_trace_pc_guard_init(mut start: *mut u32, stop: *mut u32) {
    trace!("__sanitizer_cov_trace_pc_guard_init");
}
