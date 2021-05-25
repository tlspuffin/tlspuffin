// Alternative to using libafl_targets for testing

#[no_mangle]
pub unsafe extern "C" fn __sanitizer_cov_trace_pc_guard(guard: *mut u32) {
    println!("__sanitizer_cov_trace_pc_guard");
}

#[no_mangle]
pub unsafe extern "C" fn __sanitizer_cov_trace_pc_guard_init(mut start: *mut u32, stop: *mut u32) {
    println!("__sanitizer_cov_trace_pc_guard_init");
}
