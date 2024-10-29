// Provides a dummy implementation for sancov for usage in tests

#[no_mangle]
pub const unsafe extern "C" fn __sanitizer_cov_trace_pc_guard(_guard: *mut u32) {}

#[no_mangle]
pub const unsafe extern "C" fn __sanitizer_cov_trace_pc_guard_init(
    _start: *mut u32,
    _stop: *mut u32,
) {
}

// https://clang.llvm.org/docs/SanitizerCoverage.html#tracing-data-flow

#[no_mangle]
pub const unsafe extern "C" fn __sanitizer_cov_trace_cmp1(_arg1: u8, _arg2: u8) {}
#[no_mangle]
pub const unsafe extern "C" fn __sanitizer_cov_trace_cmp2(_arg1: u16, _arg2: u16) {}
#[no_mangle]
pub const unsafe extern "C" fn __sanitizer_cov_trace_cmp4(_arg1: u32, _arg2: u32) {}
#[no_mangle]
pub const unsafe extern "C" fn __sanitizer_cov_trace_cmp8(_arg1: u64, _arg2: u64) {}

// Called before a comparison instruction if exactly one of the arguments is constant.
// Arg1 and Arg2 are arguments of the comparison, Arg1 is a compile-time constant.
// These callbacks are emitted by -fsanitize-coverage=trace-cmp since 2017-08-11
#[no_mangle]
pub const unsafe extern "C" fn __sanitizer_cov_trace_const_cmp1(_arg1: u8, _arg2: u8) {}
#[no_mangle]
pub const unsafe extern "C" fn __sanitizer_cov_trace_const_cmp2(_arg1: u16, _arg2: u16) {}
#[no_mangle]
pub const unsafe extern "C" fn __sanitizer_cov_trace_const_cmp4(_arg1: u32, _arg2: u32) {}
#[no_mangle]
pub const unsafe extern "C" fn __sanitizer_cov_trace_const_cmp8(_arg1: u64, _arg2: u64) {}

// Called before a switch statement.
// Val is the switch operand.
// Cases[0] is the number of case constants.
// Cases[1] is the size of Val in bits.
// Cases[2:] are the case constants.
#[no_mangle]
pub const unsafe extern "C" fn __sanitizer_cov_trace_switch(_val: u64, _cases: *mut u64) {}

// Called before a division statement.
// Val is the second argument of division.
#[no_mangle]
pub const unsafe extern "C" fn __sanitizer_cov_trace_div4(_val: u32) {}
#[no_mangle]
pub const unsafe extern "C" fn __sanitizer_cov_trace_div8(_val: u64) {}

// Called before a GetElementPtr (GEP) instruction
// for every non-constant array index.
#[no_mangle]
pub const unsafe extern "C" fn __sanitizer_cov_trace_gep(_idx: *mut u32) {}
