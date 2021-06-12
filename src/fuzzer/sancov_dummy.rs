// Provides a dummy implementation for sancov for usage in tests

#[no_mangle]
pub unsafe extern "C" fn __sanitizer_cov_trace_pc_guard(_guard: *mut u32) {}

#[no_mangle]
pub unsafe extern "C" fn __sanitizer_cov_trace_pc_guard_init(_start: *mut u32, _stop: *mut u32) {}


// https://clang.llvm.org/docs/SanitizerCoverage.html#tracing-data-flow

#[no_mangle]
pub unsafe extern "C" fn  __sanitizer_cov_trace_cmp1( Arg1:u8,   Arg2: u8) {}
#[no_mangle]
pub unsafe extern "C" fn  __sanitizer_cov_trace_cmp2( Arg1:u16,  Arg2: u16) {}
#[no_mangle]
pub unsafe extern "C" fn  __sanitizer_cov_trace_cmp4( Arg1:u32,  Arg2: u32) {}
#[no_mangle]
pub unsafe extern "C" fn  __sanitizer_cov_trace_cmp8( Arg1:u64,  Arg2: u64) {}

// Called before a comparison instruction if exactly one of the arguments is constant.
// Arg1 and Arg2 are arguments of the comparison, Arg1 is a compile-time constant.
// These callbacks are emitted by -fsanitize-coverage=trace-cmp since 2017-08-11
#[no_mangle]
pub unsafe extern "C" fn  __sanitizer_cov_trace_const_cmp1( Arg1:u8,  Arg2:u8) {}
#[no_mangle]
pub unsafe extern "C" fn  __sanitizer_cov_trace_const_cmp2( Arg1:u16,  Arg2:u16) {}
#[no_mangle]
pub unsafe extern "C" fn  __sanitizer_cov_trace_const_cmp4( Arg1:u32,  Arg2:u32) {}
#[no_mangle]
pub unsafe extern "C" fn  __sanitizer_cov_trace_const_cmp8( Arg1:u64,  Arg2:u64) {}

// Called before a switch statement.
// Val is the switch operand.
// Cases[0] is the number of case constants.
// Cases[1] is the size of Val in bits.
// Cases[2:] are the case constants.
#[no_mangle]
pub unsafe extern "C" fn  __sanitizer_cov_trace_switch(Val: u64 , Cases: *mut u64) {}

// Called before a division statement.
// Val is the second argument of division.
#[no_mangle]
pub unsafe extern "C" fn  __sanitizer_cov_trace_div4( Val: u32) {}
#[no_mangle]
pub unsafe extern "C" fn  __sanitizer_cov_trace_div8( Val: u64) {}

// Called before a GetElemementPtr (GEP) instruction
// for every non-constant array index.
#[no_mangle]
pub unsafe extern "C" fn  __sanitizer_cov_trace_gep(Idx:  *mut u32) {}