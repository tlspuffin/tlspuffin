use std::process::ExitCode;

use opcuapuffin::put_registry::opcua_registry;

pub fn main() -> ExitCode {
    puffin::cli::main(
        "Fuzzes the OPC UA protocol at the symbolic level",
        opcua_registry(),
    )
}

// This fix is only for GCOV and LLVM_COV
// ----------------------------------------------------------------------------
// The linker error "undefined reference to 'atexit'" occurs when mixing AddressSanitizer (ASan), GCOV, and Rust's -nodefaultlibs.
// The Problem:
//    GCOV needs to register a "save-on-exit" handler via 'atexit' in function `llvm_gcov_init'.
//    However, because the PUT is built without its own standard library to avoid symbol conflicts, the GCOV runtime couldn't find the atexit symbol.
// The Fix:
//    A manual implementation of atexit in Rust that calls the lower-level GLIBC function __cxa_atexit.
//     Why __cxa_atexit? Calling libc::atexit directly would have caused an infinite recursion (stack overflow) because our wrapper was named atexit
#[no_mangle]
pub unsafe extern "C" fn atexit(f: extern "C" fn()) -> libc::c_int {
    extern "C" {
        fn __cxa_atexit(
            cb: extern "C" fn(*mut libc::c_void),
            arg: *mut libc::c_void,
            dso: *mut libc::c_void,
        ) -> libc::c_int;
    }

    extern "C" fn atexit_wrapper(arg: *mut libc::c_void) {
        unsafe {
            let f: extern "C" fn() = std::mem::transmute(arg);
            f();
        }
    }

    __cxa_atexit(
        atexit_wrapper,
        f as *mut libc::c_void,
        std::ptr::null_mut(),
    )
}