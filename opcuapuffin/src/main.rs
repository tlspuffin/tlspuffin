use std::process::ExitCode;

use opcuapuffin::put_registry::opcua_registry;

pub fn main() -> ExitCode {
    puffin::cli::main(
        "Fuzzes the OPC UA protocol at the symbolic level",
        opcua_registry(),
    )
}

// This fix is only for GCOV
// ----------------------------------------------------------------------------
// The linker error "undefined reference to 'atexit'" occurs when mixing AddressSanitizer (ASan),
// GCOV, and Rust's -nodefaultlibs.    GCOV needs to register a "save-on-exit" handler via 'atexit'
// in function `llvm_gcov_init'.    However, because the PUT is built without its own standard
// library to avoid symbol conflicts, the GCOV runtime couldn't find the atexit symbol.
#[no_mangle]
#[cfg(feature = "gcov")]
pub unsafe extern "C" fn atexit(_f: extern "C" fn()) -> libc::c_int {
    0
}
