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
pub unsafe extern "C" fn atexit(f: extern "C" fn()) -> libc::c_int {
    // This shim shadows libc's `atexit` for the whole binary (the GCOV runtime in the
    // -nodefaultlibs PUT resolves the symbol here). Returning success without registering `f`
    // (the previous behaviour) meant GCOV's save-on-exit handler never ran, silently dropping the
    // `.gcda` data. Forward to the real libc `atexit` so the handler is actually registered.
    let real = libc::dlsym(libc::RTLD_NEXT, b"atexit\0".as_ptr().cast());
    if real.is_null() {
        // Best effort: run the handler now so coverage is flushed at least once.
        f();
        return 0;
    }
    let real_atexit: extern "C" fn(extern "C" fn()) -> libc::c_int = std::mem::transmute(real);
    real_atexit(f)
}
