use std::process::ExitCode;

use opcuapuffin::put_registry::opcua_registry;

pub fn main() -> ExitCode {
    puffin::cli::main(
        "Fuzzes the OPC UA protocol at the symbolic level",
        opcua_registry(),
    )
}

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
