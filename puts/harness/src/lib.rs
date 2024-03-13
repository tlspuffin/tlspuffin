mod bindings {
    #![allow(non_upper_case_globals)]
    #![allow(non_camel_case_types)]
    #![allow(non_snake_case)]
    #![allow(improper_ctypes)]
    #![allow(dead_code)]
    #![allow(clippy::all)]
    include!(env!("RUST_BINDINGS_FILE"));
}

mod init {
    include!(env!("RUST_PUTS_INIT_FILE"));
}

pub use bindings::*;
pub use init::*;

use puffin::error::Error;
use std::io;

use libc::{c_char, c_void};

pub static mut PUTS: Vec<&C_PUT_TYPE> = vec![];

macro_rules! define_extern_c_log {
    ( $level:ident, $name:ident ) => {
        unsafe extern "C" fn $name(message: *const c_char) {
            log::log!(log::Level::$level, "{}", to_string(message));
        }
    };
}

define_extern_c_log!(Error, c_log_error);
define_extern_c_log!(Warn, c_log_warn);
define_extern_c_log!(Info, c_log_info);
define_extern_c_log!(Debug, c_log_debug);
define_extern_c_log!(Trace, c_log_trace);

#[no_mangle]
pub static TLSPUFFIN: C_TLSPUFFIN = C_TLSPUFFIN {
    register_put: Some(register_put),
    error: Some(c_log_error),
    warn: Some(c_log_warn),
    info: Some(c_log_info),
    debug: Some(c_log_debug),
    trace: Some(c_log_trace),
    make_result: Some(make_result),
};

pub unsafe fn to_string(ptr: *const c_char) -> String {
    use std::ffi::CStr;

    if ptr.is_null() {
        return "".to_owned();
    }

    CStr::from_ptr(ptr).to_string_lossy().as_ref().to_owned()
}

use crate::bindings::{
    RESULT_CODE_RESULT_ERROR_FATAL, RESULT_CODE_RESULT_IO_WOULD_BLOCK, RESULT_CODE_RESULT_OK,
};

unsafe extern "C" fn register_put(put: *const C_PUT_TYPE) {
    if put.is_null() {
        return;
    }

    PUTS.push(&*put)
}

unsafe extern "C" fn make_result(code: RESULT_CODE, description: *const c_char) -> *mut c_void {
    let reason = to_string(description);

    let result = Box::new(match code {
        RESULT_CODE_RESULT_OK => Ok(reason),
        RESULT_CODE_RESULT_IO_WOULD_BLOCK => Err(CError {
            kind: CErrorKind::IOWouldBlock,
            reason,
        }),
        RESULT_CODE_RESULT_ERROR_FATAL => Err(CError {
            kind: CErrorKind::Fatal,
            reason,
        }),
        _ => Err(CError {
            kind: CErrorKind::Error,
            reason,
        }),
    });

    Box::into_raw(result) as *mut _
}

#[derive(Debug, Clone)]
pub struct CError {
    pub kind: CErrorKind,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub enum CErrorKind {
    IOWouldBlock,
    Error,
    Fatal,
}

impl From<CError> for io::Error {
    fn from(e: CError) -> io::Error {
        io::Error::new(
            match e.kind {
                CErrorKind::IOWouldBlock => io::ErrorKind::WouldBlock,
                _ => io::ErrorKind::Other,
            },
            e.reason,
        )
    }
}

impl From<CError> for Error {
    fn from(e: CError) -> Error {
        Error::Put(e.reason)
    }
}
