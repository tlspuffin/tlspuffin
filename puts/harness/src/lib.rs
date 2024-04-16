mod bindings {
    #![allow(non_upper_case_globals)]
    #![allow(non_camel_case_types)]
    #![allow(non_snake_case)]
    #![allow(improper_ctypes)]
    #![allow(dead_code)]
    #![allow(clippy::all)]
    include!(env!("RUST_BINDINGS_FILE"));
}

pub use bindings::*;

mod init {
    use crate::{CPutHarness, CPutLibrary, C_PUT_TYPE};

    #[allow(unused)]
    type FnRegister = unsafe extern "C" fn(data: *mut libc::c_void, cput: *const C_PUT_TYPE) -> ();

    struct RegistrationContext<'a, F>
    where
        F: FnMut(CPutHarness, CPutLibrary, *const C_PUT_TYPE),
    {
        pub harness: CPutHarness,
        pub library: CPutLibrary,
        pub callback: &'a mut F,
    }

    #[allow(unused)]
    fn do_register<F>(
        harness: CPutHarness,
        library: CPutLibrary,
        registration: unsafe extern "C" fn(data: *mut libc::c_void, cb: FnRegister),
        callback: &mut F,
    ) where
        F: FnMut(CPutHarness, CPutLibrary, *const C_PUT_TYPE),
    {
        let data = Box::into_raw(Box::new(RegistrationContext {
            harness,
            library,
            callback,
        }));

        unsafe {
            registration(data as *mut _, do_call::<F>);
        }
    }

    unsafe extern "C" fn do_call<'a, F>(data: *mut libc::c_void, put: *const C_PUT_TYPE)
    where
        F: FnMut(CPutHarness, CPutLibrary, *const C_PUT_TYPE) + 'a,
    {
        let context: RegistrationContext<'a, F> = *Box::from_raw(data as *mut _);

        (context.callback)(context.harness, context.library, put)
    }

    include!(env!("RUST_PUTS_INIT_FILE"));
}

#[derive(Clone)]
pub struct CPutHarness {
    pub name: std::borrow::Cow<'static, str>,
    pub version: std::borrow::Cow<'static, str>,
}

#[derive(Clone)]
pub struct CPutLibrary {
    pub name: std::borrow::Cow<'static, str>,
    pub version: std::borrow::Cow<'static, str>,

    pub config_name: std::borrow::Cow<'static, str>,
    pub config_hash: std::borrow::Cow<'static, str>,
}

pub use init::*;
use libc::{c_char, c_void};
use puffin::error::Error;

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
    error: Some(c_log_error),
    warn: Some(c_log_warn),
    info: Some(c_log_info),
    debug: Some(c_log_debug),
    trace: Some(c_log_trace),
    make_result: Some(make_result),
};

/// # Safety
///
/// * Passing a NULL pointer is allowed and will return an empty [String].
///
/// * When `ptr` is non-NULL, the pointed memory must respect the same
///   constraints as a memory buffer passed to [std::ffi::CStr::from_ptr].
///
pub unsafe fn to_string(ptr: *const c_char) -> String {
    use std::ffi::CStr;

    if ptr.is_null() {
        return "".to_owned();
    }

    CStr::from_ptr(ptr).to_string_lossy().as_ref().to_owned()
}

use crate::bindings::{RESULT_CODE_RESULT_IO_WOULD_BLOCK, RESULT_CODE_RESULT_OK};

unsafe extern "C" fn make_result(code: RESULT_CODE, description: *const c_char) -> *mut c_void {
    let reason = to_string(description);

    let result = Box::new(match code {
        RESULT_CODE_RESULT_OK => Ok(reason),
        RESULT_CODE_RESULT_IO_WOULD_BLOCK => Err(CError {
            kind: CErrorKind::IOWouldBlock,
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

impl From<CError> for std::io::Error {
    fn from(e: CError) -> std::io::Error {
        std::io::Error::new(
            match e.kind {
                CErrorKind::IOWouldBlock => std::io::ErrorKind::WouldBlock,
                _ => std::io::ErrorKind::Other,
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
