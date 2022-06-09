//! Errors returned by OpenSSL library.
//!
//! OpenSSL errors are stored in an `ErrorStack`.  Most methods in the crate
//! returns a `Result<T, ErrorStack>` type.
//!
//! # Examples
//!
//! ```
//! use openssl::error::ErrorStack;
//! use openssl::bn::BigNum;
//!
//! let an_error = BigNum::from_dec_str("Cannot parse letters");
//! match an_error {
//!     Ok(_)  => (),
//!     Err(e) => println!("Parsing Error: {:?}", e),
//! }
//! ```
use libc::{c_char, c_int, c_ulong};
use std::borrow::Cow;
use std::error;
use std::ffi::CStr;
use std::fmt;
use std::io;
use std::ptr;
use std::str;

use crate::error::Error;

/// Collection of [`Error`]s from OpenSSL.
///
/// [`Error`]: struct.Error.html
#[derive(Debug, Clone)]
pub struct ErrorStack(pub Vec<WolfError>);

impl ErrorStack {}

impl ErrorStack {
    /// Returns the errors in the stack.
    pub fn errors(&self) -> &[WolfError] {
        &self.0
    }
}

impl fmt::Display for ErrorStack {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.is_empty() {
            return fmt.write_str("OpenSSL error");
        }

        let mut first = true;
        for err in &self.0 {
            if !first {
                fmt.write_str(", ")?;
            }
            write!(fmt, "{}", err)?;
            first = false;
        }
        Ok(())
    }
}

impl error::Error for ErrorStack {}

impl From<ErrorStack> for io::Error {
    fn from(e: ErrorStack) -> io::Error {
        io::Error::new(io::ErrorKind::Other, e)
    }
}

impl From<ErrorStack> for fmt::Error {
    fn from(_: ErrorStack) -> fmt::Error {
        fmt::Error
    }
}

impl From<ErrorStack> for WolfError {
    fn from(_: ErrorStack) -> WolfError {
        WolfError {
            code: todo!(),
            file: todo!(),
            line: todo!(),
            func: todo!(),
            data: todo!(),
        }
    }
}

impl From<WolfError> for Error {
    fn from(_: WolfError) -> Error {
        Error::OpenSSL("woflssl".to_string())
    }
}

/// An error reported from OpenSSL.
#[derive(Clone)]
pub struct WolfError {
    code: c_ulong,
    file: *const c_char,
    line: c_int,
    func: *const c_char,
    data: Option<Cow<'static, str>>,
}

unsafe impl Sync for WolfError {}
unsafe impl Send for WolfError {}

impl WolfError {
    /// Returns the raw OpenSSL error code for this error.
    pub fn code(&self) -> c_ulong {
        self.code
    }

    /// Returns the name of the function reporting the error.
    pub fn function(&self) -> Option<&'static str> {
        unsafe {
            if self.func.is_null() {
                return None;
            }
            let bytes = CStr::from_ptr(self.func).to_bytes();
            Some(str::from_utf8(bytes).unwrap())
        }
    }

    /// Returns the name of the source file which encountered the error.
    pub fn file(&self) -> &'static str {
        unsafe {
            assert!(!self.file.is_null());
            let bytes = CStr::from_ptr(self.file as *const _).to_bytes();
            str::from_utf8(bytes).unwrap()
        }
    }

    /// Returns the line in the source file which encountered the error.
    pub fn line(&self) -> u32 {
        self.line as u32
    }

    /// Returns additional data describing the error.
    #[allow(clippy::option_as_ref_deref)]
    pub fn data(&self) -> Option<&str> {
        self.data.as_ref().map(|s| &**s)
    }
}

impl fmt::Debug for WolfError {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut builder = fmt.debug_struct("Error");
        builder.field("code", &self.code());
        if let Some(function) = self.function() {
            builder.field("function", &function);
        }
        builder.field("file", &self.file());
        builder.field("line", &self.line());
        if let Some(data) = self.data() {
            builder.field("data", &data);
        }
        builder.finish()
    }
}

impl error::Error for WolfError {}

impl fmt::Display for WolfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}
