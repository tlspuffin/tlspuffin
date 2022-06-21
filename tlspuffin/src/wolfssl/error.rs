//! Errors returned by OpenSSL library.
//!
//! OpenSSL errors are stored in an `ErrorStack`.  Most methods in the crate
//! returns a `Result<T, ErrorStack>` type.
//!
use std::{error, ffi::CStr, fmt, io, ptr, str};

use libc::{c_char, c_int, c_ulong};
use wolfssl_sys as wolf;

/// Collection of [`Error`]s from OpenSSL.
///
/// [`Error`]: struct.Error.html
#[derive(Debug, Clone)]
pub struct ErrorStack(Vec<Error>);

impl ErrorStack {
    /// Returns the contents of the OpenSSL error stack.
    pub fn get() -> ErrorStack {
        let mut vec = vec![];
        while let Some(err) = Error::get() {
            vec.push(err);
        }
        ErrorStack(vec)
    }
}

impl ErrorStack {
    /// Returns the errors in the stack.
    pub fn errors(&self) -> &[Error] {
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

/// An error reported from WolfSSL.
#[derive(Clone)]
pub struct Error {
    code: c_ulong,
    file: *const c_char,
    line: c_int,
}

unsafe impl Sync for Error {}
unsafe impl Send for Error {}

impl Error {
    /// Returns the first error on the OpenSSL error stack.
    pub fn get() -> Option<Error> {
        unsafe {
            let mut file = ptr::null();
            let mut line = 0;

            match wolf::wolfSSL_ERR_get_error_line(&mut file, &mut line) {
                0 => None,
                code => {
                    // The memory referenced by data is only valid until that slot is overwritten
                    // in the error stack, so we'll need to copy it off if it's dynamic

                    Some(Error { code, file, line })
                }
            }
        }
    }

    /// Returns the raw OpenSSL error code for this error.
    pub fn code(&self) -> c_ulong {
        self.code
    }

    /// Returns the name of the library reporting the error, if available.
    pub fn library(&self) -> Option<&'static str> {
        unsafe {
            let cstr = wolfssl_sys::wolfSSL_ERR_lib_error_string(self.code);
            if cstr.is_null() {
                return None;
            }
            let bytes = CStr::from_ptr(cstr as *const _).to_bytes();
            Some(str::from_utf8(bytes).unwrap())
        }
    }

    /// Returns the reason for the error.
    pub fn reason(&self) -> Option<&'static str> {
        unsafe {
            let cstr = wolfssl_sys::wolfSSL_ERR_reason_error_string(self.code);
            if cstr.is_null() {
                return None;
            }
            let bytes = CStr::from_ptr(cstr as *const _).to_bytes();
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
}

impl fmt::Debug for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut builder = fmt.debug_struct("Error");
        builder.field("code", &self.code());
        if let Some(library) = self.library() {
            builder.field("library", &library);
        }
        if let Some(reason) = self.reason() {
            builder.field("reason", &reason);
        }
        builder.field("file", &self.file());
        builder.field("line", &self.line());
        builder.finish()
    }
}

impl fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(fmt, "error:{:08X}", self.code())?;
        match self.library() {
            Some(l) => write!(fmt, ":{}", l)?,
            None => write!(fmt, ":lib({})", unsafe {
                wolfssl_sys::wolfSSL_ERR_GET_LIB(self.code())
            })?,
        }
        match self.reason() {
            Some(r) => write!(fmt, ":{}", r)?,
            None => write!(fmt, ":reason({})", unsafe {
                wolfssl_sys::wolfSSL_ERR_GET_LIB(self.code())
            })?,
        }
        write!(fmt, ":{}:{}", self.file(), self.line())
    }
}

impl error::Error for Error {}

// ----

/// An error code returned from SSL functions.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct ErrorCode(c_int);

impl ErrorCode {
    /// The SSL session has been closed.
    pub const ZERO_RETURN: ErrorCode = ErrorCode(wolf::WOLFSSL_ERROR_ZERO_RETURN);

    /// An attempt to read data from the underlying socket returned `WouldBlock`.
    ///
    /// Wait for read readiness and retry the operation.
    pub const WANT_READ: ErrorCode = ErrorCode(wolf::WOLFSSL_ERROR_WANT_READ);

    /// An attempt to write data to the underlying socket returned `WouldBlock`.
    ///
    /// Wait for write readiness and retry the operation.
    pub const WANT_WRITE: ErrorCode = ErrorCode(wolf::WOLFSSL_ERROR_WANT_WRITE);

    /// A non-recoverable IO error occurred.
    pub const SYSCALL: ErrorCode = ErrorCode(wolf::WOLFSSL_ERROR_SYSCALL);

    /// An error occurred in the SSL library.
    pub const SSL: ErrorCode = ErrorCode(wolf::WOLFSSL_ERROR_SSL);

    pub fn from_raw(raw: c_int) -> ErrorCode {
        ErrorCode(raw)
    }

    #[allow(clippy::trivially_copy_pass_by_ref)]
    pub fn as_raw(&self) -> c_int {
        self.0
    }
}

#[derive(Debug)]
pub(crate) enum InnerError {
    Io(io::Error),
    Ssl(ErrorStack),
}

/// An SSL error.
#[derive(Debug)]
pub struct SslError {
    pub(crate) code: ErrorCode,
    pub(crate) cause: Option<InnerError>,
}

impl SslError {
    pub fn code(&self) -> ErrorCode {
        self.code
    }

    pub fn io_error(&self) -> Option<&io::Error> {
        match self.cause {
            Some(InnerError::Io(ref e)) => Some(e),
            _ => None,
        }
    }

    pub fn into_io_error(self) -> Result<io::Error, SslError> {
        match self.cause {
            Some(InnerError::Io(e)) => Ok(e),
            _ => Err(self),
        }
    }

    pub fn ssl_error(&self) -> Option<&ErrorStack> {
        match self.cause {
            Some(InnerError::Ssl(ref e)) => Some(e),
            _ => None,
        }
    }
}

impl From<ErrorStack> for SslError {
    fn from(e: ErrorStack) -> SslError {
        SslError {
            code: ErrorCode::SSL,
            cause: Some(InnerError::Ssl(e)),
        }
    }
}

impl fmt::Display for SslError {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.code {
            ErrorCode::ZERO_RETURN => fmt.write_str("the SSL session has been shut down"),
            ErrorCode::WANT_READ => match self.io_error() {
                Some(_) => fmt.write_str("a nonblocking read call would have blocked"),
                None => fmt.write_str("the operation should be retried"),
            },
            ErrorCode::WANT_WRITE => match self.io_error() {
                Some(_) => fmt.write_str("a nonblocking write call would have blocked"),
                None => fmt.write_str("the operation should be retried"),
            },
            ErrorCode::SYSCALL => match self.io_error() {
                Some(err) => write!(fmt, "{}", err),
                None => fmt.write_str("unexpected EOF"),
            },
            ErrorCode::SSL => match self.ssl_error() {
                Some(e) => write!(fmt, "{}", e),
                None => fmt.write_str("OpenSSL error"),
            },
            ErrorCode(code) => write!(fmt, "unknown error code {}", code),
        }
    }
}

impl error::Error for SslError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self.cause {
            Some(InnerError::Io(ref e)) => Some(e),
            Some(InnerError::Ssl(ref e)) => Some(e),
            None => None,
        }
    }
}
