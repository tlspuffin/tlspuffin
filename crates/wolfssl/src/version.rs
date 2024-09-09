use std::ffi::CStr;

use wolfssl_sys as wolf;

/// The text variant of the version number and the release date. For example, "OpenSSL 0.9.5a 1 Apr
/// 2000".
pub unsafe fn version() -> &'static str {
    CStr::from_ptr(wolf::wolfSSL_lib_version())
        .to_str()
        .expect("Unable to read wolfSSL version")
}
