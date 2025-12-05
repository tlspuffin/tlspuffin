//! Bindings for the [open62541](https://www.open62541.org) library.
//!
//! If you are looking for safe Rust bindings that can be used directly, see crate [`open62541`].
//!
//! [`open62541`]: https://crates.io/crates/open62541

use core::ffi;

pub use crate::puts::open62541::raw::*;

// For some reason, `bindgen` generates different type signatures with variadic arguments. We try to
// export a single type that can be used instead, e.g. in `UA_Logger::log`.
#[cfg(all(unix, target_arch = "x86_64"))]
#[expect(non_camel_case_types, reason = "match open62541 type")]
#[doc(hidden)] // Not part of stable, public crate API.
pub type va_list_ = *mut __va_list_tag;
#[cfg(not(all(unix, target_arch = "x86_64")))]
#[expect(non_camel_case_types, reason = "match open62541 type")]
#[doc(hidden)] // Not part of stable, public crate API.
pub type va_list_ = va_list;

/// Callback type used for [`UA_Logger::log`].
#[expect(non_camel_case_types, reason = "match open62541 type")]
#[expect(clippy::allow_attributes, reason = "Rust versions")]
#[allow(non_snake_case, reason = "match open62541 type")]
#[doc(hidden)] // Not part of stable, public crate API.
pub type UA_LoggerLogCallback_ = Option<
    unsafe extern "C" fn(
        logContext: *mut ffi::c_void,
        level: UA_LogLevel,
        category: UA_LogCategory,
        msg: *const ffi::c_char,
        // Use unified type from above.
        args: va_list_,
    ),
>;

/// Callback type used for [`UA_Logger::clear`].
#[expect(non_camel_case_types, reason = "match open62541 type")]
#[doc(hidden)] // Not part of stable, public crate API.
pub type UA_LoggerClearCallback_ = Option<unsafe extern "C" fn(logger: *mut UA_Logger)>;