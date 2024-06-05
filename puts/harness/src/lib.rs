mod bindings {
    #![allow(non_upper_case_globals)]
    #![allow(non_camel_case_types)]
    #![allow(non_snake_case)]
    #![allow(improper_ctypes)]
    #![allow(dead_code)]
    #![allow(clippy::all)]
    include!(env!("RUST_BINDINGS_FILE"));
}

use std::collections::{HashMap, HashSet};

pub use bindings::*;

pub const RUST_PUT_HARNESS: &str = "TLSPUFFIN_RUST_PUT";

#[cfg(feature = "cputs")]
mod init {
    use std::sync::Mutex;

    use once_cell::sync::Lazy;

    use crate::{CPutHarness, CPutLibrary, C_PUT_INTERFACE};

    pub static TLS_C_PUTS: Lazy<Mutex<Vec<(CPutHarness, CPutLibrary, C_PUT_INTERFACE)>>> =
        Lazy::new(|| Mutex::new(vec![]));

    #[allow(dead_code)]
    fn register_one_put(harness: CPutHarness, library: CPutLibrary, interface: C_PUT_INTERFACE) {
        TLS_C_PUTS
            .lock()
            .unwrap()
            .push((harness, library, interface));
    }

    include!(env!("RUST_PUTS_INIT_FILE"));
}

#[cfg(feature = "cputs")]
pub use crate::init::register;

#[derive(Clone)]
pub struct CPutHarness {
    pub name: String,
    pub version: String,
    pub capabilities: HashSet<String>,
}

#[derive(Clone)]
pub struct CPutLibrary {
    pub name: String,
    pub version: String,

    pub config_name: String,
    pub config_hash: String,

    pub with_sancov: bool,
    pub with_asan: bool,
    pub with_gcov: bool,
    pub with_llvm_cov: bool,

    pub known_vulnerabilities: Vec<String>,
}

use std::ffi::{c_char, c_void};

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
    if ptr.is_null() {
        return "".to_owned();
    }

    std::ffi::CStr::from_ptr(ptr)
        .to_string_lossy()
        .as_ref()
        .to_owned()
}

use crate::bindings::RESULT_CODE;

unsafe extern "C" fn make_result(code: RESULT_CODE, description: *const c_char) -> *mut c_void {
    let reason = to_string(description);

    let result = Box::new(match code {
        RESULT_CODE::RESULT_OK => Ok(reason),
        RESULT_CODE::RESULT_IO_WOULD_BLOCK => Err(CError {
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

static TLS_PUTS: once_cell::sync::Lazy<
    HashMap<String, (CPutHarness, CPutLibrary, C_PUT_INTERFACE)>,
> = once_cell::sync::Lazy::new(|| {
    #[allow(dead_code)]
    fn wrap_rust_put(
        library_name: &str,
        config_name: &str,
        capabilities: HashSet<&str>,
        known_vulnerabilities: Vec<&str>,
    ) -> (String, (CPutHarness, CPutLibrary, C_PUT_INTERFACE)) {
        let harness = CPutHarness {
            name: RUST_PUT_HARNESS.to_owned(),
            version: puffin::VERSION_STR.to_owned(),
            capabilities: capabilities.into_iter().map(str::to_owned).collect(),
        };

        let library = CPutLibrary {
            name: library_name.to_owned(),
            version: "unknown".to_owned(),

            config_name: config_name.to_owned(),
            config_hash: config_name.to_owned(),

            with_sancov: cfg!(feature = "sancov"),
            with_asan: cfg!(feature = "asan"),
            with_gcov: cfg!(feature = "gcov"),
            with_llvm_cov: cfg!(feature = "llvm_cov"),

            known_vulnerabilities: known_vulnerabilities
                .into_iter()
                .map(str::to_owned)
                .collect(),
        };

        (
            config_name.to_owned(),
            (harness, library, Default::default()),
        )
    }

    #[allow(unused_mut)]
    let mut result: HashMap<String, (CPutHarness, CPutLibrary, C_PUT_INTERFACE)> = HashMap::from(
        [
            #[cfg(feature = "libressl333")]
            (
                "libressl",
                "libressl333",
                HashSet::from([
                    "tls12",
                    "tls13",
                    "tls12_session_resumption",
                    "deterministic",
                    "claims",
                    "transcript_extraction",
                    "openssl_binding",
                ]),
                vec![],
            ),
            #[cfg(feature = "openssl101f")]
            (
                "openssl",
                "openssl101f",
                HashSet::from([
                    "tls12",
                    "tls12_session_resumption",
                    "deterministic",
                    "openssl_binding",
                    "openssl101_binding",
                ]),
                vec!["cve_2014_0160", "cve_2015_0204"],
            ),
            #[cfg(feature = "openssl102u")]
            (
                "openssl",
                "openssl102u",
                HashSet::from([
                    "tls12",
                    "tls12_session_resumption",
                    "deterministic",
                    "openssl_binding",
                    "openssl102_binding",
                ]),
                vec![],
            ),
            #[cfg(feature = "openssl111j")]
            (
                "openssl",
                "openssl111j",
                HashSet::from([
                    "tls12",
                    "tls13",
                    "tls12_session_resumption",
                    "tls13_session_resumption",
                    "deterministic",
                    "claims",
                    "transcript_extraction",
                    "client_authentication_transcript_extraction",
                    "openssl_binding",
                    "openssl111_binding",
                ]),
                vec!["cve_2021_3449"],
            ),
            #[cfg(feature = "openssl111k")]
            (
                "openssl",
                "openssl111k",
                HashSet::from([
                    "tls12",
                    "tls13",
                    "tls12_session_resumption",
                    "tls13_session_resumption",
                    "deterministic",
                    "claims",
                    "transcript_extraction",
                    "client_authentication_transcript_extraction",
                    "openssl_binding",
                    "openssl111_binding",
                ]),
                vec![],
            ),
            #[cfg(feature = "openssl111u")]
            (
                "openssl",
                "openssl111u",
                HashSet::from([
                    "tls12",
                    "tls13",
                    "tls12_session_resumption",
                    "tls13_session_resumption",
                    "deterministic",
                    "claims",
                    "transcript_extraction",
                    "client_authentication_transcript_extraction",
                    "openssl_binding",
                    "openssl111_binding",
                ]),
                vec![],
            ),
            #[cfg(feature = "openssl312")]
            (
                "openssl",
                "openssl312",
                HashSet::from([
                    "tls12",
                    "tls13",
                    "tls12_session_resumption",
                    "tls13_session_resumption",
                    "deterministic",
                    "claims",
                    "transcript_extraction",
                    "client_authentication_transcript_extraction",
                    "openssl_binding",
                    "openssl111_binding",
                ]),
                vec![],
            ),
            #[cfg(feature = "wolfssl540")]
            (
                "wolfssl",
                "wolfssl540",
                HashSet::from([
                    "tls12",
                    "tls13",
                    "tls12_session_resumption",
                    "tls13_session_resumption",
                    "transcript_extraction",
                    "client_authentication_transcript_extraction",
                    "wolfssl_binding",
                    "wolfssl_binding5xx",
                    #[cfg(feature = "wolfssl_disable_postauth")]
                    "wolfssl_disable_postauth",
                ]),
                vec![
                    #[cfg(not(feature = "wolfssl_fix_CVE_2022_39173"))]
                    "cve_2022_39173",
                    #[cfg(not(feature = "wolfssl_fix_CVE_2022_42905"))]
                    "cve_2022_42905",
                    #[cfg(feature = "wolfssl_disable_postauth")]
                    "cve_2022_38152",
                ],
            ),
            #[cfg(feature = "wolfssl530")]
            (
                "wolfssl",
                "wolfssl530",
                HashSet::from([
                    "tls12",
                    "tls13",
                    "tls12_session_resumption",
                    "tls13_session_resumption",
                    "transcript_extraction",
                    "client_authentication_transcript_extraction",
                    "wolfssl_binding",
                    "wolfssl_binding5xx",
                    #[cfg(feature = "wolfssl_disable_postauth")]
                    "wolfssl_disable_postauth",
                ]),
                vec![
                    #[cfg(not(feature = "wolfssl_fix_CVE_2022_39173"))]
                    "cve_2022_39173",
                    #[cfg(not(feature = "wolfssl_fix_CVE_2022_42905"))]
                    "cve_2022_42905",
                    #[cfg(feature = "wolfssl_disable_postauth")]
                    "cve_2022_38152",
                    "cve_2022_38153",
                ],
            ),
            #[cfg(feature = "wolfssl520")]
            (
                "wolfssl",
                "wolfssl520",
                HashSet::from([
                    "tls12",
                    "tls13",
                    "tls12_session_resumption",
                    "tls13_session_resumption",
                    "transcript_extraction",
                    "client_authentication_transcript_extraction",
                    "wolfssl_binding",
                    "wolfssl_binding5xx",
                    #[cfg(feature = "wolfssl_disable_postauth")]
                    "wolfssl_disable_postauth",
                ]),
                vec![
                    #[cfg(not(feature = "wolfssl_fix_CVE_2022_39173"))]
                    "cve_2022_39173",
                    #[cfg(not(feature = "wolfssl_fix_CVE_2022_42905"))]
                    "cve_2022_42905",
                    #[cfg(feature = "wolfssl_disable_postauth")]
                    "cve_2022_38152",
                ],
            ),
            #[cfg(feature = "wolfssl510")]
            (
                "wolfssl",
                "wolfssl510",
                HashSet::from([
                    "tls12",
                    "tls13",
                    "tls12_session_resumption",
                    "tls13_session_resumption",
                    "transcript_extraction",
                    "client_authentication_transcript_extraction",
                    "wolfssl_binding",
                    "wolfssl_binding5xx",
                    #[cfg(feature = "wolfssl_disable_postauth")]
                    "wolfssl_disable_postauth",
                ]),
                vec![
                    #[cfg(not(feature = "wolfssl_fix_CVE_2022_25638"))]
                    "cve_2022_25638",
                    #[cfg(not(feature = "wolfssl_fix_CVE_2022_25640"))]
                    "cve_2022_25640",
                    #[cfg(not(feature = "wolfssl_fix_CVE_2022_39173"))]
                    "cve_2022_39173",
                    #[cfg(not(feature = "wolfssl_fix_CVE_2022_42905"))]
                    "cve_2022_42905",
                    #[cfg(feature = "wolfssl_disable_postauth")]
                    "cve_2022_38152",
                ],
            ),
            #[cfg(feature = "wolfssl430")]
            (
                "wolfssl",
                "wolfssl430",
                HashSet::from([
                    "tls12",
                    "tls13",
                    "transcript_extraction",
                    "wolfssl_binding",
                    "wolfssl_binding4xx",
                    #[cfg(feature = "wolfssl_disable_postauth")]
                    "wolfssl_disable_postauth",
                ]),
                vec![
                    #[cfg(not(feature = "wolfssl_fix_CVE_2022_25638"))]
                    "cve_2022_25638",
                    #[cfg(not(feature = "wolfssl_fix_CVE_2022_25640"))]
                    "cve_2022_25640",
                    #[cfg(not(feature = "wolfssl_fix_CVE_2022_39173"))]
                    "cve_2022_39173",
                    #[cfg(not(feature = "wolfssl_fix_CVE_2022_42905"))]
                    "cve_2022_42905",
                    #[cfg(feature = "wolfssl_disable_postauth")]
                    "cve_2022_38152",
                ],
            ),
            #[cfg(feature = "boringssl202403")]
            (
                "boringssl",
                "boringssl202403",
                HashSet::from([
                    "tls12",
                    "tls13",
                    "tls12_session_resumption",
                    "tls13_session_resumption",
                    "deterministic",
                    "claims",
                    "transcript_extraction",
                    "client_authentication_transcript_extraction",
                    "boringssl_binding",
                ]),
                vec![],
            ),
            #[cfg(feature = "boringssl202311")]
            (
                "boringssl",
                "boringssl202311",
                HashSet::from([
                    "tls12",
                    "tls13",
                    "tls12_session_resumption",
                    "tls13_session_resumption",
                    "deterministic",
                    "claims",
                    "transcript_extraction",
                    "client_authentication_transcript_extraction",
                    "boringssl_binding",
                ]),
                vec![],
            ),
        ]
        .map(
            |(library_name, config_name, capabilities, known_vulnerabilities)| {
                wrap_rust_put(
                    library_name,
                    config_name,
                    capabilities,
                    known_vulnerabilities,
                )
            },
        ),
    );

    #[cfg(feature = "cputs")]
    {
        crate::init::register();

        crate::init::TLS_C_PUTS
            .lock()
            .unwrap()
            .iter()
            .for_each(|(harness, library, interface)| {
                result.insert(
                    library.config_name.to_string(),
                    (harness.clone(), library.clone(), interface.clone()),
                );
            });
    }

    result
});

pub fn tls_puts() -> HashMap<String, (CPutHarness, CPutLibrary, C_PUT_INTERFACE)> {
    TLS_PUTS.clone()
}
