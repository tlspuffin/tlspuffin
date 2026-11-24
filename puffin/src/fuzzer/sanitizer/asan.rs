//! Helpers for asan

use std::env;
use std::ffi::CStr;

#[cfg(target_os = "linux")]
unsafe extern "C" fn iter_libs(
    info: *mut libc::dl_phdr_info,
    _size: libc::size_t,
    _data: *mut libc::c_void,
) -> libc::c_int {
    let library_name = CStr::from_ptr((*info).dlpi_name).to_str().unwrap();
    if library_name.contains("libasan") || library_name.contains("libclang_rt.asan") {
        1
    } else {
        0
    }
}

/// The options ASan starts with in a binary that links its runtime, before ASAN_OPTIONS: those
/// fuzzing needs. ASan aborts on an error, so that the fuzzer records the crash and restarts the
/// client; it checks no leak at exit; and it stores no stack trace of an allocation or a free,
/// which a long campaign otherwise spends most of its time on (ASan's stack depot only grows).
/// Its reports, its handling of SEGV and its other defaults stay. ASAN_OPTIONS still overrides
/// each option, e.g. `malloc_context_size=30` to replay an objective with its allocation and free
/// stacks. libafl_targets' `src/common.c` has libafl's own set, for fuzzers that need only the
/// crash: compare it with this one at each libafl upgrade.
pub const DEFAULT_OPTIONS: &CStr = c"abort_on_error=1:detect_leaks=0:malloc_context_size=0";

/// ASan's hook for its default options, [`DEFAULT_OPTIONS`]. The shared ASan runtime calls the
/// binary's only if the binary exports it, which puffin-build has the linker do in a release build
/// of a PUT with ASan; otherwise (a debug build) it finds its own, empty, and the guard of the
/// fuzzing commands asks for ASAN_OPTIONS. libafl_targets defines one too with its
/// `sanitizers_flags` feature, which puffin leaves off: its `handle_segv=0` and `symbolize=0`
/// would change ASan's reports.
#[no_mangle]
pub extern "C" fn __asan_default_options() -> *const libc::c_char {
    DEFAULT_OPTIONS.as_ptr()
}

/// Whether the ASan runtime is linked into this process. `__asan_init` is the runtime's own: libafl
/// only stubs `__asan_region_is_poisoned` (and compiles in an `__asan_default_options`) in builds
/// without ASan.
pub fn asan_runtime_linked() -> bool {
    // SAFETY: dlsym with RTLD_DEFAULT and a NUL-terminated name only looks the symbol up.
    unsafe { !libc::dlsym(libc::RTLD_DEFAULT, c"__asan_init".as_ptr()).is_null() }
}

/// The default options the ASan runtime took at startup: the string of the
/// `__asan_default_options` the dynamic linker resolves, [`DEFAULT_OPTIONS`] when the binary
/// exports ours, the runtime's own (empty) otherwise.
fn runtime_default_options() -> String {
    // SAFETY: as in `asan_runtime_linked`; when found, the symbol is the C function
    // `const char *__asan_default_options(void)`, which returns a static NUL-terminated string.
    unsafe {
        let symbol = libc::dlsym(libc::RTLD_DEFAULT, c"__asan_default_options".as_ptr());
        if symbol.is_null() {
            return String::new();
        }
        let function = std::mem::transmute::<
            *mut libc::c_void,
            unsafe extern "C" fn() -> *const libc::c_char,
        >(symbol);
        let options = function();
        if options.is_null() {
            String::new()
        } else {
            CStr::from_ptr(options).to_string_lossy().into_owned()
        }
    }
}

/// The last setting of the boolean flag `name` in `options`, read as ASan's flag parser reads
/// them: flags separated by spaces, commas, colons or newlines; `1`, `yes` and `true` mean true.
fn bool_flag(options: &str, name: &str) -> Option<bool> {
    options
        .split([' ', ',', ':', '\n', '\t', '\r'])
        .filter_map(|flag| flag.split_once('='))
        .rfind(|(key, _)| *key == name)
        .map(|(_, value)| matches!(value.trim_matches(['"', '\'']), "1" | "yes" | "true"))
}

/// Whether ASan aborts on an error: its default (no), then the runtime's default options, then
/// ASAN_OPTIONS, a later setting overriding an earlier one.
fn aborts_on_error(default_options: &str, env_options: &str) -> bool {
    bool_flag(env_options, "abort_on_error")
        .or_else(|| bool_flag(default_options, "abort_on_error"))
        .unwrap_or(false)
}

/// Why this process must not fuzz, if ASan is linked and does not abort on an error: an ASan
/// report would then end a fuzzing client with `exit()` instead of `abort()`, and the fuzzer would
/// neither record the crash nor restart the client.
///
/// `env_options` is ASAN_OPTIONS as the process started with it, which the runtime parsed.
pub fn asan_abort_on_error_problem(env_options: &str) -> Option<String> {
    if !asan_runtime_linked() || aborts_on_error(&runtime_default_options(), env_options) {
        return None;
    }
    Some(format!(
        "this binary links the ASan runtime, but ASan's abort_on_error is off: an ASan report \
         would end a fuzzing client with exit() instead of abort(), so the fuzzer would neither \
         record the crash nor restart the client. Set abort_on_error=1 in ASAN_OPTIONS (now \
         \"{env_options}\"), e.g. ASAN_OPTIONS=verify_asan_link_order=1:detect_leaks=0:\
         abort_on_error=1 as .cargo/config.toml has it: cargo's [env] reaches only the processes \
         cargo starts, not a binary started directly, and does not replace an ASAN_OPTIONS \
         already set."
    ))
}

#[cfg(not(target_os = "linux"))]
pub const fn asan_info() {}

#[cfg(target_os = "linux")]
pub fn asan_info() {
    unsafe {
        if libc::dl_iterate_phdr(Some(iter_libs), std::ptr::null_mut()) > 0 {
            log::info!("Running with shared ASAN support.",)
        } else {
            log::info!("Running WITHOUT shared ASAN support.")
        }
    }

    log::info!(
        "ASAN env options: {}",
        env::var("ASAN_OPTIONS").unwrap_or_default(),
    );

    log::info!(
        "ASAN default options: {} (the runtime took \"{}\")",
        DEFAULT_OPTIONS.to_string_lossy(),
        runtime_default_options(),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_boolean_flag_is_its_last_setting() {
        assert_eq!(bool_flag("abort_on_error=1", "abort_on_error"), Some(true));
        assert_eq!(
            bool_flag("detect_leaks=0:abort_on_error=0", "abort_on_error"),
            Some(false)
        );
        assert_eq!(
            bool_flag("abort_on_error=1,abort_on_error=false", "abort_on_error"),
            Some(false)
        );
        assert_eq!(
            bool_flag("abort_on_error=yes detect_leaks=0", "abort_on_error"),
            Some(true)
        );
        assert_eq!(
            bool_flag("abort_on_error=true\nhalt_on_error=0", "abort_on_error"),
            Some(true)
        );
        assert_eq!(
            bool_flag("abort_on_errors=1:xabort_on_error=1", "abort_on_error"),
            None
        );
        assert_eq!(bool_flag("", "abort_on_error"), None);
    }

    #[test]
    fn asan_options_override_the_default_options() {
        assert!(!aborts_on_error("", ""));
        assert!(aborts_on_error("abort_on_error=1:detect_leaks=0", ""));
        assert!(!aborts_on_error("abort_on_error=1", "abort_on_error=0"));
        assert!(aborts_on_error(
            "",
            "verify_asan_link_order=1:detect_leaks=0:abort_on_error=1"
        ));
        assert!(!aborts_on_error("", "detect_leaks=0"));
    }

    #[test]
    fn the_default_options_are_those_fuzzing_needs() {
        let defaults = DEFAULT_OPTIONS.to_str().unwrap();
        assert!(aborts_on_error(defaults, ""));
        assert_eq!(bool_flag(defaults, "detect_leaks"), Some(false));
        assert!(defaults
            .split(':')
            .any(|flag| flag == "malloc_context_size=0"));
        // ASAN_OPTIONS still overrides them
        assert!(!aborts_on_error(defaults, "abort_on_error=0"));
    }

    #[test]
    fn without_the_asan_runtime_nothing_is_refused() {
        // puffin's tests do not link the ASan runtime
        assert!(!asan_runtime_linked());
        assert_eq!(asan_abort_on_error_problem(""), None);
    }
}
