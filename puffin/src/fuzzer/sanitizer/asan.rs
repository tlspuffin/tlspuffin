//! Helpers for asan

use std::{env, ffi::CStr};

use log::info;

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

extern "C" {
    fn __asan_default_options() -> *mut libc::c_char;
}

/// Setups the environment variable for ASAN, because `__asan_default_options` is unreliable.
/// https://www.mail-archive.com/ubuntu-bugs@lists.ubuntu.com/msg6005262.html
pub fn setup_asan_env() {
    info!("Appending default options to env options..");
    let defaults = unsafe { CStr::from_ptr(__asan_default_options()).to_str().unwrap() };

    env::set_var(
        "ASAN_OPTIONS",
        format!(
            "{}:{}",
            env::var("ASAN_OPTIONS").unwrap_or_default(),
            defaults,
        ),
    );
}

#[cfg(not(target_os = "linux"))]
pub fn asan_info() {}

#[cfg(target_os = "linux")]
pub fn asan_info() {
    let defaults = unsafe {
        if libc::dl_iterate_phdr(Some(iter_libs), std::ptr::null_mut()) > 0 {
            info!("Running with shared ASAN support.",)
        } else {
            info!("Running WITHOUT shared ASAN support.")
        }

        CStr::from_ptr(__asan_default_options()).to_str().unwrap()
    };

    info!(
        "ASAN env options: {}",
        env::var("ASAN_OPTIONS").unwrap_or_default(),
    );

    info!("ASAN default options: {}", defaults);
}
