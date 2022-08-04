//! Helpers for asan

use std::{env, ffi::CStr, ptr};

use log::info;


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

pub fn asan_info() {
    let defaults = unsafe {


        CStr::from_ptr(__asan_default_options()).to_str().unwrap()
    };

    info!(
        "ASAN env options: {}",
        env::var("ASAN_OPTIONS").unwrap_or_default(),
    );

    info!("ASAN default options: {}", defaults);
}
