use std::mem;

use libc::{c_int, c_ulong, c_void};
use security_claims::register::Claimer;
use wolfssl_sys as wolf;

use crate::wolfssl::transcript::claim_transcript;

pub unsafe extern "C" fn SSL_finished(
    _ssl: *mut wolf::WOLFSSL,
    _a: *const u8,
    _b: *const u8,
    _c: *mut u8,
    _d: *mut c_void,
) -> i32 {
    0
}

pub unsafe extern "C" fn SSL_keylog13(
    _ssl: *mut wolf::WOLFSSL,
    _a: c_int,
    _b: *const u8,
    _d: c_int,
    _c: *mut c_void,
) -> i32 {
    0
}

pub unsafe extern "C" fn SSL_info(_ssl: *const wolf::WOLFSSL, _a: c_int, _b: c_int) {}
pub unsafe extern "C" fn SSL_keylog(_ssl: *const wolf::WOLFSSL, _a: *const i8) {}

extern "C" {
    fn free(ptr: *mut c_void);
}

pub unsafe extern "C" fn SSL_connect_timeout_ex(_info: *mut wolf::TimeoutInfo) -> i32 {
    0
}

pub unsafe extern "C" fn SSL_connect_ex(_info: *mut wolf::HandShakeInfo) -> i32 {
    log::debug!("SSL_connect_ex");
    0
}
