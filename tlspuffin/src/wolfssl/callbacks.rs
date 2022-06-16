use crate::wolfssl::ssl::SslRef;
use libc::{c_int, c_ulong};
use std::ffi::c_void;
use std::mem;

use crate::wolfssl::error::ErrorStack;
use foreign_types::ForeignTypeRef;
use wolfssl_sys as wolf;

pub unsafe extern "C" fn msg_callback<F>(
    write_p: c_int,
    version: c_int,
    content_type: c_int,
    buf: *const c_void,
    len: c_ulong,
    ssl: *mut wolf::WOLFSSL,
    arg: *mut c_void,
) where
    F: Fn(&mut SslRef),
{
    let ssl = SslRef::from_ptr_mut(ssl);

    let callback: &mut Box<F> = unsafe { mem::transmute(arg) };

    callback(ssl);
}
