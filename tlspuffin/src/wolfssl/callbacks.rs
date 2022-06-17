use std::{ffi::c_void, mem};

use foreign_types::ForeignTypeRef;
use libc::{c_int, c_ulong};
use wolfssl_sys as wolf;

use crate::wolfssl::Ssl;
use crate::wolfssl::{error::ErrorStack, ssl::SslRef};
pub unsafe extern "C" fn msg_callback<F>(
    write_p: c_int,
    version: c_int,
    content_type: c_int,
    buf: *const c_void,
    len: c_ulong,
    ssl: *mut wolf::WOLFSSL,
    arg: *mut c_void,
) where
    F: Fn(&mut SslRef) + 'static,
{
    let ssl = SslRef::from_ptr_mut(ssl);

    //let callback: &mut Box<F> = unsafe { mem::transmute(arg) };
    let callback = ssl
        .ex_data(Ssl::cached_ex_index::<F>())
        .expect("BUG: missing msg_callback") as *const F;

    (*callback)(ssl);
}
