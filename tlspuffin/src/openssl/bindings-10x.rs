use std::ffi::c_void;

use foreign_types_openssl::ForeignTypeRef;
use libc::{c_int, c_long};
use openssl::{error::ErrorStack, pkey::Private, rsa::Rsa, ssl::SslContextBuilder};
use openssl_sys::{SSL_CTX_ctrl, RSA, SSL_CTX};

const SSL_CTRL_SET_TMP_RSA: c_int = 2;

#[allow(non_snake_case)]
unsafe fn SSL_CTX_set_tmp_rsa(ctx: *mut SSL_CTX, key: *mut RSA) -> c_long {
    SSL_CTX_ctrl(ctx, SSL_CTRL_SET_TMP_RSA, 0, key as *mut c_void)
}

/// Sets the parameters to be used during ephemeral RSA key exchange.
///
/// This corresponds to `SSL_CTX_set_tmp_rsa`.
pub fn set_tmp_rsa(ctx: &SslContextBuilder, key: &Rsa<Private>) -> Result<(), ErrorStack> {
    unsafe { cvt(SSL_CTX_set_tmp_rsa(ctx.as_ptr(), key.as_ptr()) as c_int).map(|_| ()) }
}

fn cvt(r: c_int) -> Result<c_int, ErrorStack> {
    if r <= 0 {
        Err(ErrorStack::get())
    } else {
        Ok(r)
    }
}
