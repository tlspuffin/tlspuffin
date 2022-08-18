use std::ffi::c_void;

use foreign_types_openssl::ForeignTypeRef;
use libc::{c_int, c_long, c_ulong};
use openssl::{
    error::ErrorStack,
    pkey::Private,
    rsa::Rsa,
    ssl::{SslContext, SslContextBuilder, SslContextRef, SslRef},
};
use openssl_sys::{SSL_CTX_ctrl, SSL_CTX_set_options, RSA, SSL, SSL_CTX};

const SSL_OP_ALLOW_NO_DHE_KEX: c_ulong = 0x00000400;
const SSL_CTRL_SET_TMP_RSA: c_int = 2;

unsafe fn SSL_CTX_set_tmp_rsa(ctx: *mut SSL_CTX, key: *mut RSA) -> c_long {
    SSL_CTX_ctrl(ctx, SSL_CTRL_SET_TMP_RSA, 0, key as *mut c_void)
}

extern "C" {
    fn SSL_clear(ssl: *mut SSL) -> c_int;

    #[cfg(not(feature = "openssl111"))]
    fn SSL_CTX_set_tmp_rsa_callback(
        ctx: *mut SSL_CTX,
        ecdh: unsafe extern "C" fn(ssl: *mut SSL, is_export: c_int, keylength: c_int) -> *mut RSA,
    );
}

#[cfg(all(
    any(feature = "openssl101f", feature = "openssl102u"),
    not(feature = "openssl111")
))]
unsafe extern "C" fn raw_tmp_rsa<F>(ssl: *mut SSL, is_export: c_int, keylength: c_int) -> *mut RSA
where
    F: Fn(&mut SslRef, bool, u32) -> Result<Rsa<Private>, ErrorStack> + 'static + Sync + Send,
{
    let ssl = SslRef::from_ptr_mut(ssl);
    let callback = ssl
        .ssl_context()
        .ex_data(SslContext::new_ex_index::<F>().unwrap())
        .expect("BUG: tmp rsa callback missing") as *const F;

    match (*callback)(ssl, is_export != 0, keylength as u32) {
        Ok(rsa_key) => {
            let ptr = rsa_key.as_ptr();
            std::mem::forget(rsa_key);
            ptr
        }
        Err(e) => {
            e.put();
            std::ptr::null_mut()
        }
    }
}

#[cfg(all(
    any(feature = "openssl101f", feature = "openssl102u"),
    not(feature = "openssl111")
))]
pub fn set_tmp_rsa_callback<F>(ctx: &mut SslContextBuilder, callback: F)
where
    F: Fn(&mut SslRef, bool, u32) -> Result<Rsa<Private>, ErrorStack> + 'static + Sync + Send,
{
    unsafe {
        ctx.set_ex_data(SslContext::new_ex_index::<F>().unwrap(), callback);
        SSL_CTX_set_tmp_rsa_callback(ctx.as_ptr(), raw_tmp_rsa::<F>);
    }
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

/// In TLSv1.3 allow a non-(ec)dhe based key exchange mode on resumption.
/// This means that there will be no forward secrecy for the resumed session.
pub fn set_allow_no_dhe_kex(ctx: &mut SslContextBuilder) {
    unsafe { SSL_CTX_set_options(ctx.as_ptr(), SSL_OP_ALLOW_NO_DHE_KEX) };
}

pub fn clear(ssl: &SslRef) -> u32 {
    unsafe { SSL_clear(ssl.as_ptr()) as u32 }
}
