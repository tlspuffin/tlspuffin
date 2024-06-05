use libc::c_ulong;
use openssl::ssl::SslContextBuilder;
use openssl_sys::SSL_CTX_set_options;

const SSL_OP_ALLOW_NO_DHE_KEX: c_ulong = 0x00000400;

/// In TLSv1.3 allow a non-(ec)dhe based key exchange mode on resumption.
/// This means that there will be no forward secrecy for the resumed session.
pub fn set_allow_no_dhe_kex(ctx: &mut SslContextBuilder) {
    unsafe { SSL_CTX_set_options(ctx.as_ptr(), SSL_OP_ALLOW_NO_DHE_KEX) };
}
