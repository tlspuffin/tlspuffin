use libc::{c_char, c_int, c_long, c_void, strlen};
use std::any::Any;
use std::ffi::CString;
use std::io;
use std::io::{ErrorKind, Read, Write};
use std::marker::PhantomData;
use std::mem::ManuallyDrop;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;
use std::slice;

use openssl::error::ErrorStack;
use openssl::ssl::{SslContextBuilder, SslVersion};
use openssl::{
    asn1::Asn1Time,
    bn::{BigNum, MsbOption},
    hash::MessageDigest,
    pkey::{PKey, PKeyRef, Private},
    version::version,
    x509::{
        extension::{BasicConstraints, KeyUsage, SubjectKeyIdentifier},
        X509NameBuilder, X509Ref, X509,
    },
};

use crate::agent::TLSVersion;
use crate::error::Error;
use crate::io::MemoryStream;
use crate::openssl_binding::static_rsa_cert;
use wolfssl::wolfssl_sys as wolf;

/* Note: for writing this, I tried to mimic the openssl::bio module. I adapted the calls to the C functions
from OpenSSL to WolfSSL but the internal calling conventions might differ so we may need to rework
this. */

/*******************
 WolfSSL BIO
********************/

pub type BIO = wolf::WOLFSSL_BIO;
#[allow(bad_style)]
unsafe fn BIO_set_flags(bio: *mut BIO, flags: c_int) {
    (*bio).flags = flags;
}

#[allow(bad_style)]
unsafe fn BIO_get_data(bio: *mut BIO) -> *mut c_void {
    (*bio).ptr
}

#[allow(bad_style)]
unsafe fn BIO_set_data(bio: *mut BIO, data: *mut c_void) {
    (*bio).ptr = data;
}

#[allow(bad_style)]
unsafe fn BIO_set_num(bio: *mut BIO, num: c_int) {
    (*bio).num = num;
}

unsafe fn BIO_set_init(bio: *mut BIO, num: c_int) {
    wolf::wolfSSL_BIO_set_init(bio, num);
}

pub const BIO_TYPE_NONE: c_int = 0;
pub const BIO_CTRL_EOF: c_int = 2;
pub const BIO_CTRL_INFO: c_int = 3;
pub const BIO_CTRL_FLUSH: c_int = 11;
pub const BIO_CTRL_DGRAM_QUERY_MTU: c_int = 40;
pub const BIO_C_SET_BUF_MEM_EOF_RETURN: c_int = 130;
pub const BIO_FLAGS_READ: c_int = 0x01;
pub const BIO_FLAGS_WRITE: c_int = 0x02;
pub const BIO_FLAGS_IO_SPECIAL: c_int = 0x04;
pub const BIO_FLAGS_RWS: c_int = BIO_FLAGS_READ | BIO_FLAGS_WRITE | BIO_FLAGS_IO_SPECIAL;
pub const BIO_FLAGS_SHOULD_RETRY: c_int = 0x08;

pub unsafe fn BIO_set_retry_read(b: *mut BIO) {
    BIO_set_flags(b, BIO_FLAGS_READ | BIO_FLAGS_SHOULD_RETRY)
}

pub unsafe fn BIO_set_retry_write(b: *mut BIO) {
    BIO_set_flags(b, BIO_FLAGS_WRITE | BIO_FLAGS_SHOULD_RETRY)
}

pub unsafe fn BIO_clear_retry_flags(b: *mut BIO) {
    wolf::wolfSSL_BIO_clear_flags(b, BIO_FLAGS_RWS | BIO_FLAGS_SHOULD_RETRY)
}

#[allow(clippy::match_like_matches_macro)] // matches macro requires rust 1.42.0
fn retriable_error(err: &io::Error) -> bool {
    match err.kind() {
        ErrorKind::WouldBlock | ErrorKind::NotConnected => true,
        _ => false,
    }
}

/*******************
 WolfSSL BIO METHOD
********************/
// struct BIO_METHOD(*mut wolf::WOLFSSL_BIO_METHOD);
/// Safe wrapper for BIO_METHOD
pub struct BioMethod(*mut wolf::WOLFSSL_BIO_METHOD);

pub struct StreamState<S> {
    pub stream: S,
    pub error: Option<io::Error>,
    pub panic: Option<Box<dyn Any + Send>>,
    pub dtls_mtu_size: c_long,
}
unsafe fn state<'a, S: 'a>(bio: *mut BIO) -> &'a mut StreamState<S> {
    &mut *(BIO_get_data(bio) as *mut _)
}

pub unsafe fn get_mut<'a, S: 'a>(bio: *mut BIO) -> &'a mut S {
    &mut state(bio).stream
}

pub unsafe fn take_error<S>(bio: *mut BIO) -> Option<io::Error> {
    let state = state::<S>(bio);  // [test_wolf_get_bio] [SEGFAULT] here we access the ptr field of bio that is set to NULL at this point
    state.error.take()  // BOOOM
}

pub unsafe fn take_panic<S>(bio: *mut BIO) -> Option<Box<dyn Any + Send>> {
    let state = state::<S>(bio);
    state.panic.take()
}

unsafe extern "C" fn bwrite<S: Write>(
    bio: *mut wolf::WOLFSSL_BIO,
    buf: *const c_char,
    len: c_int,
) -> c_int {
    wolf::wolfSSL_BIO_clear_retry_flags(bio);

    let state = state::<S>(bio);
    let buf = slice::from_raw_parts(buf as *const _, len as usize);

    match catch_unwind(AssertUnwindSafe(|| state.stream.write(buf))) {
        Ok(Ok(len)) => len as c_int,
        Ok(Err(err)) => {
            if retriable_error(&err) {
                BIO_set_retry_write(bio);
            }
            state.error = Some(err);
            -1
        }
        Err(err) => {
            state.panic = Some(err);
            -1
        }
    }
}

unsafe extern "C" fn bread<S: Read>(bio: *mut BIO, buf: *mut c_char, len: c_int) -> c_int {
    BIO_clear_retry_flags(bio);

    let state = state::<S>(bio);
    let buf = slice::from_raw_parts_mut(buf as *mut _, len as usize);

    match catch_unwind(AssertUnwindSafe(|| state.stream.read(buf))) {
        Ok(Ok(len)) => len as c_int,
        Ok(Err(err)) => {
            if retriable_error(&err) {
                BIO_set_retry_read(bio);
            }
            state.error = Some(err);
            -1
        }
        Err(err) => {
            state.panic = Some(err);
            -1
        }
    }
}
unsafe extern "C" fn bputs<S: Write>(bio: *mut BIO, s: *const c_char) -> c_int {
    bwrite::<S>(bio, s, strlen(s) as c_int)
}

unsafe extern "C" fn ctrl<S: Write>(
    bio: *mut BIO,
    cmd: c_int,
    _num: c_long,
    _ptr: *mut c_void,
) -> c_long {
    let state = state::<S>(bio);

    if cmd == BIO_CTRL_FLUSH {
        match catch_unwind(AssertUnwindSafe(|| state.stream.flush())) {
            Ok(Ok(())) => 1,
            Ok(Err(err)) => {
                state.error = Some(err);
                0
            }
            Err(err) => {
                state.panic = Some(err);
                0
            }
        }
    } else if cmd == BIO_CTRL_DGRAM_QUERY_MTU {
        state.dtls_mtu_size
    } else {
        0
    }
}

unsafe extern "C" fn create(bio: *mut BIO) -> c_int {
    BIO_set_init(bio, 0);
    BIO_set_num(bio, 0);
    BIO_set_data(bio, ptr::null_mut());
    BIO_set_flags(bio, 0);
    1
}

unsafe extern "C" fn destroy<S>(bio: *mut BIO) -> c_int {
    if bio.is_null() {
        return 0;
    }

    let data = BIO_get_data(bio);
    assert!(!data.is_null());
    Box::<StreamState<S>>::from_raw(data as *mut _);
    BIO_set_data(bio, ptr::null_mut());
    BIO_set_init(bio, 0);
    1
}

impl BioMethod {
    fn new<S: Read + Write>() -> Result<BioMethod, ErrorStack> {
        unsafe {
            let ptr = wolf::wolfSSL_BIO_meth_new(BIO_TYPE_NONE, b"rust\0".as_ptr() as *const _);
            let method = BioMethod(ptr); // we have one less wrapper compared to OpenSSL rust lib
            wolf::wolfSSL_BIO_meth_set_write(method.0, Some(bwrite::<S>));
            wolf::wolfSSL_BIO_meth_set_read(method.0, Some(bread::<S>));
            wolf::wolfSSL_BIO_meth_set_puts(method.0, Some(bputs::<S>));
            wolf::wolfSSL_BIO_meth_set_ctrl(method.0, Some(ctrl::<S>));
            wolf::wolfSSL_BIO_meth_set_create(method.0, Some(create));
            wolf::wolfSSL_BIO_meth_set_destroy(method.0, Some(destroy::<S>));
            Ok(method)
        }
    }
}

unsafe impl Sync for BioMethod {}
unsafe impl Send for BioMethod {}

/*******************
 Main function to create a new BIO bound to a given stream
********************/
pub fn bio_new<S: Read + Write>(stream: S) -> Result<(*mut BIO, BioMethod), ErrorStack> {
    let method = BioMethod::new::<S>()?;

    let state = Box::new(StreamState {
        stream,
        error: None,
        panic: None,
        dtls_mtu_size: 0,
    });

    unsafe {
        let bio = wolf::wolfSSL_BIO_new(method.0);
        wolf::wolfSSL_BIO_set_data(bio, Box::into_raw(state) as *mut _);
        BIO_set_init(bio, 1);

        Ok((bio, method))
    }
}
