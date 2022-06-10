//! Note: for writing this, I tried to mimic the openssl::bio module. I adapted the calls to the C
//! functions from OpenSSL to WolfSSL but the internal calling conventions might differ so we may
//! need to rework this.

use std::{
    any::Any,
    io,
    io::{ErrorKind, Read, Write},
    marker::PhantomData,
    mem::ManuallyDrop,
    panic::{catch_unwind, AssertUnwindSafe},
    ptr, slice,
};

use libc::{c_char, c_int, c_long, c_uint, c_void, strlen};
use wolfssl_sys as wolf;

use super::error::ErrorStack;
use crate::{
    agent::TLSVersion,
    error::Error,
    io::MemoryStream,
    wolfssl::util::{cvt, cvt_n, cvt_p},
};

pub type BIO = wolf::WOLFSSL_BIO;

pub unsafe fn BIO_set_retry_read(b: *mut BIO) {
    wolf::wolfSSL_BIO_set_flags(
        b,
        (wolf::BIO_FLAGS_WOLFSSL_BIO_FLAG_READ | wolf::BIO_FLAGS_WOLFSSL_BIO_FLAG_RETRY)
            .try_into()
            .unwrap(),
    )
}

pub unsafe fn BIO_set_retry_write(b: *mut BIO) {
    wolf::wolfSSL_BIO_set_flags(
        b,
        (wolf::BIO_FLAGS_WOLFSSL_BIO_FLAG_WRITE | wolf::BIO_FLAGS_WOLFSSL_BIO_FLAG_RETRY)
            .try_into()
            .unwrap(),
    )
}

pub unsafe fn BIO_clear_retry_flags(b: *mut BIO) {
    wolf::wolfSSL_BIO_clear_flags(
        b,
        (wolf::BIO_FLAGS_WOLFSSL_BIO_FLAG_READ
            | wolf::BIO_FLAGS_WOLFSSL_BIO_FLAG_WRITE
            | wolf::BIO_FLAGS_WOLFSSL_BIO_FLAG_RETRY)
            .try_into()
            .unwrap(),
    )
}

#[allow(clippy::match_like_matches_macro)] // matches macro requires rust 1.42.0
fn retriable_error(err: &io::Error) -> bool {
    let kind = err.kind();
    match kind {
        ErrorKind::WouldBlock | ErrorKind::NotConnected => true,
        _ => false,
    }
}

pub struct BioMethod(BIO_METHOD);

impl BioMethod {
    fn new<S: Read + Write>() -> Result<BioMethod, ErrorStack> {
        BIO_METHOD::new::<S>().map(BioMethod)
    }
}

unsafe impl Sync for BioMethod {}
unsafe impl Send for BioMethod {}

pub struct StreamState<S> {
    pub stream: S,
    pub error: Option<io::Error>,
    pub panic: Option<Box<dyn Any + Send>>,
    pub dtls_mtu_size: c_long,
}
unsafe fn state<'a, S: 'a>(bio: *mut BIO) -> &'a mut StreamState<S> {
    &mut *(wolf::wolfSSL_BIO_get_data(bio) as *mut _)
}

pub unsafe fn get_mut<'a, S: 'a>(bio: *mut BIO) -> &'a mut S {
    &mut state(bio).stream
}

pub unsafe fn take_error<S>(bio: *mut BIO) -> Option<io::Error> {
    let state = state::<S>(bio); // [test_wolf_get_bio] [SEGFAULT] here we access the ptr field of bio that is set to NULL at this point
    state.error.take() // BOOOM
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

    // FIXME: Cast is weird
    if cmd == wolfssl_sys::BIO_CTRL_FLUSH as c_int {
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
        // FIXME cast is weird
    } else if cmd == wolfssl_sys::BIO_CTRL_DGRAM_QUERY_MTU as c_int {
        state.dtls_mtu_size
    } else {
        0
    }
}

unsafe extern "C" fn create(bio: *mut BIO) -> c_int {
    wolf::wolfSSL_BIO_set_init(bio, 0);
    BIO_set_num(bio, 0);
    wolf::wolfSSL_BIO_set_data(bio, ptr::null_mut());
    wolf::wolfSSL_BIO_set_flags(bio, 0);
    1
}

unsafe extern "C" fn destroy<S>(bio: *mut BIO) -> c_int {
    if bio.is_null() {
        return 0;
    }

    let data = wolf::wolfSSL_BIO_get_data(bio);
    assert!(!data.is_null());
    Box::<StreamState<S>>::from_raw(data as *mut _);
    wolf::wolfSSL_BIO_set_data(bio, ptr::null_mut());
    wolf::wolfSSL_BIO_set_init(bio, 0);
    1
}

pub fn bio_new<S: Read + Write>(stream: S) -> Result<(*mut BIO, BioMethod), ErrorStack> {
    let method = BioMethod::new::<S>()?;

    let state = Box::new(StreamState {
        stream,
        error: None,
        panic: None,
        dtls_mtu_size: 0,
    });

    unsafe {
        let bio = cvt_p(wolf::wolfSSL_BIO_new(method.0.get()))?;
        wolf::wolfSSL_BIO_set_data(bio, Box::into_raw(state) as *mut _);
        wolf::wolfSSL_BIO_set_init(bio, 1);

        Ok((bio, method))
    }
}

pub struct MemBioSlice<'a>(*mut BIO, PhantomData<&'a [u8]>);

impl<'a> Drop for MemBioSlice<'a> {
    fn drop(&mut self) {
        unsafe {
            wolfssl_sys::wolfSSL_BIO_free_all(self.0);
        }
    }
}

impl<'a> MemBioSlice<'a> {
    pub fn new(buf: &'a [u8]) -> Result<MemBioSlice<'a>, ErrorStack> {
        assert!(buf.len() <= c_int::max_value() as usize);
        let bio = unsafe {
            cvt_p(wolfssl_sys::wolfSSL_BIO_new_mem_buf(
                buf.as_ptr() as *const _,
                buf.len() as c_int,
            ))?
        };

        Ok(MemBioSlice(bio, PhantomData))
    }

    pub fn as_ptr(&self) -> *mut BIO {
        self.0
    }
}

pub struct MemBio(*mut BIO);

impl Drop for MemBio {
    fn drop(&mut self) {
        unsafe {
            wolfssl_sys::wolfSSL_BIO_free_all(self.0);
        }
    }
}

impl MemBio {
    pub fn new() -> Result<MemBio, ErrorStack> {
        let bio = unsafe {
            cvt_p(wolfssl_sys::wolfSSL_BIO_new(
                wolfssl_sys::wolfSSL_BIO_s_mem(),
            ))?
        };
        Ok(MemBio(bio))
    }

    pub fn as_ptr(&self) -> *mut BIO {
        self.0
    }

    pub fn get_buf(&self) -> &[u8] {
        unsafe {
            let mut ptr = ptr::null_mut();
            let len = wolfssl_sys::wolfSSL_BIO_get_mem_data(self.0, ptr);
            slice::from_raw_parts(ptr as *const _ as *const _, len as usize)
        }
    }

    pub unsafe fn from_ptr(bio: *mut BIO) -> MemBio {
        MemBio(bio)
    }
}

#[allow(bad_style, clippy::upper_case_acronyms)]
struct BIO_METHOD(*mut wolf::WOLFSSL_BIO_METHOD);

impl BIO_METHOD {
    fn new<S: Read + Write>() -> Result<BIO_METHOD, ErrorStack> {
        unsafe {
            let ptr = cvt_p(wolf::wolfSSL_BIO_meth_new(
                0, // FIXME undefined in 520 wolf::BIO_TYPE_WOLFSSL_BIO_UNDEF,
                b"rust\0".as_ptr() as *const _,
            ))?;
            let method = BIO_METHOD(ptr);
            cvt(wolf::wolfSSL_BIO_meth_set_write(
                method.0,
                Some(bwrite::<S>),
            ))?;
            cvt(wolf::wolfSSL_BIO_meth_set_read(method.0, Some(bread::<S>)))?;
            cvt(wolf::wolfSSL_BIO_meth_set_puts(method.0, Some(bputs::<S>)))?;
            cvt(wolf::wolfSSL_BIO_meth_set_ctrl(method.0, Some(ctrl::<S>)))?;
            cvt(wolf::wolfSSL_BIO_meth_set_create(method.0, Some(create)))?;
            cvt(wolf::wolfSSL_BIO_meth_set_destroy(
                method.0,
                Some(destroy::<S>),
            ))?;
            Ok(method)
        }
    }

    fn get(&self) -> *mut wolf::BIO_METHOD {
        self.0
    }
}

impl Drop for BIO_METHOD {
    fn drop(&mut self) {
        unsafe {
            Box::<wolf::WOLFSSL_BIO_METHOD>::from_raw(self.0);
        }
    }
}

unsafe fn BIO_set_num(_bio: *mut wolf::WOLFSSL_BIO, _num: c_int) {}
