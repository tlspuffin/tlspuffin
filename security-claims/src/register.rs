use std::ffi::c_void;
use std::mem;

use crate::ffi::{Claim, TLSLike};
use crate::ffi;

extern "C" fn handle_claim_c(x: Claim, ctx: *mut c_void) {
    let closure: &mut Box<Claimer> = unsafe { mem::transmute(ctx) };
    closure(x)
}

pub type Claimer = dyn FnMut(Claim);

pub fn register_claimer<F>(ssl_like_ptr: TLSLike, claimer: F)
where
    F: FnMut(Claim),
    F: 'static,
{
    let cb: Box<Box<Claimer>> = Box::new(Box::new(claimer));
    unsafe {
        ffi::register_claimer(
            ssl_like_ptr,
            Some(handle_claim_c),
            Box::into_raw(cb) as *mut _,
        );
    }
}

pub fn deregister_claimer(ssl_like_ptr: TLSLike) {
    // drop the callback
    let _: Box<Box<Claimer>> = unsafe {
        let ptr = ffi::deregister_claimer(ssl_like_ptr);
        let raw: Box<Box<Claimer>> = Box::from_raw(ptr as *mut _);
        raw
    };
}
