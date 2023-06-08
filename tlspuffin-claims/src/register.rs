use std::{ffi::c_void, mem};

use crate::{
    ffi,
    ffi::{Claim, TLSLike},
};

extern "C" fn handle_claim_c(x: Claim, ctx: *mut c_void) {
    let closure: &mut Box<Claimer> =
        unsafe { &mut *(ctx as *mut std::boxed::Box<dyn std::ops::FnMut(ffi::Claim)>) };
    closure(x)
}

pub type Claimer = dyn FnMut(Claim);

pub unsafe fn register_claimer<F>(ssl_like_ptr: TLSLike, claimer: F)
where
    F: FnMut(Claim),
    F: 'static,
{
    let cb: Box<Box<Claimer>> = Box::new(Box::new(claimer));

    ffi::register_claimer(
        ssl_like_ptr,
        Some(handle_claim_c),
        Box::into_raw(cb) as *mut _,
    );
}

pub unsafe fn deregister_claimer(ssl_like_ptr: TLSLike) {
    // drop the callback
    let _: Box<Box<Claimer>> = {
        let ptr = ffi::deregister_claimer(ssl_like_ptr);
        let raw: Box<Box<Claimer>> = Box::from_raw(ptr as *mut _);
        raw
    };
}
