#![allow(warnings)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

#[no_mangle]
pub extern "C" fn put_rng_init() {
    // nothing to do
}

#[no_mangle]
pub extern "C" fn put_rng_reseed(buffer: *const u8, length: libc::size_t) {
    log::warn!("[RNG] reseed failed: not implemented for wolfssl");
}
