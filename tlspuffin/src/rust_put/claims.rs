#[cfg(not(has_instr = "claimer"))]
pub mod dummy_registration {
    #[no_mangle]
    pub extern "C" fn register_claimer(
        _tls_like: *const ::std::os::raw::c_void,
        _claimer: security_claims::claim_t,
        _ctx: *mut ::std::os::raw::c_void,
    ) {
        // NOTE dummy implementation when the C ffi implementation is missing
    }

    #[no_mangle]
    pub extern "C" fn deregister_claimer(
        _tls_like: *const ::std::os::raw::c_void,
    ) -> *mut ::std::os::raw::c_void {
        // NOTE dummy implementation when the C ffi implementation is missing
        ::std::ptr::null_mut()
    }
}
