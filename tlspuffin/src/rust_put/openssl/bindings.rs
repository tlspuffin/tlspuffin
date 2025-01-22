use foreign_types_openssl::ForeignTypeRef;
use libc::c_int;
use openssl::ssl::SslRef;
use openssl_sys::SSL;

extern "C" {
    fn SSL_clear(ssl: *mut SSL) -> c_int;
}

pub fn clear(ssl: &SslRef) -> u32 {
    unsafe { SSL_clear(ssl.as_ptr()) as u32 }
}

mod version_specific_bindings {
    #[cfg(all(
        any(feature = "openssl101-binding", feature = "openssl102-binding"),
        not(feature = "openssl111-binding")
    ))]
    include!("bindings-10x.rs");

    #[cfg(feature = "openssl111-binding")]
    include!("bindings-111.rs");
}

pub use version_specific_bindings::*;
