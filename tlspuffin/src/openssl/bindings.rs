use foreign_types_openssl::ForeignTypeRef;
use libc::c_int;
use openssl::{
    error::ErrorStack,
    pkey::{PKey, Private},
    ssl::{SslContextBuilder, SslRef},
    x509::X509,
};
use openssl_sys::SSL;
use puffin::agent::TLSVersion;

extern "C" {
    fn SSL_clear(ssl: *mut SSL) -> c_int;
}

pub fn clear(ssl: &SslRef) -> u32 {
    unsafe { SSL_clear(ssl.as_ptr()) as u32 }
}

pub fn static_rsa_cert(key: &[u8], cert: &[u8]) -> Result<(X509, PKey<Private>), ErrorStack> {
    let rsa = openssl::rsa::Rsa::private_key_from_pem(key)?;
    let pkey = PKey::from_rsa(rsa)?;

    let cert = X509::from_pem(cert)?;
    Ok((cert, pkey))
}

#[allow(unused_variables)]
pub fn set_max_protocol_version(
    ctx_builder: &mut SslContextBuilder,
    tls_version: TLSVersion,
) -> Result<(), ErrorStack> {
    // Old OpenSSL versions do not have this function
    #[cfg(any(feature = "openssl111-binding", feature = "libressl333"))]
    match tls_version {
        TLSVersion::V1_3 => {
            #[cfg(feature = "openssl111-binding")]
            ctx_builder.set_max_proto_version(Some(openssl::ssl::SslVersion::TLS1_3))?;
            // do nothing as the maximum available TLS version is 1.3
            Ok(())
        }
        TLSVersion::V1_2 => {
            ctx_builder.set_max_proto_version(Some(openssl::ssl::SslVersion::TLS1_2))
        }
    }?;

    Ok(())
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
