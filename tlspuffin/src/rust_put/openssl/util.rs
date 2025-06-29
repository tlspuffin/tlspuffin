use openssl::error::ErrorStack;
use openssl::pkey::{PKey, Private};
use openssl::ssl::SslContextBuilder;
use openssl::x509::X509;

use crate::protocol::TLSVersion;

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
    #[cfg(any(feature = "openssl111_binding", feature = "libressl333"))]
    match tls_version {
        TLSVersion::V1_3 => {
            #[cfg(feature = "openssl111_binding")]
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
