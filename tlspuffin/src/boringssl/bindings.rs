use boring::{
    error::ErrorStack,
    pkey::{PKey, Private},
    ssl::{SslContextBuilder, SslVersion},
    x509::X509,
};
use puffin::agent::TLSVersion;

pub fn static_rsa_cert(key: &[u8], cert: &[u8]) -> Result<(X509, PKey<Private>), ErrorStack> {
    let rsa = boring::rsa::Rsa::private_key_from_pem(key)?;
    let pkey = PKey::from_rsa(rsa)?;

    let cert = X509::from_pem(cert)?;
    Ok((cert, pkey))
}

#[allow(unused_variables)]
pub fn set_max_protocol_version(
    ctx_builder: &mut SslContextBuilder,
    tls_version: TLSVersion,
) -> Result<(), ErrorStack> {
    match tls_version {
        TLSVersion::V1_3 => {
            ctx_builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;
            Ok(())
        }
        TLSVersion::V1_2 => ctx_builder.set_max_proto_version(Some(SslVersion::TLS1_2)),
    }?;

    Ok(())
}
