use openssl::{
    asn1::Asn1Time,
    bn::{BigNum, MsbOption},
    error::ErrorStack,
    hash::MessageDigest,
    pkey::{PKey, Private},
    ssl::{SslContextBuilder, SslVersion},
    x509::{
        extension::{BasicConstraints, KeyUsage, SubjectKeyIdentifier},
        X509NameBuilder, X509,
    },
};

use crate::{
    agent::TLSVersion,
    static_certs::{CERT, PRIVATE_KEY},
};

// FIXME: remove or use
pub fn generate_cert() -> Result<(X509, PKey<Private>), ErrorStack> {
    let rsa = openssl::rsa::Rsa::generate(2048)?;
    let pkey = PKey::from_rsa(rsa)?;

    let mut x509_name = X509NameBuilder::new()?;
    x509_name.append_entry_by_text("C", "US")?;
    x509_name.append_entry_by_text("ST", "TX")?;
    x509_name.append_entry_by_text("O", "Some CA organization")?;
    x509_name.append_entry_by_text("CN", "ca test")?;
    let x509_name = x509_name.build();
    let mut cert_builder = X509::builder()?;
    cert_builder.set_version(2)?;
    let serial_number = {
        let mut serial = BigNum::new()?;
        serial.rand(159, MsbOption::MAYBE_ZERO, false)?;
        serial.to_asn1_integer()
    }?;
    cert_builder.set_serial_number(&serial_number)?;
    cert_builder.set_subject_name(&x509_name)?;
    cert_builder.set_issuer_name(&x509_name)?;
    cert_builder.set_pubkey(&pkey)?;
    let not_before = Asn1Time::days_from_now(0)?;
    cert_builder.set_not_before(&not_before)?;
    let not_after = Asn1Time::days_from_now(365)?;
    cert_builder.set_not_after(&not_after)?;

    let extension = BasicConstraints::new().critical().ca().build()?;
    cert_builder.append_extension(extension)?;
    cert_builder.append_extension(
        KeyUsage::new()
            .critical()
            .key_cert_sign()
            .crl_sign()
            .build()?,
    )?;

    let subject_key_identifier =
        SubjectKeyIdentifier::new().build(&cert_builder.x509v3_context(None, None))?;
    cert_builder.append_extension(subject_key_identifier)?;

    cert_builder.sign(&pkey, MessageDigest::sha256())?;
    let cert = cert_builder.build();
    Ok((cert, pkey))
}

pub fn static_rsa_cert() -> Result<(X509, PKey<Private>), ErrorStack> {
    let rsa = openssl::rsa::Rsa::private_key_from_pem(PRIVATE_KEY.as_bytes())?;
    let pkey = PKey::from_rsa(rsa)?;

    let cert = X509::from_pem(CERT.as_bytes())?;
    Ok((cert, pkey))
}

#[allow(unused_variables)]
pub fn set_max_protocol_version(
    ctx_builder: &mut SslContextBuilder,
    tls_version: TLSVersion,
) -> Result<(), ErrorStack> {
    // Old OpenSSL versions do not have this function
    #[cfg(any(feature = "openssl111", feature = "libressl"))]
    match tls_version {
        TLSVersion::V1_3 => {
            #[cfg(feature = "openssl111")]
            ctx_builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;
            // do nothing as the maximum available TLS version is 1.3
            Ok(())
        }
        TLSVersion::V1_2 => ctx_builder.set_max_proto_version(Some(SslVersion::TLS1_2)),
        TLSVersion::Unknown => Ok(()),
    }?;

    Ok(())
}
