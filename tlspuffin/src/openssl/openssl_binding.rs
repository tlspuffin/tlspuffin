use crate::agent::TLSVersion;
use crate::error::Error;
use crate::io::MemoryStream;
use log::warn;
use openssl::error::ErrorStack;
use openssl::ssl::{SslContextBuilder, SslVersion};
use openssl::{
    asn1::Asn1Time,
    bn::{BigNum, MsbOption},
    hash::MessageDigest,
    pkey::{PKey, PKeyRef, Private},
    ssl::{Ssl, SslContext, SslMethod, SslOptions, SslStream},
    version::version,
    x509::{
        extension::{BasicConstraints, KeyUsage, SubjectKeyIdentifier},
        X509NameBuilder, X509Ref, X509,
    },
};
use std::io::ErrorKind;
use std::os::raw::c_int;

/*
   Change openssl version:
   cargo clean -p openssl-src
   cd openssl-src/openssl
   git checkout OpenSSL_1_1_1j
*/

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

pub fn openssl_version() -> &'static str {
    version()
}

#[cfg(feature = "openssl111")]
extern "C" {
    pub fn make_openssl_deterministic();
    pub fn RAND_seed(buf: *mut u8, num: c_int);
}

#[cfg(feature = "openssl111")]
pub fn make_deterministic() {
    warn!("OpenSSL is no longer random!");
    unsafe {
        make_openssl_deterministic();
        let mut seed: [u8; 4] = 42u32.to_le().to_ne_bytes();
        let buf = seed.as_mut_ptr();
        RAND_seed(buf, 4);
    }
}
#[cfg(not(feature = "openssl111"))]
pub fn make_deterministic() {
    warn!("Failed to make PUT determinisitic!");
}

fn set_max_protocol_version(
    ctx_builder: &mut SslContextBuilder,
    tls_version: &TLSVersion,
) -> Result<(), ErrorStack> {
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

pub fn create_openssl_server(
    stream: MemoryStream,
    cert: &X509Ref,
    key: &PKeyRef<Private>,
    tls_version: &TLSVersion,
) -> Result<SslStream<MemoryStream>, ErrorStack> {
    let mut ctx_builder = SslContext::builder(SslMethod::tls())?;
    ctx_builder.set_certificate(cert)?;
    ctx_builder.set_private_key(key)?;

    #[cfg(feature = "openssl111")]
    ctx_builder.clear_options(SslOptions::ENABLE_MIDDLEBOX_COMPAT);

    #[cfg(feature = "openssl111")]
    ctx_builder.set_options(SslOptions::ALLOW_NO_DHE_KEX);

    set_max_protocol_version(&mut ctx_builder, tls_version)?;

    #[cfg(any(feature = "openssl101f", feature = "openssl102u"))]
    {
        ctx_builder.set_tmp_ecdh(
            openssl::ec::EcKey::from_curve_name(openssl::nid::Nid::SECP384R1)
                .as_ref()
                .unwrap(),
        )?;
        // TODO: https://github.com/sfackler/rust-openssl/issues/1529 use callback after fix
        //ctx_builder.set_tmp_ecdh_callback(|_, _, _| {
        //   openssl::ec::EcKey::from_curve_name(openssl::nid::Nid::SECP384R1)
        //});
    }

    #[cfg(any(feature = "openssl101f", feature = "openssl102u"))]
    {
        ctx_builder.set_tmp_rsa(openssl::rsa::Rsa::generate(512).as_ref().unwrap())?;
        // TODO: https://github.com/sfackler/rust-openssl/issues/1529 use callback use callback after fix
        //ctx_builder.set_tmp_rsa_callback(|_, is_export, keylength| openssl::rsa::Rsa::generate(keylength));
    }

    // Allow EXPORT in server
    ctx_builder.set_cipher_list("ALL:EXPORT:!LOW:!aNULL:!eNULL:!SSLv2")?;

    let mut ssl = Ssl::new(&ctx_builder.build())?;

    ssl.set_accept_state();
    SslStream::new(ssl, stream)
}

pub fn log_io_error(error: &openssl::ssl::Error) -> Result<(), Error> {
    if let Some(io_error) = error.io_error() {
        match io_error.kind() {
            ErrorKind::WouldBlock => {
                // Not actually an error, we just reached the end of the stream, thrown in MemoryStream
                // trace!("Would have blocked but the underlying stream is non-blocking!");
                Ok(())
            }
            _ => Err(Error::IO(format!("Unexpected IO Error: {}", io_error))),
        }
    } else {
        Ok(())
    }
}

pub fn log_ssl_error(error: &openssl::ssl::Error) -> Result<(), Error> {
    if let Some(ssl_error) = error.ssl_error() {
        // OpenSSL threw an error, that means that there should be an Alert message in the
        // outbound channel
        Err(Error::OpenSSL(ssl_error.clone()))
    } else {
        Ok(())
    }
}

pub fn create_openssl_client(
    stream: MemoryStream,
    tls_version: &TLSVersion,
) -> Result<SslStream<MemoryStream>, ErrorStack> {
    let mut ctx_builder = SslContext::builder(SslMethod::tls())?;
    // Not sure whether we want this disabled or enabled: https://gitlab.inria.fr/mammann/tlspuffin/-/issues/26
    // The tests become simpler if disabled to maybe that's what we want. Lets leave it default
    // for now.
    // https://wiki.openssl.org/index.php/TLS1.3#Middlebox_Compatibility_Mode
    #[cfg(feature = "openssl111")]
    ctx_builder.clear_options(SslOptions::ENABLE_MIDDLEBOX_COMPAT);

    set_max_protocol_version(&mut ctx_builder, tls_version)?;

    // Disallow EXPORT in client
    ctx_builder.set_cipher_list("ALL:!EXPORT:!LOW:!aNULL:!eNULL:!SSLv2")?;

    let mut ssl = Ssl::new(&ctx_builder.build())?;
    ssl.set_connect_state();

    SslStream::new(ssl, stream)
}

pub fn do_handshake(stream: &mut SslStream<MemoryStream>) -> Result<(), Error> {
    if stream.ssl().state_string_long() == "SSL negotiation finished successfully" {
        // todo improve this case
        let mut vec: Vec<u8> = Vec::from([1; 128]);

        if let Err(error) = stream.ssl_read(&mut vec) {
            log_io_error(&error)?;
            log_ssl_error(&error)?;
        } else {
            // Reading succeeded
        }
    } else if let Err(error) = stream.do_handshake() {
        log_io_error(&error)?;
        log_ssl_error(&error)?;
    } else {
        // Handshake is done
    }

    Ok(())
}
