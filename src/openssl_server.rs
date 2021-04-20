use openssl::asn1::Asn1Time;
use openssl::bn::{BigNum, MsbOption};
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, PKeyRef, Private};
use openssl::ssl::{Ssl, SslContext, SslMethod, SslStream, SslOptions};
use openssl::version::version;
use openssl::x509::extension::{BasicConstraints, KeyUsage, SubjectKeyIdentifier};
use openssl::x509::{X509NameBuilder, X509Ref, X509};

use crate::io::{MemoryStream, Outgoing, Stream};
use crate::debug::debug_message;
use std::io::ErrorKind;

/*
   Change openssl version:
   cargo clean -p openssl-src
   cd openssl-src/openssl
   git checkout OpenSSL_1_1_1j
*/

pub fn generate_cert() -> (X509, PKey<Private>) {
    let rsa = openssl::rsa::Rsa::generate(2048).unwrap();
    let pkey = PKey::from_rsa(rsa).unwrap();

    let mut x509_name = X509NameBuilder::new().unwrap();
    x509_name.append_entry_by_text("C", "US").unwrap();
    x509_name.append_entry_by_text("ST", "TX").unwrap();
    x509_name
        .append_entry_by_text("O", "Some CA organization")
        .unwrap();
    x509_name.append_entry_by_text("CN", "ca test").unwrap();
    let x509_name = x509_name.build();
    let mut cert_builder = X509::builder().unwrap();
    cert_builder.set_version(2).unwrap();
    let serial_number = {
        let mut serial = BigNum::new().unwrap();
        serial.rand(159, MsbOption::MAYBE_ZERO, false).unwrap();
        serial.to_asn1_integer()
    }
    .unwrap();
    cert_builder.set_serial_number(&serial_number).unwrap();
    cert_builder.set_subject_name(&x509_name).unwrap();
    cert_builder.set_issuer_name(&x509_name).unwrap();
    cert_builder.set_pubkey(&pkey).unwrap();
    let not_before = Asn1Time::days_from_now(0).unwrap();
    cert_builder.set_not_before(&not_before).unwrap();
    let not_after = Asn1Time::days_from_now(365).unwrap();
    cert_builder.set_not_after(&not_after).unwrap();

    let extension = BasicConstraints::new().critical().ca().build().unwrap();
    cert_builder.append_extension(extension).unwrap();
    cert_builder.append_extension(
        KeyUsage::new()
            .critical()
            .key_cert_sign()
            .crl_sign()
            .build()
            .unwrap(),
    ).unwrap();

    let subject_key_identifier = SubjectKeyIdentifier::new()
        .build(&cert_builder.x509v3_context(None, None))
        .unwrap();
    cert_builder.append_extension(subject_key_identifier).unwrap();

    cert_builder.sign(&pkey, MessageDigest::sha256()).unwrap();
    let cert = cert_builder.build();
    return (cert, pkey);
}

pub fn openssl_version() -> &'static str {
    version()
}

pub fn create_openssl_server(stream: MemoryStream, cert: &X509Ref, key: &PKeyRef<Private>) -> SslStream<MemoryStream> {
    let mut server_ctx = SslContext::builder(SslMethod::tls()).unwrap();
    server_ctx.set_certificate(cert).unwrap();
    server_ctx.set_private_key(key).unwrap();
    let server_stream =
        SslStream::new(Ssl::new(&server_ctx.build()).unwrap(), stream).unwrap();

    return server_stream;
}


pub fn create_openssl_client(stream: MemoryStream) -> SslStream<MemoryStream> {
    let mut ctx_builder = SslContext::builder(SslMethod::tls()).unwrap();
    // https://wiki.openssl.org/index.php/TLS1.3#Middlebox_Compatibility_Mode
    ctx_builder.clear_options(SslOptions::ENABLE_MIDDLEBOX_COMPAT);

    let client_stream =
        SslStream::new(Ssl::new(&ctx_builder.build()).unwrap(), stream).unwrap();

    return client_stream;
}

pub fn client_connect(stream: &mut SslStream<MemoryStream>) -> Option<Vec<u8>> {
    match stream.connect() {
        Ok(_) => {
            println!("Handshake is done");
            None
        }
        Err(error) => {
            let outgoing = stream.get_mut().receive();

            if let Some(io_error) = error.io_error() {
                match io_error.kind() {
                    ErrorKind::WouldBlock => {
                        // Not actually an error, we just reached the end of the stream, thrown in MemoryStream
                    }
                    _ => {
                        warn!("{}", io_error);
                    }
                }
            }

            if let Some(ssl_error) = error.ssl_error() {
                // OpenSSL threw an error!
                warn!("{}", ssl_error);
            }

            Some(outgoing)
        }
    }
}

pub fn server_accept(stream: &mut SslStream<MemoryStream>) -> Option<Vec<u8>> {
    match stream.accept() {
        Ok(_) => {
            println!("Handshake is done");
            None
        }
        Err(error) => {
            if let Some(io_error) = error.io_error() {
                match io_error.kind() {
                    ErrorKind::WouldBlock => {
                        // Not actually an error, we just reached the end of the stream, thrown in MemoryStream
                        info!("Would have blocked but the underlying stream is non-blocking!");
                    }
                    _ => {
                        error!("Unexpected IO Error: {}", io_error);
                    }
                }
            }

            if let Some(ssl_error) = error.ssl_error() {
                // OpenSSL threw an error!
                error!("SSL Error: {}", ssl_error);
            }
            let outgoing = stream.get_mut().receive();
            Some(outgoing)
        }
    }
}