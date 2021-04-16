use std::io;
use std::io::{Read, Write};
use std::path::Path;

use openssl::asn1::Asn1Time;
use openssl::bn::{BigNum, MsbOption};
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, PKeyRef, Private};
use openssl::ssl::{Ssl, SslContext, SslFiletype, SslMethod, SslOptions, SslStream};
use openssl::version::version;
use openssl::x509::{X509, X509NameBuilder, X509Ref};
use openssl::x509::extension::{BasicConstraints, KeyUsage, SubjectKeyIdentifier};

/*
   Change openssl version:
   cargo clean -p openssl-src
   cd openssl-src/openssl
   git checkout OpenSSL_1_1_1j
*/

pub fn creat_cert() -> (X509, PKey<Private>) {
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
    cert_builder.set_version(2);
    let serial_number = {
        let mut serial = BigNum::new().unwrap();
        serial.rand(159, MsbOption::MAYBE_ZERO, false);
        serial.to_asn1_integer()
    }
        .unwrap();
    cert_builder.set_serial_number(&serial_number);
    cert_builder.set_subject_name(&x509_name);
    cert_builder.set_issuer_name(&x509_name);
    cert_builder.set_pubkey(&pkey);
    let not_before = Asn1Time::days_from_now(0).unwrap();
    cert_builder.set_not_before(&not_before);
    let not_after = Asn1Time::days_from_now(365).unwrap();
    cert_builder.set_not_after(&not_after);

    cert_builder.append_extension(BasicConstraints::new().critical().ca().build().unwrap());
    cert_builder.append_extension(
        KeyUsage::new()
            .critical()
            .key_cert_sign()
            .crl_sign()
            .build()
            .unwrap(),
    );

    let subject_key_identifier = SubjectKeyIdentifier::new()
        .build(&cert_builder.x509v3_context(None, None))
        .unwrap();
    cert_builder.append_extension(subject_key_identifier);

    cert_builder.sign(&pkey, MessageDigest::sha256());
    let cert = cert_builder.build();
    return (cert, pkey);
}

#[derive(Debug)]
pub struct MemoryStream {
    incoming: io::Cursor<Vec<u8>>,
    outgoing: Vec<u8>,
}

impl MemoryStream {
    pub fn new() -> Self {
        Self {
            incoming: io::Cursor::new(Vec::new()),
            outgoing: Vec::new(),
        }
    }

    pub fn extend_incoming(&mut self, data: &[u8]) {
        self.incoming.get_mut().extend_from_slice(data);
    }

    pub fn take_outgoing(&mut self) -> Outgoing<'_> {
        Outgoing(&mut self.outgoing)
    }
}

impl Read for MemoryStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.incoming.read(buf)?;
        if self.incoming.position() == self.incoming.get_ref().len() as u64 {
            self.incoming.set_position(0);
            self.incoming.get_mut().clear();
        }
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "no data available",
            ));
        }
        Ok(n)
    }
}

impl Write for MemoryStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.outgoing.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub struct Outgoing<'a>(&'a mut Vec<u8>);

impl<'a> Drop for Outgoing<'a> {
    fn drop(&mut self) {
        self.0.clear();
    }
}

impl<'a> ::std::ops::Deref for Outgoing<'a> {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl<'a> AsRef<[u8]> for Outgoing<'a> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

pub fn openssl_version() -> &'static str {
    version()
}

pub fn create_openssl_server(cert: &X509Ref, key: &PKeyRef<Private>) -> SslStream<MemoryStream> {
    let mut server_ctx = SslContext::builder(SslMethod::tls()).unwrap();
    server_ctx.set_certificate(cert).unwrap();
    server_ctx.set_private_key(key).unwrap();
    let server_stream =
        SslStream::new(Ssl::new(&server_ctx.build()).unwrap(), MemoryStream::new()).unwrap();

    return server_stream;
}
