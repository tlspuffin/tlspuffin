use std::io::ErrorKind;
use std::mem::transmute;
use std::os::raw::c_int;

use foreign_types_shared::ForeignTypeRef;
use security_claims::{register_claimer, ClaimType};

use openssl::error::ErrorStack;
use openssl::ssl::SslVersion;
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

use crate::agent::TLSVersion;
use crate::error::Error;
use crate::io::MemoryStream;

const PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCm+I4KieF8pypN
WrcuAuKDcZNQW/0txKHBR7R8wqCtkBiiQ0WWslV6NHWiaaG/mba8oGQhVRcDMoxf
BEOA0Eppq+PDJ5giB+9CxvD+cTlaHTZIMsj1qQL/6o6IUE6WBysth8vP6pIjYRPe
5fVsLv4XFYWXYV4LkmF+kuUqIznvqHkO0BUp7U6pyNEvO74uHbqvNbF2Y3Kgkg+s
pbaCWPHyCdTGeiPbVzWWgEqBSv7QBRKGNnTZgd400NEG5sF7H1vNZkuZEEEiBLH3
Ob2BSLtQ/ny0q9jkh2tYjfygJDDoqQOSd8ZjU/9gej2zhzHY2OpDyfR1XkmvrAPC
9Fu1ts4PAgMBAAECggEAK4SSuMpw+6UyEFE5dwOHeAzNAV/IX/pk0lRXBUFQ0YvB
7+CqrXkzcBNmKXtwjdiJWSZQkqNzyQCOt2EMGvGuw1Xqmf2i2BPLV1M0kox+Dy+X
6z9ZQzXWs0618W9E3DNoHIjNJRaVGiV+IVU8HwMsdGXGmMrm0QtI3813bwEZY43Q
mlDJXF1r5UugHIo2Hh6HRzsaUnC3pG1HNuKL8PcdTFNslVMeGQmO8IpYKxHN5Ldz
loW6lkkSuBrRsbojvyDUveFLoEX/RhJoxg/Oic6JV7eBWewS/0Ps3gryBmBX3jBV
6RZQlL8l4z2tDi+0t7flnqbQkqHof3wQCArkIsgOiQKBgQDTruiU3xRZ2WXvu3PN
dLx9G+Q2I/0TmYw1viEyjhZOTWoinM614Gkn30GMGQU1+Lcq5BTujVdRaSQy0DWv
1GkzwJye3q0xNBIj2qP7GFZa446UjShOu1NU7HvT2meGtEDmQHA26T55Fd+E1I9K
te0sk71GNhI8nOLEsgcLf34hJQKBgQDJ7U4BQb0H5bDHdiyWABiEAUKe9CxmDesS
/IElWI4kUYH+BJC3OKsPaGwKRHP9xM3/Z1xNuEaICru2nrTxjySGlHQLRm9b0x/w
d4zF4Lmd+hx8Y3EuavwAsN2v9DzGCxksoZgmJPmA64u3HpfwnfkqJLR9yUdrAjOe
iMwokzNOIwKBgDcvKOjugwKtXxqxNo5AOYcwBz1qAmbip5+3EjZ4vi3plpqxYF4f
w6omVJMuTqJ0VWP0E9Tgufu6OjqY9vYAnPBl7S6phGMIXRZFwGwMOy70lc36QqDL
yvyfreRb0pNWWHjuIZLfGW89mYiqVTS32r29QiGUpQpyJ9f5RUblFL+VAoGBAMPf
YY9uiUMj13tkcpN+vEkwP8OY74h/b8wXC9+CKz+noQUawJY6bhSgIk1DYZCEW56o
UK1DV4eXgcb/5F19kNzLHFXjmRnljlHgZbl86BEKEJ/Ihn2UYab56dFIhbtGAMF+
buxxaWVZF0ombxSE6LGssThjCtgOZqwd3oxtXZMpAoGBALGK0dV3CSG0cS5Sya4P
twtC36V0ynuef3YrRaOMYnj9zgXZD+Db/vpTZSYwSSBAvqVLGTt3EgzW/zwD5+62
UbQ/245wgNlgATlVVRUcgnHz9bnNAW0dBG4YeLnQTkVl1I0TR8VDjJCi3F6l1nnr
XIZqdO/MQ75qBeUM/r9tsdpu
-----END PRIVATE KEY-----";

const CERT: &str = "-----BEGIN CERTIFICATE-----
MIIDajCCAlKgAwIBAgITdvXibPwwAIa0Bv65gaVuVie5VjANBgkqhkiG9w0BAQsF
ADBFMQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwY
SW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMB4XDTIxMDUyNDE1MzAwMFoXDTIxMDYy
MzE1MzAwMFowRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAf
BgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDCCASIwDQYJKoZIhvcNAQEB
BQADggEPADCCAQoCggEBAKb4jgqJ4XynKk1aty4C4oNxk1Bb/S3EocFHtHzCoK2Q
GKJDRZayVXo0daJpob+ZtrygZCFVFwMyjF8EQ4DQSmmr48MnmCIH70LG8P5xOVod
NkgyyPWpAv/qjohQTpYHKy2Hy8/qkiNhE97l9Wwu/hcVhZdhXguSYX6S5SojOe+o
eQ7QFSntTqnI0S87vi4duq81sXZjcqCSD6yltoJY8fIJ1MZ6I9tXNZaASoFK/tAF
EoY2dNmB3jTQ0QbmwXsfW81mS5kQQSIEsfc5vYFIu1D+fLSr2OSHa1iN/KAkMOip
A5J3xmNT/2B6PbOHMdjY6kPJ9HVeSa+sA8L0W7W2zg8CAwEAAaNTMFEwHQYDVR0O
BBYEFI4uUtLX7czsxVP8axN/jfVKjKOPMB8GA1UdIwQYMBaAFI4uUtLX7czsxVP8
axN/jfVKjKOPMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBACfO
f4Q93i5Ra3qt+a+MLbY1/EExNVxahePeI4ImmIP7i2ZaHP/sSSHO3L0m02X4hygI
IMAg0PwN3kiV2elA39TqY0YZv3q0yc5gtssN1nsKwjm36O11RN1HlK1D07SMm00R
zkMfeXUKErSFDB3PPHwwc+G6FUKMPW4g4rg49aVSizIdbCLmMPECNyXHsD4bo2fF
WAccqe3TAwAq6m2BWaH8YchExVPAnJ5AvO2pBbE8j8v6dF470vBs6szvBKvgV9pu
+ullb9HQDft8lcQCI7Ib5reI/0YaYN02Mlhy3hLbxHKJaB1FlYMtqiiYL55GIEtZ
i7RrmCDnL/ue3MkPP+8=
-----END CERTIFICATE-----";

/*
   Change openssl version:
   cargo clean -p openssl-src
   cd openssl-src/openssl
   git checkout OpenSSL_1_1_1j
*/
pub fn static_rsa_cert() -> Result<(X509, PKey<Private>), ErrorStack> {
    let rsa = openssl::rsa::Rsa::private_key_from_pem(PRIVATE_KEY.as_bytes())?;
    let pkey = PKey::from_rsa(rsa)?;

    let cert = X509::from_pem(CERT.as_bytes())?;
    Ok((cert, pkey))
}

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

extern "C" {
    pub fn make_openssl_deterministic();
    pub fn RAND_seed(buf: *mut u8, num: c_int);
}

pub fn make_deterministic() {
    warn!("OpenSSL is no longer random!");
    unsafe {
        make_openssl_deterministic();
        let mut seed: [u8; 4] = transmute(42u32.to_le());
        let buf = seed.as_mut_ptr();
        RAND_seed(buf, 4);
    }
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
    ctx_builder.set_options(SslOptions::NO_TICKET); // todo remove, its here for seed_successful12

    #[cfg(feature = "ossl110")]
    match tls_version {
        TLSVersion::V1_3 => ctx_builder.set_max_proto_version(Some(SslVersion::TLS1_3))?,
        TLSVersion::V1_2 => ctx_builder.set_max_proto_version(Some(SslVersion::TLS1_2))?,
    }

    #[cfg(all(feature = "ossl101", not(feature = "ossl110")))]
    ctx_builder.set_tmp_ecdh_callback(|_, _, _| {
        openssl::ec::EcKey::from_curve_name(openssl::nid::Nid::SECP384R1)
    });

    #[cfg(all(feature = "ossl101", not(feature = "ossl110")))]
    ctx_builder
        .set_tmp_rsa_callback(|_, is_export, keylength| openssl::rsa::Rsa::generate(keylength));

    let mut ssl = Ssl::new(&ctx_builder.build())?;

    ssl.set_accept_state();
    SslStream::new(ssl, stream)
}

pub fn log_io_error(error: &openssl::ssl::Error) -> Result<(), Error> {
    if let Some(io_error) = error.io_error() {
        match io_error.kind() {
            ErrorKind::WouldBlock => {
                // Not actually an error, we just reached the end of the stream, thrown in MemoryStream
                trace!("Would have blocked but the underlying stream is non-blocking!");
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
    // ctx_builder.clear_options(SslOptions::ENABLE_MIDDLEBOX_COMPAT);

    #[cfg(feature = "ossl110")]
    match tls_version {
        TLSVersion::V1_3 => ctx_builder.set_max_proto_version(Some(SslVersion::TLS1_3))?,
        TLSVersion::V1_2 => ctx_builder.set_max_proto_version(Some(SslVersion::TLS1_2))?,
    }

    ctx_builder.set_cipher_list("ALL:!EXPORT:!LOW:!aNULL:!eNULL:!SSLv2")?;

    let mut ssl = Ssl::new(&ctx_builder.build())?;
    ssl.set_connect_state();

    let mut test: u32 = 4;

    register_claimer(ssl.as_ptr().cast(), move |claim| {
        match claim.typ {
            ClaimType::CLAIM_CIPHERS => {}
        }
        test += 1;
        println!("claim {}: {:?}", test, claim);
    });

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
            trace!("read succeeded");
        }
    } else {
        if let Err(error) = stream.do_handshake() {
            log_io_error(&error)?;
            log_ssl_error(&error)?;
        } else {
            trace!("Handshake is done");
        }
    }

    Ok(())
}
