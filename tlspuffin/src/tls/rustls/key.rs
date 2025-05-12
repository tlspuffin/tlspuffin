use std::fmt;

use comparable::Comparable;
use extractable_macro::Extractable;
use puffin::codec::{Codec, Reader};

use crate::tls::TLSProtocolTypes;

/// This type contains a private key by value.
///
/// The private key must be DER-encoded ASN.1 in either
/// PKCS#8 or PKCS#1 format.
///
/// The `rustls-pemfile` crate can be used to extract
/// private keys from a PEM file in these formats.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PrivateKey(pub Vec<u8>);

/// This type contains a single certificate by value.
///
/// The certificate must be DER-encoded X.509.
///
/// The `rustls-pemfile` crate can be used to parse a PEM file.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Extractable, Comparable)]
#[extractable(TLSProtocolTypes)]
pub struct Certificate(#[extractable_no_recursion] pub Vec<u8>);

impl Codec for PrivateKey {
    fn encode(&self, bytes: &mut Vec<u8>) {
        bytes.append(&mut self.0.clone())
    }

    fn read(r: &mut Reader) -> Option<Self> {
        <Vec<u8> as Codec>::read(r).map(PrivateKey)
    }
}

impl AsRef<[u8]> for Certificate {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Certificate {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("Certificate").field(&self.0).finish()
    }
}

#[cfg(test)]
mod tests {
    use super::Certificate;

    #[test_log::test]
    fn certificate_debug() {
        assert_eq!(
            "Certificate([97, 98])",
            format!("{:?}", Certificate(b"ab".to_vec()))
        );
    }
}
