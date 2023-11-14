use puffin::codec;
use ring::{aead, hkdf};

use crate::tls::rustls::{
    error::Error,
    msgs::message::{BorrowedPlainMessage, OpaqueMessage, PlainMessage},
};

/// Objects with this trait can decrypt TLS messages.
pub trait MessageDecrypter: Send + Sync {
    /// Perform the decryption over the concerned TLS message.

    fn decrypt(&self, m: OpaqueMessage, seq: u64) -> Result<PlainMessage, Error>;
}

/// Objects with this trait can encrypt TLS messages.
pub trait MessageEncrypter: Send + Sync {
    fn encrypt(&self, m: BorrowedPlainMessage, seq: u64) -> Result<OpaqueMessage, Error>;
}

impl dyn MessageEncrypter {
    pub fn invalid() -> Box<dyn MessageEncrypter> {
        Box::new(InvalidMessageEncrypter {})
    }
}

impl dyn MessageDecrypter {
    pub fn invalid() -> Box<dyn MessageDecrypter> {
        Box::new(InvalidMessageDecrypter {})
    }
}

/// A write or read IV.
#[derive(Default)]
pub struct Iv(pub [u8; ring::aead::NONCE_LEN]);

impl Iv {
    fn new(value: [u8; ring::aead::NONCE_LEN]) -> Self {
        Self(value)
    }

    pub fn copy(value: &[u8]) -> Self {
        debug_assert_eq!(value.len(), ring::aead::NONCE_LEN);
        let mut iv = Self::new(Default::default());
        iv.0.copy_from_slice(value);
        iv
    }

    #[cfg(test)]
    pub fn value(&self) -> &[u8; 12] {
        &self.0
    }
}

pub struct IvLen;

impl hkdf::KeyType for IvLen {
    fn len(&self) -> usize {
        aead::NONCE_LEN
    }
}

impl From<hkdf::Okm<'_, IvLen>> for Iv {
    fn from(okm: hkdf::Okm<IvLen>) -> Self {
        let mut r = Self(Default::default());
        okm.fill(&mut r.0[..]).unwrap();
        r
    }
}

pub fn make_nonce(iv: &Iv, seq: u64) -> ring::aead::Nonce {
    let mut nonce = [0u8; ring::aead::NONCE_LEN];
    codec::put_u64(seq, &mut nonce[4..]);

    nonce.iter_mut().zip(iv.0.iter()).for_each(|(nonce, iv)| {
        *nonce ^= *iv;
    });

    aead::Nonce::assume_unique_for_key(nonce)
}

/// A `MessageEncrypter` which doesn't work.
struct InvalidMessageEncrypter {}

impl MessageEncrypter for InvalidMessageEncrypter {
    fn encrypt(&self, _m: BorrowedPlainMessage, _seq: u64) -> Result<OpaqueMessage, Error> {
        Err(Error::General("encrypt not yet available".to_string()))
    }
}

/// A `MessageDecrypter` which doesn't work.
struct InvalidMessageDecrypter {}

impl MessageDecrypter for InvalidMessageDecrypter {
    fn decrypt(&self, _m: OpaqueMessage, _seq: u64) -> Result<PlainMessage, Error> {
        Err(Error::DecryptError)
    }
}
