use std::fmt::Debug;

use puffin::codec;
use puffin::codec::{Codec, Reader};

use crate::tls::rustls::key;
/// An externally length'd payload
#[derive(Debug, Clone, PartialEq)]
pub struct Payload(pub Vec<u8>);

impl Codec for Payload {
    fn encode(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self.0);
    }

    fn read(r: &mut Reader) -> Option<Self> {
        Some(Self::read(r))
    }
}

impl Payload {
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }

    pub fn empty() -> Self {
        Self::new(Vec::new())
    }

    pub fn read(r: &mut Reader) -> Self {
        Self(r.rest().to_vec())
    }
}

impl Codec for key::Certificate {
    fn encode(&self, bytes: &mut Vec<u8>) {
        codec::u24(self.0.len() as u32).encode(bytes);
        bytes.extend_from_slice(&self.0);
    }

    fn read(r: &mut Reader) -> Option<Self> {
        let len = codec::u24::read(r)?.0 as usize;
        let mut sub = r.sub(len)?;
        let body = sub.rest().to_vec();
        Some(Self(body))
    }
}

/// An arbitrary, unknown-content, u24-length-prefixed payload
#[derive(Debug, Clone, PartialEq)]
pub struct PayloadU24(pub Vec<u8>);

impl PayloadU24 {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl Codec for PayloadU24 {
    fn encode(&self, bytes: &mut Vec<u8>) {
        codec::u24(self.0.len() as u32).encode(bytes);
        bytes.extend_from_slice(&self.0);
    }

    fn read(r: &mut Reader) -> Option<Self> {
        let len = codec::u24::read(r)?.0 as usize;
        let mut sub = r.sub(len)?;
        let body = sub.rest().to_vec();
        Some(Self(body))
    }
}

/// An arbitrary, unknown-content, u16-length-prefixed payload
#[derive(Debug, Clone, PartialEq)]
pub struct PayloadU16(pub Vec<u8>);

impl PayloadU16 {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn empty() -> Self {
        Self::new(Vec::new())
    }

    pub fn encode_slice(slice: &[u8], bytes: &mut Vec<u8>) {
        (slice.len() as u16).encode(bytes);
        bytes.extend_from_slice(slice);
    }
}

impl Codec for PayloadU16 {
    fn encode(&self, bytes: &mut Vec<u8>) {
        Self::encode_slice(&self.0, bytes);
    }

    fn read(r: &mut Reader) -> Option<Self> {
        let len = u16::read(r)? as usize;
        let mut sub = r.sub(len)?;
        let body = sub.rest().to_vec();
        Some(Self(body))
    }
}

/// An arbitrary, unknown-content, u8-length-prefixed payload
#[derive(Debug, Clone, PartialEq)]
pub struct PayloadU8(pub Vec<u8>);

impl PayloadU8 {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn empty() -> Self {
        Self(Vec::new())
    }

    pub fn into_inner(self) -> Vec<u8> {
        self.0
    }
}

impl Codec for PayloadU8 {
    fn encode(&self, bytes: &mut Vec<u8>) {
        (self.0.len() as u8).encode(bytes);
        bytes.extend_from_slice(&self.0);
    }

    fn read(r: &mut Reader) -> Option<Self> {
        let len = u8::read(r)? as usize;
        let mut sub = r.sub(len)?;
        let body = sub.rest().to_vec();
        Some(Self(body))
    }
}

/// Things we can encode and read from a Reader.
pub trait Codec2: Debug + Sized {
    /// Encode yourself by appending onto `bytes`.
    fn encode2(&self, bytes: &mut Vec<u8>);

    /// Convenience function to get the results of `encode()`.
    fn get_encoding2(&self) -> Vec<u8> {
        let mut ret = Vec::new();
        self.encode2(&mut ret);
        ret
    }

    /// Decode yourself by fiddling with the `Reader`.
    /// Return Some if it worked, None if not.
    fn read2(_: &mut Reader) -> Option<Self>;

    /// Read one of these from the front of `bytes` and
    /// return it.
    fn read_bytes2(bytes: &[u8]) -> Option<Self> {
        let mut rd = Reader::init(bytes);
        Self::read2(&mut rd)
    }
}

impl Codec2 for Vec<PayloadU8> {
    fn encode2(&self, bytes: &mut Vec<u8>) {
        for i in self {
            i.encode(bytes);
        }
    }

    fn read2(r: &mut Reader) -> Option<Vec<PayloadU8>> {
        let mut ret: Vec<PayloadU8> = Vec::new();

        while r.any_left() {
            ret.push(PayloadU8::read(r)?);
        }

        Some(ret)
    }
}

impl Codec2 for Vec<PayloadU16> {
    fn encode2(&self, bytes: &mut Vec<u8>) {
        for i in self {
            i.encode(bytes);
        }
    }

    fn read2(r: &mut Reader) -> Option<Vec<PayloadU16>> {
        let mut ret: Vec<PayloadU16> = Vec::new();

        while r.any_left() {
            ret.push(PayloadU16::read(r)?);
        }

        Some(ret)
    }
}

impl Codec2 for Vec<PayloadU24> {
    fn encode2(&self, bytes: &mut Vec<u8>) {
        for i in self {
            i.encode(bytes);
        }
    }

    fn read2(r: &mut Reader) -> Option<Vec<PayloadU24>> {
        let mut ret: Vec<PayloadU24> = Vec::new();

        while r.any_left() {
            ret.push(PayloadU24::read(r)?);
        }

        Some(ret)
    }
}

impl Codec2 for Option<Vec<u8>> {
    fn encode2(&self, bytes: &mut Vec<u8>) {
        match self {
            None => {}
            Some(v) => v.encode(bytes),
        }
    }

    fn read2(r: &mut Reader) -> Option<Option<Vec<u8>>> {
        if !r.any_left() {
            return Some(None);
        } else {
            return Some(<Vec<u8>>::read(r));
        }
    }
}
