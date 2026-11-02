use std::fmt::Debug;

use comparable::Comparable;
use extractable_macro::Extractable;
use puffin::codec;
use puffin::codec::{Codec, Reader};

use crate::protocol::TLSProtocolTypes;
use crate::tls::rustls::key;

/// An externally length'd payload
#[derive(Debug, Clone, PartialEq, Extractable, Comparable)]
#[extractable(TLSProtocolTypes)]
pub struct Payload(
    #[extractable_no_recursion]
    #[comparable_ignore]
    pub Vec<u8>,
);

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
#[derive(Debug, Clone, PartialEq, Extractable, Comparable)]
#[extractable(TLSProtocolTypes)]
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
#[derive(Debug, Clone, PartialEq, Extractable, Comparable)]
#[extractable(TLSProtocolTypes)]
pub struct PayloadU16(#[extractable_no_recursion] pub Vec<u8>);

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
#[derive(Debug, Clone, PartialEq, Extractable, Comparable)]
#[extractable(TLSProtocolTypes)]
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

// Make it VecCodecWoSize so that Vec<T>: Codec for free
impl codec::VecCodecWoSize for PayloadU8 {}
impl codec::VecCodecWoSize for PayloadU16 {}
impl codec::VecCodecWoSize for PayloadU24 {}
