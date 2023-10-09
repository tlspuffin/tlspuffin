use crate::algebra::error::FnError;
use std::{convert::TryInto, fmt::Debug};

/// Read from a byte slice.
pub struct Reader<'a> {
    buf: &'a [u8],
    offs: usize,
}

impl<'a> Reader<'a> {
    pub fn init(bytes: &[u8]) -> Reader {
        Reader {
            buf: bytes,
            offs: 0,
        }
    }

    pub fn rest(&mut self) -> &[u8] {
        let ret = &self.buf[self.offs..];
        self.offs = self.buf.len();
        ret
    }

    pub fn take(&mut self, len: usize) -> Option<&[u8]> {
        if self.left() < len {
            return None;
        }

        let current = self.offs;
        self.offs += len;
        Some(&self.buf[current..current + len])
    }

    pub fn peek(&self, len: usize) -> Option<&[u8]> {
        if self.left() < len {
            return None;
        }

        let current = self.offs;
        Some(&self.buf[current..current + len])
    }

    pub fn any_left(&self) -> bool {
        self.offs < self.buf.len()
    }

    pub fn left(&self) -> usize {
        self.buf.len() - self.offs
    }

    pub fn used(&self) -> usize {
        self.offs
    }

    pub fn sub(&mut self, len: usize) -> Option<Reader> {
        self.take(len).map(Reader::init)
    }
}

/// Things we can encode
pub trait Encode: Debug + Sized {
    /// Encode yourself by appending onto `bytes`.
    fn encode(&self, bytes: &mut Vec<u8>);

    /// Convenience function to get the results of `encode()`.
    fn get_encoding(&self) -> Vec<u8> {
        let mut ret = Vec::new();
        self.encode(&mut ret);
        ret
    }
}

/// Things we can encode and read from a Reader.
pub trait Codec: Debug + Sized {
    /// Encode yourself by appending onto `bytes`.
    fn encode(&self, bytes: &mut Vec<u8>);

    /// Convenience function to get the results of `encode()`.
    fn get_encoding(&self) -> Vec<u8> {
        let mut ret = Vec::new();
        self.encode(&mut ret);
        ret
    }

    /// Decode yourself by fiddling with the `Reader`.
    /// Return Some if it worked, None if not.
    fn read(_: &mut Reader) -> Option<Self>;

    /// Read one of these from the front of `bytes` and
    /// return it.
    fn read_bytes(bytes: &[u8]) -> Option<Self> {
        let mut rd = Reader::init(bytes);
        Self::read(&mut rd)
    }
}

impl<T: Codec> Encode for T {
    fn encode(&self, bytes: &mut Vec<u8>) {
        Codec::encode(self, bytes)
    }
}

// Encoding functions.
fn decode_u8(bytes: &[u8]) -> Option<u8> {
    let [value]: [u8; 1] = bytes.try_into().ok()?;
    Some(value)
}

impl Codec for u8 {
    fn encode(&self, bytes: &mut Vec<u8>) {
        bytes.push(*self);
    }
    fn read(r: &mut Reader) -> Option<Self> {
        r.take(1).and_then(decode_u8)
    }
}

pub fn put_u16(v: u16, out: &mut [u8]) {
    let out: &mut [u8; 2] = (&mut out[..2]).try_into().unwrap();
    *out = u16::to_be_bytes(v);
}

pub fn decode_u16(bytes: &[u8]) -> Option<u16> {
    Some(u16::from_be_bytes(bytes.try_into().ok()?))
}

impl Codec for u16 {
    fn encode(&self, bytes: &mut Vec<u8>) {
        let mut b16 = [0u8; 2];
        put_u16(*self, &mut b16);
        bytes.extend_from_slice(&b16);
    }

    fn read(r: &mut Reader) -> Option<Self> {
        r.take(2).and_then(decode_u16)
    }
}

// Make a distinct type for u24, even though it's a u32 underneath
#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone)]
pub struct u24(pub u32);

impl u24 {
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let [a, b, c]: [u8; 3] = bytes.try_into().ok()?;
        Some(Self(u32::from_be_bytes([0, a, b, c])))
    }
}

#[cfg(any(target_pointer_width = "32", target_pointer_width = "64"))]
impl From<u24> for usize {
    #[inline]
    fn from(v: u24) -> Self {
        v.0 as Self
    }
}

impl Codec for u24 {
    fn encode(&self, bytes: &mut Vec<u8>) {
        let be_bytes = u32::to_be_bytes(self.0);
        bytes.extend_from_slice(&be_bytes[1..])
    }

    fn read(r: &mut Reader) -> Option<Self> {
        r.take(3).and_then(Self::decode)
    }
}

pub fn decode_u32(bytes: &[u8]) -> Option<u32> {
    Some(u32::from_be_bytes(bytes.try_into().ok()?))
}

impl Codec for u32 {
    fn encode(&self, bytes: &mut Vec<u8>) {
        bytes.extend(&Self::to_be_bytes(*self))
    }

    fn read(r: &mut Reader) -> Option<Self> {
        r.take(4).and_then(decode_u32)
    }
}

pub fn put_u64(v: u64, bytes: &mut [u8]) {
    let bytes: &mut [u8; 8] = (&mut bytes[..8]).try_into().unwrap();
    *bytes = u64::to_be_bytes(v)
}

pub fn decode_u64(bytes: &[u8]) -> Option<u64> {
    Some(u64::from_be_bytes(bytes.try_into().ok()?))
}

impl Codec for u64 {
    fn encode(&self, bytes: &mut Vec<u8>) {
        let mut b64 = [0u8; 8];
        put_u64(*self, &mut b64);
        bytes.extend_from_slice(&b64);
    }

    fn read(r: &mut Reader) -> Option<Self> {
        r.take(8).and_then(decode_u64)
    }
}

pub fn encode_vec_u8<T: Encode>(bytes: &mut Vec<u8>, items: &[T]) {
    let len_offset = bytes.len();
    bytes.push(0);

    for i in items {
        i.encode(bytes);
    }

    let len = bytes.len() - len_offset - 1;
    bytes[len_offset] = len.min(0xff) as u8;
}


// Data that can be considered "coutable" and whose Vec<> are prefixed with the size of the vector (e.g., Certificate)
pub trait Countable {}
impl Countable for Vec<u8> {}

impl<T: Codec + Countable> Codec for Vec<T> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        if self.len() == 0 {
            // encode_vec_u8(bytes, self) // TODO: investigate if this breaks something for some Countable types. At least we need it for Certificates list
        } else {
            encode_vec_u8(bytes, self)
        }
    }

    fn read(r: &mut Reader) -> Option<Self> {
        read_vec_u8(r)
    }
}

// We do not put the size of the vector for Vec<u8> as we consider it as plain data
impl Codec for Vec<u8> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        for i in self {
            bytes.push(*i);
        }
    }

    fn read(r: &mut Reader) -> Option<Self> {
        let mut ret: Vec<u8> = Vec::new();

        while r.any_left() {
            ret.push(u8::read(r)?);
        }

        Some(ret)
    }
}

impl<T: Debug + Encode> Encode for Option<T> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        if let Some(value) = self {
            value.encode(bytes);
        }
    }
}

impl<T: Debug + Encode, E: Debug> Encode for Result<T, E> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        if let Ok(value) = self {
            value.encode(bytes);
        }
    }
}
impl Encode for bool {
    fn encode(&self, bytes: &mut Vec<u8>) {
        if *self {
            bytes.push(1)
        } else {
            bytes.push(0)
        }
    }
}
pub fn encode_vec_u16<T: Codec>(bytes: &mut Vec<u8>, items: &[T]) {
    let len_offset = bytes.len();
    bytes.extend(&[0, 0]);

    for i in items {
        i.encode(bytes);
    }

    let len = bytes.len() - len_offset - 2;
    let out: &mut [u8; 2] = (&mut bytes[len_offset..len_offset + 2]).try_into().unwrap();
    *out = u16::to_be_bytes(len.min(0xffff) as u16);
}

pub fn encode_vec_u24<T: Codec>(bytes: &mut Vec<u8>, items: &[T]) {
    let len_offset = bytes.len();
    bytes.extend(&[0, 0, 0]);

    for i in items {
        i.encode(bytes);
    }

    let len = bytes.len() - len_offset - 3;
    let len_bytes = u32::to_be_bytes(len.min(0xff_ffff) as u32);
    let out: &mut [u8; 3] = (&mut bytes[len_offset..len_offset + 3]).try_into().unwrap();
    out.copy_from_slice(&len_bytes[1..]);
}

pub fn read_vec_u8<T: Codec>(r: &mut Reader) -> Option<Vec<T>> {
    let mut ret: Vec<T> = Vec::new();
    let len = usize::from(u8::read(r)?);
    let mut sub = r.sub(len)?;

    while sub.any_left() {
        ret.push(T::read(&mut sub)?);
    }

    Some(ret)
}

pub fn read_vec_u16<T: Codec>(r: &mut Reader) -> Option<Vec<T>> {
    let mut ret: Vec<T> = Vec::new();
    let len = usize::from(u16::read(r)?);
    let mut sub = r.sub(len)?;

    while sub.any_left() {
        ret.push(T::read(&mut sub)?);
    }

    Some(ret)
}

pub fn read_vec_u24_limited<T: Codec>(r: &mut Reader, max_bytes: usize) -> Option<Vec<T>> {
    let mut ret: Vec<T> = Vec::new();
    let len = u24::read(r)?.0 as usize;
    if len > max_bytes {
        return None;
    }

    let mut sub = r.sub(len)?;

    while sub.any_left() {
        ret.push(T::read(&mut sub)?);
    }

    Some(ret)
}
