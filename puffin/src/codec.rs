use std::fmt::Debug;

use crate::error::Error;

/// Read from a byte slice.
pub struct Reader<'a> {
    buf: &'a [u8],
    offs: usize,
}

impl<'a> Reader<'a> {
    #[must_use]
    pub const fn init(bytes: &[u8]) -> Reader {
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

    #[must_use]
    pub fn peek(&self, len: usize) -> Option<&[u8]> {
        if self.left() < len {
            return None;
        }

        let current = self.offs;
        Some(&self.buf[current..current + len])
    }

    #[must_use]
    pub const fn any_left(&self) -> bool {
        self.offs < self.buf.len()
    }

    #[must_use]
    pub const fn left(&self) -> usize {
        self.buf.len() - self.offs
    }

    #[must_use]
    pub const fn used(&self) -> usize {
        self.offs
    }

    pub fn sub(&mut self, len: usize) -> Option<Reader> {
        self.take(len).map(Reader::init)
    }
}

/// Things we can encode and read from a Reader.
/// Used by puffin as it does not require to be `Sized` (we rely on `<dyn T>` for `T:CodecP`.
pub trait CodecP: Debug {
    /// Encode yourself by appending onto `bytes`.
    fn encode(&self, bytes: &mut Vec<u8>);

    /// Decode yourself by fiddling with the `Reader`.
    /// Return Some if it worked, None if not.
    fn read(&mut self, _: &mut Reader) -> Result<(), Error>;

    /// Convenience function to get the results of `encode()`.
    fn get_encoding(&self) -> Vec<u8> {
        let mut ret = Vec::new();
        self.encode(&mut ret);
        ret
    }

    /// Read one of these from the front of `bytes` and
    /// return it.
    fn read_bytes(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let mut rd = Reader::init(bytes);
        self.read(&mut rd)
    }
}

/// Things we can encode and read from a Reader, `Sized` version.
/// Easier to work with when types are instantiated, for example in protocol crates such as
/// `tlspuffin`.
pub trait Codec: Debug + Sized {
    /// Encode yourself by appending onto `bytes`.
    fn encode(&self, bytes: &mut Vec<u8>);

    /// Decode yourself by fiddling with the `Reader`.
    /// Return Some if it worked, None if not.
    fn read(_: &mut Reader) -> Option<Self>;

    /// Convenience function to get the results of `encode()`.
    fn get_encoding(&self) -> Vec<u8> {
        let mut ret = Vec::new();
        self.encode(&mut ret);
        ret
    }

    /// Read one of these from the front of `bytes` and
    /// return it.
    #[must_use]
    fn read_bytes(bytes: &[u8]) -> Option<Self> {
        let mut rd = Reader::init(bytes);
        Self::read(&mut rd)
    }
}

impl<T: Codec> CodecP for T {
    fn encode(&self, bytes: &mut Vec<u8>) {
        T::encode(self, bytes);
    }

    fn read(&mut self, r: &mut Reader) -> Result<(), Error> {
        match T::read(r) {
            None => Err(Error::Term(format!(
                "Failed to read for type {}",
                std::any::type_name::<T>()
            ))),
            Some(it) => {
                *self = it;
                Ok(())
            }
        }
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

#[must_use]
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
    #[must_use]
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
        bytes.extend_from_slice(&be_bytes[1..]);
    }

    fn read(r: &mut Reader) -> Option<Self> {
        r.take(3).and_then(Self::decode)
    }
}

#[must_use]
pub fn decode_u32(bytes: &[u8]) -> Option<u32> {
    Some(u32::from_be_bytes(bytes.try_into().ok()?))
}

impl Codec for u32 {
    fn encode(&self, bytes: &mut Vec<u8>) {
        bytes.extend(&Self::to_be_bytes(*self));
    }

    fn read(r: &mut Reader) -> Option<Self> {
        r.take(4).and_then(decode_u32)
    }
}

pub fn put_u64(v: u64, bytes: &mut [u8]) {
    let bytes: &mut [u8; 8] = (&mut bytes[..8]).try_into().unwrap();
    *bytes = u64::to_be_bytes(v);
}

#[must_use]
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

/// encode a Vec whose length is encoded in 1 byte
pub fn encode_vec_u8<T: CodecP>(bytes: &mut Vec<u8>, items: &[T]) {
    let len_offset = bytes.len();
    bytes.push(0);

    for i in items {
        i.encode(bytes);
    }

    let len = bytes.len() - len_offset - 1;
    bytes[len_offset] = len.min(0xff) as u8;
}

// We do not put the size of the vector for Vec<u8> as we consider it as plain data
impl Codec for Vec<u8> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        for i in self {
            bytes.push(*i);
        }
    }

    fn read(r: &mut Reader) -> Option<Self> {
        let mut ret: Self = Self::new();

        while r.any_left() {
            ret.push(<u8 as Codec>::read(r)?);
        }

        Some(ret)
    }
}

impl<T: Debug + Codec> Codec for Option<T> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        if let Some(value) = self {
            value.encode(bytes);
        }
    }

    fn read(r: &mut Reader) -> Option<Self> {
        if r.any_left() {
            Some(T::read(r))
        } else {
            Some(None)
        }
    }
}

impl Codec for bool {
    fn encode(&self, bytes: &mut Vec<u8>) {
        if *self {
            bytes.push(1);
        } else {
            bytes.push(0);
        }
    }

    fn read(r: &mut Reader) -> Option<Self> {
        r.take(1).map(|b| b.len() == 1 && b[0] == 1)
    }
}

/// encode a Vec whose length is encoded in 2 bytes
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

/// encode a Vec whose length is encoded in 3 bytes
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
    let len = usize::from(<u8 as Codec>::read(r)?);
    let mut sub = r.sub(len)?;

    while sub.any_left() {
        ret.push(T::read(&mut sub)?);
    }

    Some(ret)
}

pub fn read_vec_u16<T: Codec>(r: &mut Reader) -> Option<Vec<T>> {
    let mut ret: Vec<T> = Vec::new();
    let len = usize::from(<u16 as Codec>::read(r)?);
    let mut sub = r.sub(len)?;

    while sub.any_left() {
        ret.push(T::read(&mut sub)?);
    }

    Some(ret)
}

pub fn read_vec_u24_limited<T: Codec>(r: &mut Reader, max_bytes: usize) -> Option<Vec<T>> {
    let mut ret: Vec<T> = Vec::new();
    let len = <u24 as Codec>::read(r)?.0 as usize;
    if len > max_bytes {
        return None;
    }

    let mut sub = r.sub(len)?;

    while sub.any_left() {
        ret.push(T::read(&mut sub)?);
    }

    Some(ret)
}

impl Codec for [u8; 16] {
    fn encode(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(self);
    }

    fn read(r: &mut Reader) -> Option<Self> {
        <Vec<u8> as Codec>::read(r).and_then(|v| {
            let mut ret = [0u8; 16];
            ret.copy_from_slice(&v);
            Some(ret)
        })
    }
}

impl Codec for String {
    fn encode(&self, bytes: &mut Vec<u8>) {
        <Vec<u8> as Codec>::encode(&self.as_bytes().to_vec(), bytes);
    }

    fn read(r: &mut Reader) -> Option<Self> {
        <Vec<u8> as Codec>::read(r).map(|v| String::from_utf8_lossy(&v).to_string())
    }
}

/// Trait for data whose Vectors are encoded without length prefix
pub trait VecCodecWoSize {}
impl VecCodecWoSize for Vec<u8> {}

impl<T: Codec + VecCodecWoSize> Codec for Vec<T> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        for i in self {
            i.encode(bytes);
        }
    }

    fn read(r: &mut Reader) -> Option<Self> {
        let mut ret: Self = Self::new();

        while r.any_left() {
            ret.push(T::read(r)?);
        }

        Some(ret)
    }
}

pub fn compare_encoding<X: Codec, Y: Codec>(x: &X, y: &Y) -> std::cmp::Ordering {
    match Codec::get_encoding(x) <= Codec::get_encoding(y) {
        true => std::cmp::Ordering::Less,
        false => std::cmp::Ordering::Greater,
    }
}
