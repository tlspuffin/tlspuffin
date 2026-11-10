#![allow(clippy::ptr_arg)]
#![allow(dead_code)]

use puffin::algebra::error::FnError;

pub fn fn_true() -> Result<bool, FnError> {
    Ok(true)
}
pub fn fn_false() -> Result<bool, FnError> {
    Ok(false)
}

pub fn fn_seq_0() -> Result<u64, FnError> {
    Ok(0)
}
pub fn fn_seq_1() -> Result<u64, FnError> {
    Ok(1)
}
pub fn fn_seq_2() -> Result<u64, FnError> {
    Ok(2)
}
pub fn fn_seq_3() -> Result<u64, FnError> {
    Ok(3)
}
// No symbolic use of sequence number >=4, could be removed if bit-level mutations
// are allowed on this type
pub fn fn_seq_4() -> Result<u64, FnError> {
    Ok(4)
}
pub fn fn_seq_5() -> Result<u64, FnError> {
    Ok(5)
}
pub fn fn_seq_6() -> Result<u64, FnError> {
    Ok(6)
}
pub fn fn_seq_7() -> Result<u64, FnError> {
    Ok(7)
}
pub fn fn_seq_8() -> Result<u64, FnError> {
    Ok(8)
}
pub fn fn_seq_9() -> Result<u64, FnError> {
    Ok(9)
}
pub fn fn_seq_10() -> Result<u64, FnError> {
    Ok(10)
}
pub fn fn_seq_11() -> Result<u64, FnError> {
    Ok(11)
}
pub fn fn_seq_12() -> Result<u64, FnError> {
    Ok(12)
}
pub fn fn_seq_13() -> Result<u64, FnError> {
    Ok(13)
}
pub fn fn_seq_14() -> Result<u64, FnError> {
    Ok(14)
}
pub fn fn_seq_15() -> Result<u64, FnError> {
    Ok(15)
}
pub fn fn_seq_16() -> Result<u64, FnError> {
    Ok(16)
}

/// Used in heartbleed attack
pub fn fn_large_length() -> Result<u64, FnError> {
    Ok(32702) // chosen by experimenting
}

pub fn fn_empty_bytes_vec() -> Result<Vec<u8>, FnError> {
    Ok(vec![])
}

pub fn fn_large_bytes_vec() -> Result<Vec<u8>, FnError> {
    Ok(vec![42; 700])
}

/// Two bytes encoding a large big-endian 16-bit length (0xF000 = 61440), for length-prefixed
/// fields whose length is not checked against the enclosing message.
///
/// Used in CVE-2026-5393 as the signature field of a dual-algorithm (CKS "both")
/// CertificateVerify: wolfSSL 5.9.0 reads it as the first signature length and then reads the
/// second length 2 + 61440 bytes further, without bounds check. In the tlspuffin wolfSSL 5.9.0
/// build the record lies in the static input buffer of the 44128-byte `WOLFSSL` object, so any
/// first length >= ~0xA9B6 reads past the end of that object (ASan heap-buffer-overflow; 0xFFFF
/// crashes with a SEGV instead). Smaller lengths read valid memory inside the object, which ASan
/// cannot see.
pub fn fn_large_u16_length_bytes() -> Result<Vec<u8>, FnError> {
    Ok(vec![0xF0, 0x00])
}
