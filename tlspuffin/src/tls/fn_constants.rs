#![allow(clippy::ptr_arg)]
#![allow(dead_code)]

use puffin::algebra::error::FnError;
use puffin::codec;
use puffin::codec::Encode;

// TODO-bitlevel: bools: easier to DY-mutate them! (just one flip is possible)
// TODO: make sure there is no use of this that put the bool in a message, in that case
// HAVOC without DY mutations would not be equal to AFL-like fuzzers
pub fn fn_true() -> Result<bool, FnError> {
    Ok(true)
}
pub fn fn_false() -> Result<bool, FnError> {
    Ok(false)
}

// TODO-bitlevel: fn_seq not sure they are found in plaintext in the ned, I looked for usages and found
// seq used as a squence number for encryption. For this usage, seq is serialized as expected.
// See make_nonce in ciphers.rs
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
// are allowed on ths type
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
