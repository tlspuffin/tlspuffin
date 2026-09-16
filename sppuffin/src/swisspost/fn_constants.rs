#![allow(clippy::ptr_arg)]
#![allow(dead_code)]

use puffin::algebra::error::FnError;
use crate::protocol::SppU64;

pub fn fn_true() -> Result<bool, FnError> {
    Ok(true)
}
pub fn fn_false() -> Result<bool, FnError> {
    Ok(false)
}

pub fn fn_seq_0() -> Result<SppU64, FnError> {
    Ok(SppU64(0))
}
pub fn fn_seq_1() -> Result<SppU64, FnError> {
    Ok(SppU64(1))
}
pub fn fn_seq_2() -> Result<SppU64, FnError> {
    Ok(SppU64(2))
}
pub fn fn_seq_3() -> Result<SppU64, FnError> {
    Ok(SppU64(3))
}
// No symbolic use of sequence number >=4, could be removed if bit-level mutations
// are allowed on this type
pub fn fn_seq_4() -> Result<SppU64, FnError> {
    Ok(SppU64(4))
}
pub fn fn_seq_5() -> Result<SppU64, FnError> {
    Ok(SppU64(5))
}
pub fn fn_seq_6() -> Result<SppU64, FnError> {
    Ok(SppU64(6))
}
pub fn fn_seq_7() -> Result<SppU64, FnError> {
    Ok(SppU64(7))
}
pub fn fn_seq_8() -> Result<SppU64, FnError> {
    Ok(SppU64(8))
}
pub fn fn_seq_9() -> Result<SppU64, FnError> {
    Ok(SppU64(9))
}
pub fn fn_seq_10() -> Result<SppU64, FnError> {
    Ok(SppU64(10))
}
pub fn fn_seq_11() -> Result<SppU64, FnError> {
    Ok(SppU64(11))
}
pub fn fn_seq_12() -> Result<SppU64, FnError> {
    Ok(SppU64(12))
}
pub fn fn_seq_13() -> Result<SppU64, FnError> {
    Ok(SppU64(13))
}
pub fn fn_seq_14() -> Result<SppU64, FnError> {
    Ok(SppU64(14))
}
pub fn fn_seq_15() -> Result<SppU64, FnError> {
    Ok(SppU64(15))
}
pub fn fn_seq_16() -> Result<SppU64, FnError> {
    Ok(SppU64(16))
}
