use puffin::algebra::error::FnError;

pub fn fn_true() -> Result<bool, FnError> {
    Ok(true)
}
pub fn fn_false() -> Result<bool, FnError> {
    Ok(false)
}

pub fn fn_seq_0() -> Result<u32, FnError> {
    Ok(0)
}