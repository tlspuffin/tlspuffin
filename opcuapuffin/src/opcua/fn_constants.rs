use puffin::algebra::error::FnError;

pub fn fn_true() -> Result<bool, FnError> {
    Ok(true)
}
pub fn fn_false() -> Result<bool, FnError> {
    Ok(false)
}
