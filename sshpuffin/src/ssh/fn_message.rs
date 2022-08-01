use puffin::algebra::error::FnError;

use crate::ssh::message::RawMessage;

pub fn fn_banner(banner: &String) -> Result<RawMessage, FnError> {
    Ok(RawMessage::Banner(banner.clone()))
}
