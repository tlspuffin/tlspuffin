use std::fmt;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum FnError {
    Unknown(String),
    /// Error which happened because a cryptographic operation failed.
    Crypto(String),
    /// Error which happens because the term is malformed (e.g. a field is missing)
    Malformed(String),
    /// Error which happens because of Codec needs to be used and failed (most likely read failed)
    Codec(String),
}

impl std::error::Error for FnError {}

impl From<String> for FnError {
    fn from(message: String) -> Self {
        Self::Unknown(message)
    }
}

impl fmt::Display for FnError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Unknown(msg) => write!(f, "[!!UNKNOWN!!] error in fn: {msg}"),
            Self::Crypto(msg) => write!(f, "[Crypto] error in fn from rustls: {msg}"),
            Self::Malformed(msg) => write!(f, "[Malformed] error in fn from rustls: {msg}"),
            Self::Codec(msg) => write!(
                f,
                "[Codec] error in fn from rustls due to a Codec usage: {msg}"
            ),
        }
    }
}
