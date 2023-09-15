use std::fmt;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FnError {
    Unknown(String),
    /// Error which happened because a cryptographic operation failed.
    Crypto(String),
    /// Error which happens because the term is malformed (e.g. a field is missing)
    Malformed(String),
}

impl std::error::Error for FnError {}

impl From<String> for FnError {
    fn from(message: String) -> Self {
        FnError::Unknown(message)
    }
}

impl fmt::Display for FnError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            FnError::Unknown(msg) => write!(f, "[!!UNKNOWN!!] error in fn: {}", msg),
            FnError::Crypto(msg) => write!(f, "[Crypto] error in fn from rustls: {}", msg),
            FnError::Malformed(msg) => write!(f, "[Malformed] error in fn from rustls: {}", msg),
        }
    }
}
