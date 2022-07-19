use std::fmt;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FnError {
    Unknown(String),
    Rustls(String),
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
            FnError::Unknown(msg) => write!(f, "error in fn: {}", msg),
            FnError::Rustls(msg) => write!(f, "error in fn from rustls: {}", msg),
        }
    }
}
