use std::fmt;
use webpki::InvalidDnsNameError;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FnError {
    Message(String),
    Rustls(String),
}

impl std::error::Error for FnError {}

impl From<rustls::error::Error> for FnError {
    fn from(err: rustls::error::Error) -> Self {
        FnError::Rustls(err.to_string())
    }
}

impl From<String> for FnError {
    fn from(message: String) -> Self {
        FnError::Message(message)
    }
}

impl From<ring::error::Unspecified> for FnError {
    fn from(err: ring::error::Unspecified) -> Self {
        FnError::Message(err.to_string()) // Returns ring::error::Unspecified"
    }
}

impl From<InvalidDnsNameError> for FnError {
    fn from(err: InvalidDnsNameError) -> Self {
        FnError::Message(err.to_string())
    }
}

impl fmt::Display for FnError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FnError::Message(msg) => write!(f, "error in fn: {}", msg),
            FnError::Rustls(msg) =>  write!(f, "error in fn from rustls: {}", msg),
        }
    }
}