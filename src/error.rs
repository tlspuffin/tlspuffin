use std::fmt::Formatter;
use std::{fmt, io};

use openssl::error::ErrorStack;

use crate::tls::FnError;

#[derive(Debug, Clone)]
pub enum Error {
    /// A concrete function failed
    FnError(FnError),
    /// OpenSSL reported an error
    OpenSSLErrorStack(ErrorStack),
    /// There was an unexpected IO error. Should never happen because we are not fuzzing on a network which can fail.
    IOError(String),
    /// Some error which was caused because of agents or their names. Like an agent which was not found.
    Agent(String),
    /// Error while operating on a [`Stream`]
    Stream(String),
    /// Error which happened during term evaluation
    TermEvaluation(String)
}

impl std::error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Error::FnError(err) =>  write!(f, "{}: {}", "FnError", err),
            Error::OpenSSLErrorStack(err) => write!(f, "{}: {}", "OpenSSLErrorStack", err),
            Error::IOError(err) => write!(f, "{}: {}", "IOError", err),
            Error::Agent(err) => write!(f, "{}: {}", "Agent", err),
            Error::Stream(err) => write!(f, "{}: {}", "Stream", err),
            Error::TermEvaluation(err) => write!(f, "{}: {}", "TermEvaluation", err),
        }
    }
}

impl From<openssl::error::ErrorStack> for Error {
    fn from(err: ErrorStack) -> Self {
        Error::OpenSSLErrorStack(err)
    }
}

impl From<FnError> for Error {
    fn from(err: FnError) -> Self {
        Error::FnError(err)
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Error::IOError(err.to_string())
    }
}
