use std::{fmt, fmt::Formatter, io};

use crate::algebra::error::FnError;

#[derive(Debug, Clone)]
pub enum Error {
    /// Returned if a concrete function from the module [`tls`] fails or term evaluation fails
    Fn(FnError),
    Term(String),
    /// PUT reported an error
    Put(String),
    /// There was an unexpected IO error. Should never happen because we are not fuzzing on a network which can fail.
    IO(String),
    /// Some error which was caused because of agents or their names. Like an agent which was not found.
    Agent(String),
    /// Error while operating on a [`Stream`]
    Stream(String),
    Extraction(),
    SecurityClaim(&'static str),
}

impl std::error::Error for Error {}

impl From<anyhow::Error> for Error {
    fn from(value: anyhow::Error) -> Self {
        Self::Term(format!("AnyHow Error: {}", value))
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Error::Fn(err) => write!(f, "error executing a function symbol: {}", err),
            Error::Term(err) => write!(f, "error evaluating a term: {}", err),
            Error::Put(err) => write!(f, "error in openssl: {}", err),
            Error::IO(err) => write!(
                f,
                "error in io of openssl (this should not happen): {}",
                err
            ),
            Error::Agent(err) => write!(f, "error regarding an agent: {}", err),
            Error::Stream(err) => write!(f, "error in the stream: {}", err),
            Error::Extraction() => write!(f, "error while extracting variable",),
            Error::SecurityClaim(msg) => write!(
                f,
                "error because a security violation occurred. msg: {}",
                msg
            ),
        }
    }
}

impl From<FnError> for Error {
    fn from(err: FnError) -> Self {
        Error::Fn(err)
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Error::IO(err.to_string())
    }
}
