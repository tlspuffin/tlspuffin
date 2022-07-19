use std::{fmt, fmt::Formatter, io};

use rustls::msgs::enums::ContentType;

use crate::{agent::AgentName, claims::ClaimList, tls::error::FnError};

#[derive(Debug, Clone)]
pub enum Error {
    /// Returned if a concrete function from the module [`tls`] fails or term evaluation fails
    Fn(FnError),
    Term(String),
    /// OpenSSL reported an error
    OpenSSL(String),
    /// There was an unexpected IO error. Should never happen because we are not fuzzing on a network which can fail.
    IO(String),
    /// Some error which was caused because of agents or their names. Like an agent which was not found.
    Agent(String),
    /// Error while operating on a [`Stream`]
    Stream(String),
    Extraction(ContentType),
    SecurityClaim(&'static str, ClaimList),
}

impl std::error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Error::Fn(err) => write!(f, "error executing a function symbol: {}", err),
            Error::Term(err) => write!(f, "error evaluating a term: {}", err),
            Error::OpenSSL(err) => write!(f, "error in openssl: {}", err),
            Error::IO(err) => write!(
                f,
                "error in io of openssl (this should not happen): {}",
                err
            ),
            Error::Agent(err) => write!(f, "error regarding an agent: {}", err),
            Error::Stream(err) => write!(f, "error in the stream: {}", err),
            Error::Extraction(content_type) => write!(
                f,
                "error while extracting variable data from {:?}",
                content_type
            ),
            Error::SecurityClaim(msg, claims) => write!(
                f,
                "error because a security violation occurred. msg: {}, claims: {:?}",
                msg, claims
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
