use std::{fmt, io};

use crate::algebra::error::FnError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Returned if a concrete function from the protocol fails or term evaluation fails
    Fn(FnError),
    /// Error while evaluating a term
    Term(String),
    /// Error while evaluating a term due to a bug (for debugging)
    TermBug(String),
    /// Error while encoding/reading EvaluatedTerm ->/<- bitstring
    Codec(String),
    /// PUT reported an error
    Put(String),
    /// There was an unexpected IO error. Should never happen because we are not fuzzing on a
    /// network which can fail.
    IO(String),
    /// Some error which was caused because of agents or their names. Like an agent which was not
    /// found.
    Agent(String),
    /// Error while operating on a [`Stream`](crate::stream::Stream)
    Stream(String),
    Extraction(),
    SecurityClaim(&'static str),
}

impl std::error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Fn(err) => write!(f, "error executing a function symbol: {err}"),
            Self::Term(err) => write!(f, "error evaluating a term: {err}"),
            Self::TermBug(err) => write!(f, "critical error evaluating a term due to a bug: {err}"),
            Error::Codec(err) => write!(
                f,
                "error encoding/reading an EvaluatedTerm/bitstring: {err}"
            ),
            Self::Put(err) => write!(f, "error in openssl: {err}"),
            Self::IO(err) => write!(f, "error in io of openssl (this should not happen): {err}"),
            Self::Agent(err) => write!(f, "error regarding an agent: {err}"),
            Self::Stream(err) => write!(f, "error in the stream: {err}"),
            Self::Extraction() => write!(f, "error while extracting variable",),
            Self::SecurityClaim(msg) => {
                write!(f, "error because a security violation occurred. msg: {msg}")
            }
        }
    }
}

impl From<FnError> for Error {
    fn from(err: FnError) -> Self {
        Self::Fn(err)
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Self::IO(err.to_string())
    }
}
