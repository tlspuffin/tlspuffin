use std::any::Any;
use std::fmt::Formatter;
use std::{fmt, io};

use libafl::bolts::serdeany::SerdeAny;
use libafl::executors::CustomExitKind;
use openssl::error::ErrorStack;
use serde::{Serialize, Serializer};

use crate::tls::error::FnError;
use rustls::msgs::enums::ContentType;
use id_tree::NodeIdError;

// #[derive(Debug, Clone, Serialize)] Serialization not used right now
#[derive(Debug, Clone)]
pub enum Error {
    /// Returned if a concrete function from the module [`tls`] fails or term evaluation fails
    Fn(FnError),
    Term(String),
    /// OpenSSL reported an error
    //#[serde(serialize_with = "serialize_openssl_error")]
    OpenSSL(ErrorStack),
    /// There was an unexpected IO error. Should never happen because we are not fuzzing on a network which can fail.
    IO(String),
    /// Some error which was caused because of agents or their names. Like an agent which was not found.
    Agent(String),
    /// Error while operating on a [`Stream`]
    Stream(String),
    Extraction(ContentType),
}

/*fn serialize_openssl_error<S>(error: &ErrorStack, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(error.to_string().as_str())
}

impl SerdeAny for Error {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

impl CustomExitKind for Error {}*/

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
            Error::Extraction(content_type) => write!(f, "error while extracting variable data from {:?}", content_type),
        }
    }
}

impl From<openssl::error::ErrorStack> for Error {
    fn from(err: ErrorStack) -> Self {
        Error::OpenSSL(err)
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

impl From<NodeIdError> for Error {
    fn from(err: NodeIdError) -> Self {
        Error::Term(err.to_string())
    }
}
