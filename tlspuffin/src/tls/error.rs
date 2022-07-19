use rustls::msgs::message::MessageError;

impl From<rustls::error::Error> for FnError {
    fn from(err: rustls::error::Error) -> Self {
        FnError::Rustls(err.to_string())
    }
}

impl From<String> for FnError {
    fn from(message: String) -> Self {
        FnError::Unknown(message)
    }
}

impl From<MessageError> for FnError {
    fn from(err: MessageError) -> Self {
        FnError::Unknown(format!("{:?}", err))
    }
}

impl From<ring::error::Unspecified> for FnError {
    fn from(err: ring::error::Unspecified) -> Self {
        FnError::Unknown(err.to_string()) // Returns ring::error::Unspecified"
    }
}
