use puffin::{error::Error, io::MessageResult, trace::QueryMatcher};
use rustls::msgs::{
    enums::{ContentType, HandshakeType},
    message::MessagePayload,
};

/// [MessageType] contains TLS-related typing information, this is to be distinguished from the *.typ fields
/// It uses [rustls::msgs::enums::{ContentType,HandshakeType}].
#[derive(Debug, Deserialize, Serialize, Clone, Copy, Hash, Eq, PartialEq)]
pub enum TlsMessageType {
    ChangeCipherSpec,
    Alert,
    Handshake(Option<HandshakeType>),
    ApplicationData,
    Heartbeat,
}

impl QueryMatcher for HandshakeType {
    fn matches(&self, query: &Self) -> bool {
        query == self
    }
}

impl QueryMatcher for TlsMessageType {
    fn matches(&self, query: &TlsMessageType) -> bool {
        match query {
            TlsMessageType::Handshake(query_handshake_type) => match self {
                TlsMessageType::Handshake(handshake_type) => {
                    handshake_type.matches(query_handshake_type)
                }
                _ => false,
            },
            TlsMessageType::ChangeCipherSpec => matches!(self, TlsMessageType::ChangeCipherSpec),
            TlsMessageType::Alert => matches!(self, TlsMessageType::Alert),
            TlsMessageType::Heartbeat => matches!(self, TlsMessageType::Heartbeat),
            TlsMessageType::ApplicationData => matches!(self, TlsMessageType::ApplicationData),
        }
    }
}

impl TryFrom<&MessageResult> for TlsMessageType {
    type Error = Error;

    fn try_from(message_result: &MessageResult) -> Result<Self, Self::Error> {
        let tls_opaque_type = message_result.1.typ;
        match (tls_opaque_type, message_result) {
            (ContentType::Handshake, MessageResult(Some(message), _)) => match &message.payload {
                MessagePayload::Handshake(handshake_payload) => {
                    Ok(TlsMessageType::Handshake(Some(handshake_payload.typ)))
                }
                MessagePayload::TLS12EncryptedHandshake(_) => Ok(TlsMessageType::Handshake(None)),
                _ => Err(Error::Extraction()),
            },
            (ContentType::Handshake, _) => Ok(TlsMessageType::Handshake(None)),
            (ContentType::ApplicationData, _) => Ok(TlsMessageType::ApplicationData),
            (ContentType::Heartbeat, _) => Ok(TlsMessageType::Heartbeat),
            (ContentType::Alert, _) => Ok(TlsMessageType::Alert),
            (ContentType::ChangeCipherSpec, _) => Ok(TlsMessageType::ChangeCipherSpec),
            (ContentType::Unknown(_), _) => Err(Error::Extraction()),
        }
    }
}

impl TlsMessageType {
    pub fn specificity(&self) -> u32 {
        match self {
            TlsMessageType::Handshake(handshake_type) => {
                1 + match handshake_type {
                    None => 0,
                    Some(_) => 1,
                }
            }
            _ => 0,
        }
    }
}
