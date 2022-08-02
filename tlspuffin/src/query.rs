use puffin::{algebra::Matcher, error::Error, io::MessageResult};
use serde::{Deserialize, Serialize};

use crate::tls::rustls::msgs::{
    enums::{ContentType, HandshakeType},
    message::{Message, MessagePayload, OpaqueMessage},
};

/// [MessageType] contains TLS-related typing information, this is to be distinguished from the *.typ fields
/// It uses [rustls::msgs::enums::{ContentType,HandshakeType}].
#[derive(Debug, Deserialize, Serialize, Clone, Copy, Hash, Eq, PartialEq)]
pub enum TlsQueryMatcher {
    ChangeCipherSpec,
    Alert,
    Handshake(Option<HandshakeType>),
    ApplicationData,
    Heartbeat,
}

impl Matcher for TlsQueryMatcher {
    fn matches(&self, matcher: &TlsQueryMatcher) -> bool {
        match matcher {
            TlsQueryMatcher::Handshake(query_handshake_type) => match self {
                TlsQueryMatcher::Handshake(handshake_type) => {
                    handshake_type.matches(query_handshake_type)
                }
                _ => false,
            },
            TlsQueryMatcher::ChangeCipherSpec => matches!(self, TlsQueryMatcher::ChangeCipherSpec),
            TlsQueryMatcher::Alert => matches!(self, TlsQueryMatcher::Alert),
            TlsQueryMatcher::Heartbeat => matches!(self, TlsQueryMatcher::Heartbeat),
            TlsQueryMatcher::ApplicationData => matches!(self, TlsQueryMatcher::ApplicationData),
        }
    }

    fn specificity(&self) -> u32 {
        match self {
            TlsQueryMatcher::Handshake(handshake_type) => {
                1 + match handshake_type {
                    None => 0,
                    Some(handshake_type) => handshake_type.specificity(),
                }
            }
            _ => 0,
        }
    }
}

impl TryFrom<&MessageResult<Message, OpaqueMessage>> for TlsQueryMatcher {
    type Error = Error;

    fn try_from(
        message_result: &MessageResult<Message, OpaqueMessage>,
    ) -> Result<Self, Self::Error> {
        let tls_opaque_type = message_result.1.typ;
        match (tls_opaque_type, message_result) {
            (ContentType::Handshake, MessageResult(Some(message), _)) => match &message.payload {
                MessagePayload::Handshake(handshake_payload) => {
                    Ok(TlsQueryMatcher::Handshake(Some(handshake_payload.typ)))
                }
                MessagePayload::TLS12EncryptedHandshake(_) => Ok(TlsQueryMatcher::Handshake(None)),
                _ => Err(Error::Extraction()),
            },
            (ContentType::Handshake, _) => Ok(TlsQueryMatcher::Handshake(None)),
            (ContentType::ApplicationData, _) => Ok(TlsQueryMatcher::ApplicationData),
            (ContentType::Heartbeat, _) => Ok(TlsQueryMatcher::Heartbeat),
            (ContentType::Alert, _) => Ok(TlsQueryMatcher::Alert),
            (ContentType::ChangeCipherSpec, _) => Ok(TlsQueryMatcher::ChangeCipherSpec),
            (ContentType::Unknown(_), _) => Err(Error::Extraction()),
        }
    }
}
