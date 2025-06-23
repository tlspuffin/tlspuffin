use puffin::algebra::Matcher;
use serde::{Deserialize, Serialize};

use crate::tls::rustls::msgs::enums::HandshakeType;

/// [TlsQueryMatcher] contains TLS-related typing information, this is to be distinguished from the
/// *.typ fields It uses [rustls::msgs::enums::{ContentType,HandshakeType}].
#[derive(Debug, Deserialize, Serialize, Clone, Copy, Hash, Eq, PartialEq)]
pub enum TlsQueryMatcher {
    ChangeCipherSpec,
    Alert,
    Handshake(Option<HandshakeType>),
    ApplicationData,
    Heartbeat,
    ClientHelloFlight,
    ServerHelloFlight,
    EncryptedFlight,
    OtherFlight,
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
            TlsQueryMatcher::ClientHelloFlight => {
                matches!(self, TlsQueryMatcher::ClientHelloFlight)
            }
            TlsQueryMatcher::ServerHelloFlight => {
                matches!(self, TlsQueryMatcher::ServerHelloFlight)
            }
            TlsQueryMatcher::EncryptedFlight => matches!(self, TlsQueryMatcher::EncryptedFlight),
            TlsQueryMatcher::OtherFlight => matches!(self, TlsQueryMatcher::OtherFlight),
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
