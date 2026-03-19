use std::any::TypeId;

use comparable::Comparable;
use extractable_macro::Extractable;
use puffin::agent::{AgentDescriptor, AgentName, ProtocolDescriptorConfig};
use puffin::algebra::signature::Signature;
use puffin::algebra::Matcher;
use puffin::differential::TraceDifference;
use puffin::error::Error;
use puffin::protocol::{
    EvaluatedTerm, Extractable, OpaqueProtocolMessage, OpaqueProtocolMessageFlight,
    ProtocolBehavior, ProtocolMessage, ProtocolMessageDeframer, ProtocolMessageFlight,
    ProtocolTypes,
};
use puffin::put::PutDescriptor;
use puffin::trace::{Knowledge, Source, Trace};
use puffin::{atom_extract_knowledge, codec, dummy_codec, dummy_extract_knowledge, term};
use serde::{Deserialize, Serialize};

use crate::claims::{
    TlsClaim, TranscriptCertificate, TranscriptClientFinished, TranscriptClientHello,
    TranscriptPartialClientHello, TranscriptServerFinished, TranscriptServerHello,
};
use crate::debug::{debug_message_with_info, debug_opaque_message_with_info};
use crate::put_registry::tls_registry;
use crate::query::TlsQueryMatcher;
use crate::tls::fn_impl::{
    fn_decrypt_handshake_flight_with_secret, fn_false, fn_finished_get_cipher,
    fn_finished_get_client_random, fn_finished_get_handshake_secret, fn_seq_0,
    fn_server_hello_transcript, fn_true,
};
use crate::tls::rustls::hash_hs::HandshakeHash;
use crate::tls::rustls::msgs::deframer::MessageDeframer;
use crate::tls::rustls::msgs::handshake::{
    CertReqExtension, CertificateEntry, CertificateExtension, CertificatePayloadTLS13,
    CertificateRequestPayload, CertificateRequestPayloadTLS13, CertificateStatus,
    ClientSessionTicket, DigitallySignedStruct, HelloRetryExtension, NewSessionTicketExtension,
    NewSessionTicketPayloadTLS13, PresharedKeyIdentity, Random, ServerExtension, SessionID,
    UnknownExtension,
};
use crate::tls::rustls::msgs::message::{try_read_bytes, Message, MessagePayload, OpaqueMessage};
use crate::tls::rustls::msgs::{self};
use crate::tls::violation::TlsSecurityViolationPolicy;
use crate::tls::TLS_SIGNATURE;

#[derive(Debug, Clone, Comparable)]
pub struct MessageFlight {
    pub messages: Vec<Message>,
}

impl Extractable<TLSProtocolTypes> for MessageFlight {
    fn extract_knowledge<'a>(
        &'a self,
        knowledges: &mut Vec<Knowledge<'a, TLSProtocolTypes>>,
        _: Option<TlsQueryMatcher>,
        source: &'a Source,
    ) -> Result<(), Error> {
        // Classify flight by the first non-CCS message. TLS 1.3 middlebox
        // compatibility (e.g. LibreSSL) may prepend a dummy ChangeCipherSpec.
        let matcher = self
            .messages
            .iter()
            .find(|m| !matches!(m.payload, MessagePayload::ChangeCipherSpec(_)))
            .map(|msg| match &msg.payload {
                MessagePayload::Handshake(hs) => match hs.payload {
                    msgs::handshake::HandshakePayload::ClientHello(_) => {
                        TlsQueryMatcher::ClientHelloFlight
                    }
                    msgs::handshake::HandshakePayload::ServerHello(_) => {
                        TlsQueryMatcher::ServerHelloFlight
                    }
                    _ => TlsQueryMatcher::OtherFlight,
                },
                MessagePayload::ApplicationData(_) => TlsQueryMatcher::EncryptedFlight,
                _ => TlsQueryMatcher::OtherFlight,
            });

        knowledges.push(Knowledge {
            source,
            matcher,
            data: self,
        });

        self.messages.extract_knowledge(knowledges, None, source)?;
        Ok(())
    }
}

impl ProtocolMessageFlight<TLSProtocolTypes, Message, OpaqueMessage, OpaqueMessageFlight>
    for MessageFlight
{
    fn new() -> Self {
        Self { messages: vec![] }
    }

    fn push(&mut self, msg: Message) {
        self.messages.push(msg);
    }

    fn debug(&self, info: &str) {
        log::debug!("{}: {:?}", info, self);
    }
}

impl From<Message> for MessageFlight {
    fn from(value: Message) -> Self {
        Self {
            messages: vec![value],
        }
    }
}

impl codec::Codec for MessageFlight {
    fn encode(&self, bytes: &mut Vec<u8>) {
        for msg in &self.messages {
            msg.encode(bytes);
        }
    }

    fn read(reader: &mut codec::Reader) -> Option<Self> {
        let mut flight = Self::new();

        while let Some(msg) = Message::read(reader) {
            flight.push(msg);
        }
        Some(flight)
    }
}

#[derive(Debug, Clone, Extractable, Comparable)]
#[extractable(TLSProtocolTypes)]
pub struct OpaqueMessageFlight {
    pub messages: Vec<OpaqueMessage>,
}

impl OpaqueProtocolMessageFlight<TLSProtocolTypes, OpaqueMessage> for OpaqueMessageFlight {
    fn new() -> Self {
        Self { messages: vec![] }
    }

    fn push(&mut self, msg: OpaqueMessage) {
        self.messages.push(msg);
    }

    fn debug(&self, info: &str) {
        log::debug!("{}: {:?}", info, self);
    }
}

impl codec::Codec for OpaqueMessageFlight {
    fn encode(&self, bytes: &mut Vec<u8>) {
        for msg in &self.messages {
            msg.encode(bytes);
        }
    }

    fn read(reader: &mut codec::Reader) -> Option<Self> {
        let mut deframer = MessageDeframer::new();
        let mut flight = Self::new();

        let _ = deframer.read(&mut reader.rest());
        while let Some(msg) = deframer.pop_frame() {
            flight.push(msg);
            // continue to read the buffer
            let _ = deframer.read(&mut reader.rest());
        }

        Some(flight)
    }
}

impl From<MessageFlight> for OpaqueMessageFlight {
    fn from(value: MessageFlight) -> Self {
        Self {
            messages: value.messages.iter().map(|m| m.create_opaque()).collect(),
        }
    }
}

impl TryFrom<OpaqueMessageFlight> for MessageFlight {
    type Error = ();

    fn try_from(value: OpaqueMessageFlight) -> Result<Self, Self::Error> {
        let flight = Self {
            messages: value
                .messages
                .iter()
                .filter_map(|m| (*m).clone().try_into().ok())
                .collect(),
        };

        if flight.messages.is_empty() {
            Err(())
        } else {
            Ok(flight)
        }
    }
}

impl From<OpaqueMessage> for OpaqueMessageFlight {
    fn from(value: OpaqueMessage) -> Self {
        Self {
            messages: vec![value],
        }
    }
}

impl ProtocolMessage<TLSProtocolTypes, OpaqueMessage> for Message {
    fn create_opaque(&self) -> OpaqueMessage {
        msgs::message::PlainMessage::from(self.clone()).into_unencrypted_opaque()
    }

    fn debug(&self, info: &str) {
        debug_message_with_info(info, self);
    }
}

impl Extractable<TLSProtocolTypes> for Message {
    /// Extracts knowledge from a [`crate::tls::rustls::msgs::message::Message`].
    /// Only plaintext messages yield more knowledge than their binary payload.
    /// If a message is an ApplicationData (TLS 1.3) or an encrypted Heartbeet
    /// or Handhake message (TLS 1.2), then only the message itself and the
    /// binary payload is returned.
    fn extract_knowledge<'a>(
        &'a self,
        knowledges: &mut Vec<Knowledge<'a, TLSProtocolTypes>>,
        _: Option<TlsQueryMatcher>,
        source: &'a Source,
    ) -> Result<(), Error> {
        let matcher = match &self.payload {
            MessagePayload::Alert(_) => Some(TlsQueryMatcher::Alert),
            MessagePayload::Handshake(hs) => Some(TlsQueryMatcher::Handshake(Some(hs.typ))),
            MessagePayload::ChangeCipherSpec(_) => None,
            MessagePayload::ApplicationData(_) => Some(TlsQueryMatcher::ApplicationData),
            MessagePayload::Heartbeat(_) => Some(TlsQueryMatcher::Heartbeat),
            MessagePayload::TLS12EncryptedHandshake(_) => Some(TlsQueryMatcher::Handshake(None)),
        };

        knowledges.push(Knowledge {
            source,
            matcher,
            data: self,
        });

        self.payload
            .extract_knowledge(knowledges, matcher, source)?;
        Ok(())
    }
}

impl ProtocolMessageDeframer<TLSProtocolTypes> for MessageDeframer {
    type OpaqueProtocolMessage = OpaqueMessage;

    fn pop_frame(&mut self) -> Option<OpaqueMessage> {
        self.frames.pop_front()
    }

    fn read(&mut self, rd: &mut dyn std::io::Read) -> std::io::Result<usize> {
        self.read(rd)
    }
}

impl OpaqueProtocolMessage<TLSProtocolTypes> for OpaqueMessage {
    fn debug(&self, info: &str) {
        debug_opaque_message_with_info(info, self);
    }
}

atom_extract_knowledge!(TLSProtocolTypes, CertReqExtension);
atom_extract_knowledge!(TLSProtocolTypes, CertificateEntry);
atom_extract_knowledge!(TLSProtocolTypes, CertificateExtension);
atom_extract_knowledge!(TLSProtocolTypes, CertificatePayloadTLS13);
atom_extract_knowledge!(TLSProtocolTypes, CertificateRequestPayload);
atom_extract_knowledge!(TLSProtocolTypes, CertificateRequestPayloadTLS13);
atom_extract_knowledge!(TLSProtocolTypes, CertificateStatus);
atom_extract_knowledge!(TLSProtocolTypes, DigitallySignedStruct);
atom_extract_knowledge!(TLSProtocolTypes, HandshakeHash);
atom_extract_knowledge!(TLSProtocolTypes, HelloRetryExtension);
atom_extract_knowledge!(TLSProtocolTypes, NewSessionTicketExtension);
atom_extract_knowledge!(TLSProtocolTypes, NewSessionTicketPayloadTLS13);
atom_extract_knowledge!(TLSProtocolTypes, PresharedKeyIdentity);
atom_extract_knowledge!(TLSProtocolTypes, Random);
atom_extract_knowledge!(TLSProtocolTypes, ServerExtension);
atom_extract_knowledge!(TLSProtocolTypes, SessionID);
atom_extract_knowledge!(TLSProtocolTypes, u32);
atom_extract_knowledge!(TLSProtocolTypes, u64);
atom_extract_knowledge!(TLSProtocolTypes, u16);
atom_extract_knowledge!(TLSProtocolTypes, u8);
dummy_extract_knowledge!(TLSProtocolTypes, bool);
dummy_codec!(TLSProtocolTypes, UnknownExtension);
dummy_codec!(TLSProtocolTypes, ClientSessionTicket);

impl Matcher for msgs::enums::HandshakeType {
    fn matches(&self, matcher: &Self) -> bool {
        matcher == self
    }

    fn specificity(&self) -> u32 {
        1
    }
}

#[derive(Serialize, Deserialize, Copy, Clone, Debug, Eq, PartialEq, Hash, Comparable)]
pub enum AgentType {
    Server,
    Client,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, Eq, PartialEq, Hash, Comparable)]
pub enum TLSVersion {
    V1_3,
    V1_2,
    Both,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq, Hash)]
pub struct TLSDescriptorConfig {
    /// Whether the agent which holds this descriptor is a server.
    pub typ: AgentType,
    pub tls_version: TLSVersion,
    /// If agent is a server:
    ///   Make client auth. a requirement.
    /// If agent is a client:
    ///   Send a static certificate.
    ///
    /// Default: false
    pub client_authentication: bool,
    /// If agent is a server:
    ///   No effect, servers always send certificates in TLS.
    /// If agent is a client:
    ///   Make server auth. a requirement.
    ///
    /// Default: true
    pub server_authentication: bool,
    /// Whether we want to try to reuse a previous agent. This is needed for TLS session resumption
    /// as openssl agents rotate ticket keys if they are recreated.
    pub try_reuse: bool,
    /// List of available TLS ciphers - public for default() to be used
    /// Not supposed to be used outside the public methods to manage 1.2/1.3/both
    pub _cipher_string_tls13: String,
    pub _cipher_string_tls12: String,
    /// List of available TLS groups/curves
    /// If `None`, use the default PUT groups
    pub groups: Option<String>,
}

impl TLSDescriptorConfig {
    pub fn new_client(name: AgentName, tls_version: TLSVersion) -> AgentDescriptor<Self> {
        let protocol_config = Self {
            tls_version,
            typ: AgentType::Client,
            ..Self::default()
        };

        AgentDescriptor {
            name,
            protocol_config,
        }
    }

    pub fn new_server(name: AgentName, tls_version: TLSVersion) -> AgentDescriptor<Self> {
        let protocol_config = Self {
            tls_version,
            typ: AgentType::Server,
            ..Self::default()
        };

        AgentDescriptor {
            name,
            protocol_config,
        }
    }

    pub fn set_cipher_string_12(&mut self, cipher_string: String) {
        self._cipher_string_tls12 = cipher_string;
    }

    pub fn set_cipher_string_13(&mut self, cipher_string: String) {
        self._cipher_string_tls13 = cipher_string;
    }

    /// Sets both 1.2 and 1.3 cipher strings. If you need to specify two different cipher strings,
    /// use `set_cipher_string_12` and `set_cipher_string_13` separately.
    /// When using tlsversion::both both strings will be concatenated (and deduped).
    /// Be careful if you set only one of them when using both.
    pub fn set_cipher_string(&mut self, cipher_string: String) {
        self._cipher_string_tls13 = cipher_string.clone();
        self._cipher_string_tls12 = cipher_string;
    }

    fn concat_cipher_strings(&self) -> String {
        // concat the two cipher strings with 1.3 first and remove duplicates
        // Separate values between colon ":" to deduplicate
        let combined = format!(
            "{}:{}",
            self._cipher_string_tls13, self._cipher_string_tls12
        );
        let mut seen = std::collections::HashSet::new();
        combined
            .split(':')
            .filter(|s| !s.is_empty() && seen.insert(*s))
            .collect::<Vec<_>>()
            .join(":")
    }

    pub fn get_cipher_string_12(&self) -> String {
        match self.tls_version {
            TLSVersion::V1_2 | TLSVersion::V1_3 => self._cipher_string_tls12.clone(),
            TLSVersion::Both => self.concat_cipher_strings(),
        }
    }

    pub fn get_cipher_string_13(&self) -> String {
        match self.tls_version {
            TLSVersion::V1_2 | TLSVersion::V1_3 => self._cipher_string_tls13.clone(),
            TLSVersion::Both => self.concat_cipher_strings(),
        }
    }
}

impl ProtocolDescriptorConfig for TLSDescriptorConfig {
    fn is_reusable_with(&self, other: &Self) -> bool {
        self.typ == other.typ
            && self.tls_version == other.tls_version
            && self._cipher_string_tls13 == other._cipher_string_tls13
            && self._cipher_string_tls12 == other._cipher_string_tls12
            && self.groups == other.groups
    }
}

// Bulk strings are not well-supported across wolfssl versions (better in later ones)
// We therefore use a custom list of ciphers.
// In order:
//  - TLS 1.3 (same name for standard and openssl)
//  - TLS 1.2 (standard names)
//  - TLS 1.2 (openssl names) openssl set_cipher_list method does not parse standard format
// For the 1.2 lists we can make them follow one after the other because it either ignores a full
// list or accepts it and ignores the second even if it is able the parse it because it already
// exists.

// Excluded ciphers:
// - TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 / ECDHE-RSA-CHACHA20-POLY1305
// Exclusion with ! does not work for all implementations, we therefore have to make them invalid
// by adding some text to the cipher name.
const TLS_DEFAULT_CIPHER: &str = "\
TLS_AES_256_GCM_SHA384:\
TLS_CHACHA20_POLY1305_SHA256:\
TLS_AES_128_GCM_SHA256:\
\
\
TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:\
TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:\
TLS_DHE_DSS_WITH_AES_256_GCM_SHA384:\
TLS_DHE_RSA_WITH_AES_256_GCM_SHA384:\
TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:\
TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256_EXCLUDED:\
TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256:\
TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8:\
TLS_ECDHE_ECDSA_WITH_AES_256_CCM:\
TLS_DHE_RSA_WITH_AES_256_CCM_8:\
TLS_DHE_RSA_WITH_AES_256_CCM:\
TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384:\
TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384:\
TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384:\
TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384:\
TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:\
TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:\
TLS_DHE_DSS_WITH_AES_128_GCM_SHA256:\
TLS_DHE_RSA_WITH_AES_128_GCM_SHA256:\
TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8:\
TLS_ECDHE_ECDSA_WITH_AES_128_CCM:\
TLS_DHE_RSA_WITH_AES_128_CCM_8:\
TLS_DHE_RSA_WITH_AES_128_CCM:\
TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256:\
TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256:\
TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256:\
TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256:\
TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384:\
TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384:\
TLS_DHE_RSA_WITH_AES_256_CBC_SHA256:\
TLS_DHE_DSS_WITH_AES_256_CBC_SHA256:\
TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384:\
TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384:\
TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256:\
TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256:\
TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:\
TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:\
TLS_DHE_RSA_WITH_AES_128_CBC_SHA256:\
TLS_DHE_DSS_WITH_AES_128_CBC_SHA256:\
TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256:\
TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256:\
TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256:\
TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256:\
TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:\
TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:\
TLS_DHE_RSA_WITH_AES_256_CBC_SHA:\
TLS_DHE_DSS_WITH_AES_256_CBC_SHA:\
TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA:\
TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA:\
TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:\
TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:\
TLS_DHE_RSA_WITH_AES_128_CBC_SHA:\
TLS_DHE_PSK_WITH_AES_256_GCM_SHA384:\
TLS_DHE_PSK_WITH_AES_128_GCM_SHA256:\
TLS_DHE_PSK_WITH_AES_256_CBC_SHA384:\
TLS_DHE_PSK_WITH_AES_128_CBC_SHA256:\
TLS_DHE_DSS_WITH_AES_128_CBC_SHA:\
TLS_DHE_RSA_WITH_SEED_CBC_SHA:\
TLS_DHE_DSS_WITH_SEED_CBC_SHA:\
TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA:\
TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA:\
TLS_RSA_WITH_AES_256_GCM_SHA384:\
TLS_RSA_WITH_AES_256_CCM_8:\
TLS_RSA_WITH_AES_256_CCM:\
TLS_RSA_WITH_ARIA_256_GCM_SHA384:\
TLS_RSA_WITH_AES_128_GCM_SHA256:\
TLS_RSA_WITH_AES_128_CCM_8:\
TLS_RSA_WITH_AES_128_CCM:\
TLS_RSA_WITH_ARIA_128_GCM_SHA256:\
TLS_RSA_WITH_AES_256_CBC_SHA256:\
TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256:\
TLS_RSA_WITH_AES_128_CBC_SHA256:\
TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256:\
TLS_RSA_WITH_AES_256_CBC_SHA:\
TLS_RSA_WITH_CAMELLIA_256_CBC_SHA:\
TLS_RSA_WITH_AES_128_CBC_SHA:\
TLS_RSA_WITH_SEED_CBC_SHA:\
TLS_RSA_WITH_CAMELLIA_128_CBC_SHA:\
TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256:\
TLS_PSK_WITH_CHACHA20_POLY1305_SHA256:\
TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256:\
TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256:\
\
\
ECDHE-ECDSA-AES256-GCM-SHA384:\
ECDHE-RSA-AES256-GCM-SHA384:\
DHE-DSS-AES256-GCM-SHA384:\
DHE-RSA-AES256-GCM-SHA384:\
ECDHE-ECDSA-CHACHA20-POLY1305:\
ECDHE-RSA-CHACHA20-POLY1305-EXCLUDED:\
DHE-RSA-CHACHA20-POLY1305:\
ECDHE-ECDSA-AES256-CCM8:\
ECDHE-ECDSA-AES256-CCM:\
DHE-RSA-AES256-CCM8:\
DHE-RSA-AES256-CCM:\
ECDHE-ECDSA-ARIA256-GCM-SHA384:\
ECDHE-ARIA256-GCM-SHA384:\
DHE-DSS-ARIA256-GCM-SHA384:\
DHE-RSA-ARIA256-GCM-SHA384:\
ECDHE-ECDSA-AES128-GCM-SHA256:\
ECDHE-RSA-AES128-GCM-SHA256:\
DHE-DSS-AES128-GCM-SHA256:\
DHE-RSA-AES128-GCM-SHA256:\
ECDHE-ECDSA-AES128-CCM8:\
ECDHE-ECDSA-AES128-CCM:\
DHE-RSA-AES128-CCM8:\
DHE-RSA-AES128-CCM:\
ECDHE-ECDSA-ARIA128-GCM-SHA256:\
ECDHE-ARIA128-GCM-SHA256:\
DHE-DSS-ARIA128-GCM-SHA256:\
DHE-RSA-ARIA128-GCM-SHA256:\
ECDHE-ECDSA-AES256-SHA384:\
ECDHE-RSA-AES256-SHA384:\
DHE-RSA-AES256-SHA256:\
DHE-DSS-AES256-SHA256:\
ECDHE-ECDSA-CAMELLIA256-SHA384:\
ECDHE-RSA-CAMELLIA256-SHA384:\
DHE-RSA-CAMELLIA256-SHA256:\
DHE-DSS-CAMELLIA256-SHA256:\
ECDHE-ECDSA-AES128-SHA256:\
ECDHE-RSA-AES128-SHA256:\
DHE-RSA-AES128-SHA256:\
DHE-DSS-AES128-SHA256:\
ECDHE-ECDSA-CAMELLIA128-SHA256:\
ECDHE-RSA-CAMELLIA128-SHA256:\
DHE-RSA-CAMELLIA128-SHA256:\
DHE-DSS-CAMELLIA128-SHA256:\
ECDHE-ECDSA-AES256-SHA:\
ECDHE-RSA-AES256-SHA:\
DHE-RSA-AES256-SHA:\
DHE-DSS-AES256-SHA:\
DHE-RSA-CAMELLIA256-SHA:\
DHE-DSS-CAMELLIA256-SHA:\
ECDHE-ECDSA-AES128-SHA:\
ECDHE-RSA-AES128-SHA:\
DHE-RSA-AES128-SHA:\
DHE-PSK-AES256-GCM-SHA384:\
DHE-PSK-AES128-GCM-SHA256:\
DHE-PSK-AES256-CBC-SHA384:\
DHE-PSK-AES128-CBC-SHA256:\
DHE-DSS-AES128-SHA:\
DHE-RSA-SEED-SHA:\
DHE-DSS-SEED-SHA:\
DHE-RSA-CAMELLIA128-SHA:\
DHE-DSS-CAMELLIA128-SHA:\
AES256-GCM-SHA384:\
AES256-CCM8:\
AES256-CCM:\
ARIA256-GCM-SHA384:\
AES128-GCM-SHA256:\
AES128-CCM8:\
AES128-CCM:\
ARIA128-GCM-SHA256:\
AES256-SHA256:\
CAMELLIA256-SHA256:\
AES128-SHA256:\
CAMELLIA128-SHA256:\
AES256-SHA:\
CAMELLIA256-SHA:\
AES128-SHA:\
SEED-SHA:\
CAMELLIA128-SHA:\
ECDHE-PSK-AES128-CBC-SHA256:\
PSK-CHACHA20-POLY1305:\
ECDHE-PSK-CHACHA20-POLY1305:\
DHE-PSK-CHACHA20-POLY1305:\
";

impl Default for TLSDescriptorConfig {
    fn default() -> Self {
        Self {
            tls_version: TLSVersion::V1_3,
            client_authentication: false,
            server_authentication: true,
            try_reuse: false,
            typ: AgentType::Server,
            _cipher_string_tls13: TLS_DEFAULT_CIPHER.into(),
            _cipher_string_tls12: TLS_DEFAULT_CIPHER.into(),
            groups: None,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Hash, Serialize, Deserialize)]
pub struct TLSProtocolTypes;

impl ProtocolTypes for TLSProtocolTypes {
    type Matcher = TlsQueryMatcher;
    type PUTConfig = TLSDescriptorConfig;

    fn signature() -> &'static Signature<Self> {
        &TLS_SIGNATURE
    }

    fn differential_fuzzing_blacklist() -> Option<Vec<TypeId>> {
        None
    }

    fn differential_fuzzing_whitelist() -> Option<Vec<TypeId>> {
        Some(vec![TypeId::of::<MessagePayload>()])
    }

    fn differential_fuzzing_terms_to_eval(
        agents: &Vec<AgentDescriptor<Self::PUTConfig>>,
    ) -> Vec<puffin::algebra::Term<Self>> {
        let mut is_server = false;
        let mut server = AgentName::new();
        let mut is_client = false;
        let mut client = AgentName::new();

        for agent in agents {
            if agent.protocol_config.typ == AgentType::Server {
                is_server = true;
                server = agent.name;
            } else if agent.protocol_config.typ == AgentType::Client {
                is_client = true;
                client = agent.name;
            }
        }

        let mut terms = vec![];

        if is_server {
            terms.push(term! {
                fn_decrypt_handshake_flight_with_secret(
                ((server, 0)[Some(TlsQueryMatcher::ServerHelloFlight)]/MessageFlight),
                (fn_server_hello_transcript(((server, 0)))),
                fn_true,
                fn_seq_0,  // sequence 0
                (fn_finished_get_client_random(((server, 0)))),
                (fn_finished_get_cipher(((server, 0)))),
                (fn_finished_get_handshake_secret(((server, 2))))
            )
            });
        }

        if is_client {
            terms.push(term! {
                fn_decrypt_handshake_flight_with_secret(
                ((client, 0)[Some(TlsQueryMatcher::EncryptedFlight)]/MessageFlight),
                (fn_server_hello_transcript(((client, 0)))),
                fn_false,
                fn_seq_0,
                (fn_finished_get_client_random(((client, 0)))),
                (fn_finished_get_cipher(((client, 0)))),
                (fn_finished_get_handshake_secret(((client, 0))))
            )
            });
        }

        terms
    }

    fn differential_fuzzing_claims_blacklist() -> Option<Vec<TypeId>> {
        Some(vec![
            TypeId::of::<TranscriptCertificate>(),
            TypeId::of::<TranscriptClientFinished>(),
            TypeId::of::<TranscriptClientHello>(),
            TypeId::of::<TranscriptPartialClientHello>(),
            TypeId::of::<TranscriptServerFinished>(),
            TypeId::of::<TranscriptServerHello>(),
        ])
    }

    fn differential_fuzzing_uniformise_put_config(mut trace: Trace<Self>) -> Trace<Self> {
        for agent in trace.descriptors.iter_mut() {
            agent.protocol_config.set_cipher_string_12(String::from(
                "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            ));
            agent.protocol_config.set_cipher_string_13(String::from(
                "TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256",
            ));
            agent.protocol_config.groups = Some(String::from("P-256:P-384"));
        }

        for t in trace.prior_traces.iter_mut() {
            *t = Self::differential_fuzzing_uniformise_put_config(t.to_owned());
        }

        trace
    }

    fn differential_fuzzing_filter_diff(diff: &TraceDifference) -> bool {
        if let TraceDifference::Knowledges(puffin::differential::KnowledgeDiff::InnerDifference {
            index: _,
            type_name: _,
            diff,
            source: _,
        }) = diff
        {
            // OpenSSL sends an optional EllipticCurves extension when renegociating
            if diff.contains("EncryptedExtensionsChange([Removed(0, Unknown(UnknownExtensionDesc { typ: EllipticCurves }))])") {
                return false;
            }
        }
        true
    }
}

impl std::fmt::Display for TLSProtocolTypes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "")
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct TLSProtocolBehavior;

impl ProtocolBehavior for TLSProtocolBehavior {
    type Claim = TlsClaim;
    type OpaqueProtocolMessage = OpaqueMessage;
    type OpaqueProtocolMessageFlight = OpaqueMessageFlight;
    type ProtocolMessage = Message;
    type ProtocolMessageFlight = MessageFlight;
    type ProtocolTypes = TLSProtocolTypes;
    type SecurityViolationPolicy = TlsSecurityViolationPolicy;

    fn create_corpus(put: PutDescriptor) -> Vec<(Trace<Self::ProtocolTypes>, &'static str)> {
        crate::tls::seeds::create_corpus(
            tls_registry()
                .find_by_id(put.factory)
                .expect("missing PUT in TLS registry"),
        )
    }

    fn try_read_bytes(
        bitstring: &[u8],
        ty: TypeId,
    ) -> Result<Box<dyn EvaluatedTerm<Self::ProtocolTypes>>, Error> {
        try_read_bytes(bitstring, ty)
    }
}
