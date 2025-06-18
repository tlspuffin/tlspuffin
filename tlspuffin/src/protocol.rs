use std::any::TypeId;

use comparable::Comparable;
use extractable_macro::Extractable;
use puffin::agent::{AgentDescriptor, AgentName, ProtocolDescriptorConfig};
use puffin::algebra::signature::Signature;
use puffin::algebra::Matcher;
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
    fn_decrypt_handshake_flight_with_secret, fn_finished_get_cipher, fn_finished_get_client_random,
    fn_finished_get_handshake_secret, fn_seq_0, fn_server_hello_transcript, fn_true,
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

#[derive(Debug, Clone, Extractable, Comparable)]
#[extractable(TLSProtocolTypes)]
pub struct MessageFlight {
    pub messages: Vec<Message>,
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
    /// List of available TLS ciphers
    pub cipher_string_tls13: String,
    pub cipher_string_tls12: String,
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
}

impl ProtocolDescriptorConfig for TLSDescriptorConfig {
    fn is_reusable_with(&self, other: &Self) -> bool {
        self.typ == other.typ
            && self.tls_version == other.tls_version
            && self.cipher_string_tls13 == other.cipher_string_tls13
            && self.cipher_string_tls12 == other.cipher_string_tls12
            && self.groups == other.groups
    }
}

const TLS_DEFAULT_CIPHER: &str = "ALL:!EXPORT:!LOW:!aNULL:!eNULL:!SSLv2";

impl Default for TLSDescriptorConfig {
    fn default() -> Self {
        Self {
            tls_version: TLSVersion::V1_3,
            client_authentication: false,
            server_authentication: true,
            try_reuse: false,
            typ: AgentType::Server,
            cipher_string_tls13: TLS_DEFAULT_CIPHER.into(),
            cipher_string_tls12: TLS_DEFAULT_CIPHER.into(),
            groups: None,
        }
    }
}

#[derive(Clone, Debug, Hash, Serialize, Deserialize)]
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

        for agent in agents {
            if agent.protocol_config.typ == AgentType::Server {
                is_server = true;
                server = agent.name;
            }
        }

        let mut terms = vec![];

        if is_server {
            terms.push(term! {
                fn_decrypt_handshake_flight_with_secret(
                ((server, 0)/MessageFlight), // The first flight of messages sent by the server
                (fn_server_hello_transcript(((server, 0)))),
                fn_true,
                fn_seq_0,  // sequence 0
                (fn_finished_get_client_random(((server, 0)))),
                (fn_finished_get_cipher(((server, 0)))),
                (fn_finished_get_handshake_secret(((server, 2))))
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

    fn differential_fuzzing_uniformise_put_config(
        agent: AgentDescriptor<Self::PUTConfig>,
    ) -> AgentDescriptor<Self::PUTConfig> {
        let mut new = agent.clone();
        new.protocol_config.cipher_string_tls12 = String::from(
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        );
        new.protocol_config.cipher_string_tls13 = String::from(
            "TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256",
        );
        new.protocol_config.groups = Some(String::from("P-256:P-384"));
        new
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
