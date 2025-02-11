use core::any::TypeId;

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
use puffin::{atom_extract_knowledge, codec, dummy_extract_knowledge};
use serde::{Deserialize, Serialize};

use crate::claims::TlsClaim;
use crate::debug::{debug_message_with_info, debug_opaque_message_with_info};
use crate::put_registry::tls_registry;
use crate::query::TlsQueryMatcher;
use crate::tls::rustls::hash_hs::HandshakeHash;
use crate::tls::rustls::key::Certificate;
use crate::tls::rustls::msgs::alert::AlertMessagePayload;
use crate::tls::rustls::msgs::base::Payload;
use crate::tls::rustls::msgs::ccs::ChangeCipherSpecPayload;
use crate::tls::rustls::msgs::deframer::MessageDeframer;
use crate::tls::rustls::msgs::enums::{
    AlertDescription, AlertLevel, CipherSuite, Compression, HandshakeType, KeyUpdateRequest,
    NamedGroup, ProtocolVersion, SignatureScheme,
};
use crate::tls::rustls::msgs::handshake::{
    CertReqExtension, CertificateEntry, CertificateExtension, CertificatePayload,
    CertificatePayloadTLS13, CertificateRequestPayload, CertificateRequestPayloadTLS13,
    CertificateStatus, ClientExtension, ClientHelloPayload, DigitallySignedStruct,
    ECDHEServerKeyExchange, HandshakeMessagePayload, HandshakePayload, HelloRetryExtension,
    NewSessionTicketExtension, NewSessionTicketPayload, NewSessionTicketPayloadTLS13,
    PresharedKeyIdentity, Random, ServerExtension, ServerHelloPayload, ServerKeyExchangePayload,
    SessionID,
};
use crate::tls::rustls::msgs::heartbeat::HeartbeatPayload;
use crate::tls::rustls::msgs::message::{try_read_bytes, Message, MessagePayload, OpaqueMessage};
use crate::tls::rustls::msgs::{self};
use crate::tls::violation::TlsSecurityViolationPolicy;
use crate::tls::TLS_SIGNATURE;

#[derive(Debug, Clone)]
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

#[derive(Debug, Clone)]
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

impl Extractable<TLSProtocolTypes> for MessageFlight {
    fn extract_knowledge<'a>(
        &'a self,
        knowledges: &mut Vec<Knowledge<'a, TLSProtocolTypes>>,
        matcher: Option<TlsQueryMatcher>,
        source: &'a Source,
    ) -> Result<(), Error> {
        knowledges.push(Knowledge {
            source,
            matcher,
            data: self,
        });

        for msg in &self.messages {
            msg.extract_knowledge(knowledges, matcher, source)?;
        }
        Ok(())
    }
}

impl Extractable<TLSProtocolTypes> for OpaqueMessageFlight {
    fn extract_knowledge<'a>(
        &'a self,
        knowledges: &mut Vec<Knowledge<'a, TLSProtocolTypes>>,
        matcher: Option<TlsQueryMatcher>,
        source: &'a Source,
    ) -> Result<(), Error> {
        knowledges.push(Knowledge {
            source,
            matcher,
            data: self,
        });
        for msg in &self.messages {
            msg.extract_knowledge(knowledges, matcher, source)?;
        }
        Ok(())
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

impl Extractable<TLSProtocolTypes> for MessagePayload {
    fn extract_knowledge<'a>(
        &'a self,
        knowledges: &mut Vec<Knowledge<'a, TLSProtocolTypes>>,
        matcher: Option<TlsQueryMatcher>,
        source: &'a Source,
    ) -> Result<(), Error> {
        knowledges.push(Knowledge {
            source,
            matcher,
            data: self,
        });
        match &self {
            MessagePayload::Alert(alert) => alert.extract_knowledge(knowledges, matcher, source)?,
            MessagePayload::Handshake(hs) => hs.extract_knowledge(knowledges, matcher, source)?,
            MessagePayload::ChangeCipherSpec(ccs) => {
                ccs.extract_knowledge(knowledges, matcher, source)?
            }
            MessagePayload::ApplicationData(opaque) => {
                opaque.extract_knowledge(knowledges, matcher, source)?
            }
            MessagePayload::Heartbeat(h) => h.extract_knowledge(knowledges, matcher, source)?,
            MessagePayload::TLS12EncryptedHandshake(tls12encrypted) => {
                tls12encrypted.extract_knowledge(knowledges, matcher, source)?
            }
        }
        Ok(())
    }
}

impl Extractable<TLSProtocolTypes> for ChangeCipherSpecPayload {
    fn extract_knowledge<'a>(
        &'a self,
        knowledges: &mut Vec<Knowledge<'a, TLSProtocolTypes>>,
        matcher: Option<TlsQueryMatcher>,
        source: &'a Source,
    ) -> Result<(), Error> {
        knowledges.push(Knowledge {
            source,
            matcher,
            data: self,
        });

        Ok(())
    }
}

impl Extractable<TLSProtocolTypes> for HeartbeatPayload {
    fn extract_knowledge<'a>(
        &'a self,
        knowledges: &mut Vec<Knowledge<'a, TLSProtocolTypes>>,
        matcher: Option<TlsQueryMatcher>,
        source: &'a Source,
    ) -> Result<(), Error> {
        knowledges.push(Knowledge {
            source,
            matcher,
            data: self,
        });
        knowledges.push(Knowledge {
            source,
            matcher,
            data: &self.payload.0,
        });
        Ok(())
    }
}

impl Extractable<TLSProtocolTypes> for AlertMessagePayload {
    fn extract_knowledge<'a>(
        &'a self,
        knowledges: &mut Vec<Knowledge<'a, TLSProtocolTypes>>,
        matcher: Option<TlsQueryMatcher>,
        source: &'a Source,
    ) -> Result<(), Error> {
        knowledges.push(Knowledge {
            source,
            matcher,
            data: self,
        });
        knowledges.push(Knowledge {
            source,
            matcher,
            data: &self.description,
        });
        knowledges.push(Knowledge {
            source,
            matcher,
            data: &self.level,
        });
        Ok(())
    }
}

impl Extractable<TLSProtocolTypes> for HandshakeMessagePayload {
    fn extract_knowledge<'a>(
        &'a self,
        knowledges: &mut Vec<Knowledge<'a, TLSProtocolTypes>>,
        matcher: Option<TlsQueryMatcher>,
        source: &'a Source,
    ) -> Result<(), Error> {
        knowledges.push(Knowledge {
            source,
            matcher,
            data: self,
        });
        knowledges.push(Knowledge {
            source,
            matcher,
            data: &self.typ,
        });
        self.payload
            .extract_knowledge(knowledges, matcher, source)?;
        Ok(())
    }
}

impl Extractable<TLSProtocolTypes> for HandshakePayload {
    fn extract_knowledge<'a>(
        &'a self,
        knowledges: &mut Vec<Knowledge<'a, TLSProtocolTypes>>,
        matcher: Option<TlsQueryMatcher>,
        source: &'a Source,
    ) -> Result<(), Error> {
        knowledges.push(Knowledge {
            source,
            matcher,
            data: self,
        });
        match &self {
            HandshakePayload::HelloRequest | HandshakePayload::HelloRetryRequest(_) => {}
            HandshakePayload::ClientHello(ch) => {
                ch.extract_knowledge(knowledges, matcher, source)?;
            }
            HandshakePayload::ServerHello(sh) => {
                sh.extract_knowledge(knowledges, matcher, source)?;
            }
            HandshakePayload::Certificate(c) => {
                c.extract_knowledge(knowledges, matcher, source)?;
            }
            HandshakePayload::ServerKeyExchange(ske) => {
                ske.extract_knowledge(knowledges, matcher, source)?;
            }
            HandshakePayload::ServerHelloDone => {}
            HandshakePayload::ClientKeyExchange(cke) => {
                cke.extract_knowledge(knowledges, matcher, source)?;
            }
            HandshakePayload::NewSessionTicket(ticket) => {
                ticket.extract_knowledge(knowledges, matcher, source)?;
            }
            HandshakePayload::EncryptedExtensions(ext) => {
                ext.extract_knowledge(knowledges, matcher, source)?;
            }
            HandshakePayload::CertificateTLS13(c) => {
                c.extract_knowledge(knowledges, matcher, source)?;
            }
            HandshakePayload::CertificateRequest(c) => {
                c.extract_knowledge(knowledges, matcher, source)?;
            }
            HandshakePayload::CertificateRequestTLS13(c) => {
                c.extract_knowledge(knowledges, matcher, source)?;
            }
            HandshakePayload::CertificateVerify(c) => {
                c.extract_knowledge(knowledges, matcher, source)?;
            }
            HandshakePayload::EndOfEarlyData => {}
            HandshakePayload::NewSessionTicketTLS13(t) => {
                t.extract_knowledge(knowledges, matcher, source)?;
            }
            HandshakePayload::KeyUpdate(k) => {
                k.extract_knowledge(knowledges, matcher, source)?;
            }
            HandshakePayload::Finished(payload) => {
                payload.extract_knowledge(knowledges, matcher, source)?;
            }
            HandshakePayload::CertificateStatus(certificate_status) => {
                certificate_status.extract_knowledge(knowledges, matcher, source)?;
            }
            HandshakePayload::MessageHash(payload) => {
                payload.extract_knowledge(knowledges, matcher, source)?;
            }
            HandshakePayload::Unknown(payload) => {
                payload.extract_knowledge(knowledges, matcher, source)?;
            }
        }
        Ok(())
    }
}

impl Extractable<TLSProtocolTypes> for CertificatePayload {
    fn extract_knowledge<'a>(
        &'a self,
        knowledges: &mut Vec<Knowledge<'a, TLSProtocolTypes>>,
        matcher: Option<TlsQueryMatcher>,
        source: &'a Source,
    ) -> Result<(), Error> {
        knowledges.push(Knowledge {
            source,
            matcher,
            data: self,
        });
        knowledges.push(Knowledge {
            source,
            matcher,
            data: &self.0,
        });
        Ok(())
    }
}

impl Extractable<TLSProtocolTypes> for ServerKeyExchangePayload {
    fn extract_knowledge<'a>(
        &'a self,
        knowledges: &mut Vec<Knowledge<'a, TLSProtocolTypes>>,
        matcher: Option<TlsQueryMatcher>,
        source: &'a Source,
    ) -> Result<(), Error> {
        knowledges.push(Knowledge {
            source,
            matcher,
            data: self,
        });
        match self {
            ServerKeyExchangePayload::ECDHE(ecdhe) => {
                // this path wont be taken because we do not know the key exchange algorithm
                // in advance
                ecdhe.extract_knowledge(knowledges, matcher, source)?;
            }
            ServerKeyExchangePayload::Unknown(unknown) => {
                unknown.extract_knowledge(knowledges, matcher, source)?;
            }
        }
        Ok(())
    }
}

impl Extractable<TLSProtocolTypes> for ECDHEServerKeyExchange {
    fn extract_knowledge<'a>(
        &'a self,
        knowledges: &mut Vec<Knowledge<'a, TLSProtocolTypes>>,
        matcher: Option<TlsQueryMatcher>,
        source: &'a Source,
    ) -> Result<(), Error> {
        knowledges.push(Knowledge {
            source,
            matcher,
            data: self,
        });
        Ok(())
    }
}

impl Extractable<TLSProtocolTypes> for Payload {
    fn extract_knowledge<'a>(
        &'a self,
        knowledges: &mut Vec<Knowledge<'a, TLSProtocolTypes>>,
        matcher: Option<TlsQueryMatcher>,
        source: &'a Source,
    ) -> Result<(), Error> {
        knowledges.push(Knowledge {
            source,
            matcher,
            data: self,
        });
        knowledges.push(Knowledge {
            source,
            matcher,
            data: &self.0,
        });
        Ok(())
    }
}

impl Extractable<TLSProtocolTypes> for ClientHelloPayload {
    fn extract_knowledge<'a>(
        &'a self,
        knowledges: &mut Vec<Knowledge<'a, TLSProtocolTypes>>,
        matcher: Option<TlsQueryMatcher>,
        source: &'a Source,
    ) -> Result<(), Error> {
        knowledges.push(Knowledge {
            source,
            matcher,
            data: self,
        });
        knowledges.push(Knowledge {
            source,
            matcher,
            data: &self.random,
        });
        knowledges.push(Knowledge {
            source,
            matcher,
            data: &self.session_id,
        });
        knowledges.push(Knowledge {
            source,
            matcher,
            data: &self.client_version,
        });
        knowledges.push(Knowledge {
            source,
            matcher,
            data: &self.extensions,
        });
        knowledges.push(Knowledge {
            source,
            matcher,
            data: &self.compression_methods,
        });
        knowledges.push(Knowledge {
            source,
            matcher,
            data: &self.cipher_suites,
        });
        // we add both the Vec<T> and below the Wrapper(T) too
        knowledges.push(Knowledge {
            source,
            matcher,
            data: &self.extensions.0,
        });
        knowledges.push(Knowledge {
            source,
            matcher,
            data: &self.compression_methods.0,
        });
        knowledges.push(Knowledge {
            source,
            matcher,
            data: &self.cipher_suites.0,
        });
        knowledges.extend(self.extensions.0.iter().map(|extension| Knowledge {
            source,
            matcher,
            data: extension,
        }));
        knowledges.extend(
            self.compression_methods
                .0
                .iter()
                .map(|compression| Knowledge {
                    source,
                    matcher,
                    data: compression,
                }),
        );
        knowledges.extend(self.cipher_suites.0.iter().map(|cipher_suite| Knowledge {
            source,
            matcher,
            data: cipher_suite,
        }));
        Ok(())
    }
}

impl Extractable<TLSProtocolTypes> for NewSessionTicketPayload {
    fn extract_knowledge<'a>(
        &'a self,
        knowledges: &mut Vec<Knowledge<'a, TLSProtocolTypes>>,
        matcher: Option<TlsQueryMatcher>,
        source: &'a Source,
    ) -> Result<(), Error> {
        knowledges.push(Knowledge {
            source,
            matcher,
            data: self,
        });
        knowledges.push(Knowledge {
            source,
            matcher,
            data: &self.lifetime_hint,
        });
        knowledges.push(Knowledge {
            source,
            matcher,
            data: &self.ticket.0,
        });
        Ok(())
    }
}

impl Extractable<TLSProtocolTypes> for ServerHelloPayload {
    fn extract_knowledge<'a>(
        &'a self,
        knowledges: &mut Vec<Knowledge<'a, TLSProtocolTypes>>,
        matcher: Option<TlsQueryMatcher>,
        source: &'a Source,
    ) -> Result<(), Error> {
        knowledges.push(Knowledge {
            source,
            matcher,
            data: self,
        });
        knowledges.push(Knowledge {
            source,
            matcher,
            data: &self.random,
        });
        knowledges.push(Knowledge {
            source,
            matcher,
            data: &self.session_id,
        });
        knowledges.push(Knowledge {
            source,
            matcher,
            data: &self.cipher_suite,
        });
        knowledges.push(Knowledge {
            source,
            matcher,
            data: &self.compression_method,
        });
        knowledges.push(Knowledge {
            source,
            matcher,
            data: &self.legacy_version,
        });
        // we add both the Vec<T> and below the Wrapper(T) too
        knowledges.push(Knowledge {
            source,
            matcher,
            data: &self.extensions.0,
        });
        knowledges.push(Knowledge {
            source,
            matcher,
            data: &self.extensions,
        });
        knowledges.extend(self.extensions.0.iter().map(|extension| Knowledge {
            source,
            matcher,
            data: extension,
        }));
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

impl Extractable<TLSProtocolTypes> for OpaqueMessage {
    fn extract_knowledge<'a>(
        &'a self,
        knowledges: &mut Vec<Knowledge<'a, TLSProtocolTypes>>,
        matcher: Option<TlsQueryMatcher>,
        source: &'a Source,
    ) -> Result<(), Error> {
        knowledges.push(Knowledge {
            source,
            matcher,
            data: self,
        });
        Ok(())
    }
}

atom_extract_knowledge!(TLSProtocolTypes, AlertDescription);
atom_extract_knowledge!(TLSProtocolTypes, AlertLevel);
atom_extract_knowledge!(TLSProtocolTypes, CertReqExtension);
atom_extract_knowledge!(TLSProtocolTypes, Certificate);
atom_extract_knowledge!(TLSProtocolTypes, CertificateEntry);
atom_extract_knowledge!(TLSProtocolTypes, CertificateExtension);
atom_extract_knowledge!(TLSProtocolTypes, CertificatePayloadTLS13);
atom_extract_knowledge!(TLSProtocolTypes, CertificateRequestPayload);
atom_extract_knowledge!(TLSProtocolTypes, CertificateRequestPayloadTLS13);
atom_extract_knowledge!(TLSProtocolTypes, CertificateStatus);
atom_extract_knowledge!(TLSProtocolTypes, CipherSuite);
atom_extract_knowledge!(TLSProtocolTypes, ClientExtension);
atom_extract_knowledge!(TLSProtocolTypes, Compression);
atom_extract_knowledge!(TLSProtocolTypes, DigitallySignedStruct);
atom_extract_knowledge!(TLSProtocolTypes, HandshakeHash);
atom_extract_knowledge!(TLSProtocolTypes, HandshakeType);
atom_extract_knowledge!(TLSProtocolTypes, HelloRetryExtension);
atom_extract_knowledge!(TLSProtocolTypes, KeyUpdateRequest);
atom_extract_knowledge!(TLSProtocolTypes, NamedGroup);
atom_extract_knowledge!(TLSProtocolTypes, NewSessionTicketExtension);
atom_extract_knowledge!(TLSProtocolTypes, NewSessionTicketPayloadTLS13);
atom_extract_knowledge!(TLSProtocolTypes, PresharedKeyIdentity);
atom_extract_knowledge!(TLSProtocolTypes, ProtocolVersion);
atom_extract_knowledge!(TLSProtocolTypes, Random);
atom_extract_knowledge!(TLSProtocolTypes, ServerExtension);
atom_extract_knowledge!(TLSProtocolTypes, SessionID);
atom_extract_knowledge!(TLSProtocolTypes, SignatureScheme);
atom_extract_knowledge!(TLSProtocolTypes, u32);
atom_extract_knowledge!(TLSProtocolTypes, u64);
atom_extract_knowledge!(TLSProtocolTypes, u8);
dummy_extract_knowledge!(TLSProtocolTypes, bool);

impl<T: EvaluatedTerm<TLSProtocolTypes> + Clone + codec::Codec + 'static>
    Extractable<TLSProtocolTypes> for Vec<T>
where
    Vec<T>: codec::Codec,
{
    fn extract_knowledge<'a>(
        &'a self,
        knowledges: &mut Vec<Knowledge<'a, TLSProtocolTypes>>,
        matcher: Option<<TLSProtocolTypes as ProtocolTypes>::Matcher>,
        source: &'a Source,
    ) -> Result<(), Error> {
        knowledges.push(Knowledge {
            source,
            matcher,
            data: self,
        });

        for k in self {
            k.extract_knowledge(knowledges, matcher, source)?;
        }
        Ok(())
    }
}

impl<T: Extractable<TLSProtocolTypes> + Clone + 'static> Extractable<TLSProtocolTypes> for Option<T>
where
    Option<T>: codec::Codec,
{
    fn extract_knowledge<'a>(
        &'a self,
        knowledges: &mut Vec<Knowledge<'a, TLSProtocolTypes>>,
        matcher: Option<<TLSProtocolTypes as ProtocolTypes>::Matcher>,
        source: &'a Source,
    ) -> Result<(), Error> {
        knowledges.push(Knowledge {
            source,
            matcher,
            data: self,
        });

        match self {
            Some(x) => x.extract_knowledge(knowledges, matcher, source)?,
            None => (),
        }
        Ok(())
    }
}

impl Matcher for msgs::enums::HandshakeType {
    fn matches(&self, matcher: &Self) -> bool {
        matcher == self
    }

    fn specificity(&self) -> u32 {
        1
    }
}

#[derive(Serialize, Deserialize, Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum AgentType {
    Server,
    Client,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, Eq, PartialEq, Hash)]
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
    pub cipher_string: String,
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
            && self.cipher_string == other.cipher_string
    }
}

impl Default for TLSDescriptorConfig {
    fn default() -> Self {
        Self {
            tls_version: TLSVersion::V1_3,
            client_authentication: false,
            server_authentication: true,
            try_reuse: false,
            typ: AgentType::Server,
            cipher_string: String::from("ALL:!EXPORT:!LOW:!aNULL:!eNULL:!SSLv2"),
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
