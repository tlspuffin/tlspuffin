use std::any::TypeId;

use comparable::Comparable;
use extractable_macro::Extractable;
use puffin::agent::{AgentDescriptor, ProtocolDescriptorConfig};
use puffin::algebra::signature::Signature;
use puffin::codec;
use puffin::codec::{Codec, Reader, VecCodecWoSize};
use puffin::error::Error;
use puffin::protocol::{
    EvaluatedTerm, OpaqueProtocolMessageFlight, ProtocolBehavior, ProtocolMessage,
    ProtocolMessageDeframer, ProtocolMessageFlight, ProtocolTypes,
};
use puffin::put::PutDescriptor;
use puffin::trace::Trace;
use serde::{Deserialize, Serialize};

use crate::claim::SshClaim;
use crate::put_registry::ssh_registry;
use crate::query::SshQueryMatcher;
use crate::ssh::deframe::SshMessageDeframer;
use crate::ssh::message::{RawSshMessage, SshMessage};
use crate::ssh::SSH_SIGNATURE;
use crate::violation::SshSecurityViolationPolicy;

#[derive(Debug, Clone, Extractable, Comparable)]
#[extractable(SshProtocolTypes)]
pub struct SshMessageFlight {
    pub messages: Vec<SshMessage>,
}

impl VecCodecWoSize for SshMessage {}
impl codec::Codec for SshMessageFlight {
    fn encode(&self, bytes: &mut Vec<u8>) {
        for msg in &self.messages {
            msg.encode(bytes);
        }
    }

    fn read(reader: &mut codec::Reader) -> Option<Self> {
        let mut flight = Vec::new();

        while let Some(msg) = SshMessage::read(reader) {
            flight.push(msg);
        }
        Some(SshMessageFlight { messages: flight })
    }
}

impl ProtocolMessageFlight<SshProtocolTypes, SshMessage, RawSshMessage, RawSshMessageFlight>
    for SshMessageFlight
{
    fn new() -> Self {
        Self { messages: vec![] }
    }

    fn push(&mut self, msg: SshMessage) {
        self.messages.push(msg);
    }

    fn debug(&self, info: &str) {
        log::debug!("{}: {:?}", info, self);
    }
}

impl From<SshMessage> for SshMessageFlight {
    fn from(value: SshMessage) -> Self {
        Self {
            messages: vec![value],
        }
    }
}

#[derive(Debug, Clone, Extractable, Comparable)]
#[extractable(SshProtocolTypes)]
pub struct RawSshMessageFlight {
    pub messages: Vec<RawSshMessage>,
}

impl VecCodecWoSize for RawSshMessage {}

impl OpaqueProtocolMessageFlight<SshProtocolTypes, RawSshMessage> for RawSshMessageFlight {
    fn new() -> Self {
        Self { messages: vec![] }
    }

    fn push(&mut self, msg: RawSshMessage) {
        self.messages.push(msg);
    }

    fn debug(&self, info: &str) {
        log::debug!("{}: {:?}", info, self);
    }
}

impl TryFrom<RawSshMessageFlight> for SshMessageFlight {
    type Error = ();

    fn try_from(value: RawSshMessageFlight) -> Result<Self, Self::Error> {
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

impl Codec for RawSshMessageFlight {
    fn encode(&self, bytes: &mut Vec<u8>) {
        for msg in &self.messages {
            msg.encode(bytes);
        }
    }

    fn read(reader: &mut Reader) -> Option<Self> {
        let mut deframer = SshMessageDeframer::new();
        let mut flight = Self::new();

        let _ = deframer.read(&mut reader.rest());
        while let Some(msg) = deframer.pop_frame() {
            flight.push(msg);
        }

        Some(flight)
    }
}

impl From<SshMessageFlight> for RawSshMessageFlight {
    fn from(value: SshMessageFlight) -> Self {
        Self {
            messages: value.messages.iter().map(|m| m.create_opaque()).collect(),
        }
    }
}

impl From<RawSshMessage> for RawSshMessageFlight {
    fn from(value: RawSshMessage) -> Self {
        Self {
            messages: vec![value],
        }
    }
}

#[derive(Serialize, Deserialize, Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum AgentType {
    Server,
    Client,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq, Hash)]
pub struct SshDescriptorConfig {
    /// Whether the agent which holds this descriptor is a server.
    pub typ: AgentType,
    /// Whether we want to try to reuse a previous agent.
    pub try_reuse: bool,
}

impl ProtocolDescriptorConfig for SshDescriptorConfig {
    fn is_reusable_with(&self, other: &Self) -> bool {
        self.typ == other.typ
    }
}

impl Default for SshDescriptorConfig {
    fn default() -> Self {
        Self {
            typ: AgentType::Server,
            try_reuse: false,
        }
    }
}

#[derive(Clone, Debug, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct SshProtocolTypes;
impl ProtocolTypes for SshProtocolTypes {
    type Matcher = SshQueryMatcher;
    type PUTConfig = SshDescriptorConfig;

    fn signature() -> &'static Signature<Self> {
        &SSH_SIGNATURE
    }

    fn differential_fuzzing_whitelist() -> Option<Vec<std::any::TypeId>> {
        use crate::ssh::message::{KexEcdhReplyMessage, KexInitMessage, SshMessage};
        // Only compare structured, semantically-meaningful messages. Opaque
        // types (RawSshMessage, OnWireData, BinaryPacket, Vec<u8>, raw flights,
        // banner String) are excluded: they carry ciphertext / framing /
        // version strings that legitimately differ across implementations and
        // would otherwise drown real divergences in noise. Random/derived
        // sub-fields within the kept types are dropped via #[comparable_ignore]
        // (e.g. KexInit cookie, ECDH ephemeral key + signature).
        Some(vec![
            TypeId::of::<SshMessage>(),
            TypeId::of::<SshMessageFlight>(),
            TypeId::of::<KexInitMessage>(),
            TypeId::of::<KexEcdhReplyMessage>(),
        ])
        // SshMessageFlight is defined in this module (see above).
    }

    fn differential_fuzzing_terms_to_eval(
        agents: &Vec<AgentDescriptor<Self::PUTConfig>>,
    ) -> Vec<puffin::algebra::Term<Self>> {
        // For every libssh server agent, emit recipes that decrypt its
        // post-NewKeys encrypted output into structured SshMessages so the two
        // PUTs' encrypted record-layer responses can be compared. Recipes whose
        // queries / sequence numbers don't match a given PUT's run evaluate to
        // an error and are silently skipped by the differential engine.
        let mut terms = vec![];
        for agent in agents {
            if agent.protocol_config.typ == AgentType::Server {
                // Emit both the ChaCha20-Poly1305 and AES-256-GCM recipe sets;
                // those that do not match the cipher actually negotiated in a
                // given run fail their AEAD tag and are silently skipped.
                terms.extend(crate::ssh::seeds::server_decryption_recipes(agent.name));
                terms.extend(crate::ssh::seeds::server_decryption_recipes_aesgcm(
                    agent.name,
                ));
            }
        }
        terms
    }

    fn differential_fuzzing_claims_blacklist() -> Option<Vec<TypeId>> {
        None
    }

    fn differential_fuzzing_uniformise_put_config(trace: Trace<Self>) -> Trace<Self> {
        trace
    }

    fn differential_fuzzing_filter_diff(diff: &puffin::differential::TraceDifference) -> bool {
        use puffin::differential::{KnowledgeDiff, TraceDifference};
        use puffin::trace::Source;

        // Cross-implementation (libssh vs wolfSSH) comparison: keep only genuine
        // behavioral divergences and drop the inherent, benign cross-vendor noise.
        match diff {
            // Execution-status and security-violation divergences are always
            // meaningful.
            TraceDifference::Status(_) | TraceDifference::SecurityClaim(_) => true,

            // Claim diffs are kept: algorithm names are canonicalized to SSH wire
            // form at claim construction (SshClaimInner::canonicalize), so the
            // benign cross-vendor naming noise (libssh "aes256-gcm@openssh.com" /
            // "curve25519-sha256" vs wolfSSH "AES-256 GCM" / "ECDH") is already
            // gone. A surviving claim diff therefore signals a *real* negotiation
            // divergence — e.g. a downgrade — which is exactly what we want.
            TraceDifference::Claims(_) => true,

            // Knowledge diffs: the handshake layer (agent-sourced KEXINIT offer
            // lists, host key, ephemeral, banners/flights) inherently differs
            // between independent implementations. Keep only the decryption-recipe
            // results (Source::Label) — the actual decrypted post-NewKeys protocol
            // behavior, which is the meaningful cross-vendor signal.
            TraceDifference::Knowledges(k) => match k {
                KnowledgeDiff::InnerDifference { source, .. } => {
                    matches!(source, Source::Label(_))
                }
                KnowledgeDiff::DifferentTypes {
                    first_source,
                    second_source,
                    ..
                } => {
                    matches!(first_source, Source::Label(_))
                        || matches!(second_source, Source::Label(_))
                }
            },
        }
    }
}

impl std::fmt::Display for SshProtocolTypes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "")
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct SshProtocolBehavior {}

impl ProtocolBehavior for SshProtocolBehavior {
    type Claim = SshClaim;
    type OpaqueProtocolMessage = RawSshMessage;
    type OpaqueProtocolMessageFlight = RawSshMessageFlight;
    type ProtocolMessage = SshMessage;
    type ProtocolMessageFlight = SshMessageFlight;
    type ProtocolTypes = SshProtocolTypes;
    type SecurityViolationPolicy = SshSecurityViolationPolicy;

    fn create_corpus(put: PutDescriptor) -> Vec<(Trace<Self::ProtocolTypes>, &'static str)> {
        crate::ssh::seeds::create_corpus(
            ssh_registry()
                .find_by_id(put.factory)
                .expect("missing PUT in SSH registry"),
        )
    }

    fn try_read_bytes(
        bitstring: &[u8],
        ty: TypeId,
    ) -> Result<Box<dyn EvaluatedTerm<Self::ProtocolTypes>>, Error> {
        crate::ssh::message::try_read_bytes(bitstring, ty)
    }

    fn check_trace_security_violation(
        trace: &Trace<Self::ProtocolTypes>,
        ctx: &puffin::trace::TraceContext<Self>,
    ) -> Option<&'static str> {
        crate::violation::matching_conversation_violation(trace, ctx)
    }
}
