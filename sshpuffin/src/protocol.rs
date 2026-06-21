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
        use puffin::differential::TraceDifference;

        // Cross-implementation (libssh vs wolfSSH) comparison. Security in the DY
        // model lives in *properties over claims*, not in raw bytes or control
        // flow, so we compare security state and drop the implementation-defined
        // transport transcript and execution path.
        match diff {
            // The security-violation hook firing on one PUT and not the other
            // (matching-conversation / Terrapin-class, null cipher, impersonation,
            // auth-bypass) is always meaningful.
            TraceDifference::SecurityClaim(_) => true,

            // Claims carry the negotiated security state (kex/cipher/MAC → downgrade
            // & null-cipher; auth method + verified key fingerprint → impersonation
            // & auth-bypass). Algorithm names are canonicalized to SSH wire form at
            // construction (SshClaimInner::canonicalize) and the trace-position
            // `step` field is excluded from comparison, so a surviving claim diff is
            // a *real* security-state divergence — including the presence/absence
            // case (one PUT reaches handshake/auth completion and emits a claim
            // where the other does not), which is how an asymmetric *security-state*
            // acceptance still surfaces here even though Status is dropped below.
            TraceDifference::Claims(_) => true,

            // Status diffs are dropped. Triaging a cross-vendor campaign showed
            // ~96–98% of objectives were Status diffs and every one was benign:
            // the two stacks reject the same malformed/mutated trace at different
            // steps or with different errors (parser & banner strictness differs —
            // e.g. libssh rejects a banner wolfSSH accepts), one continues while the
            // other trips wolfSSH's consecutive-failure guard ("would overflow"),
            // or one side raises a DY term-evaluation error because a recipe cannot
            // bind once the flows diverge. None are security properties. Memory
            // safety is unaffected: a crash aborts the PUT and is recorded as a
            // crash objective by the fuzzer, not via this status comparison. And an
            // asymmetric *security-state* outcome (one side actually completes the
            // handshake/auth) still surfaces as a Claim presence/absence diff above.
            TraceDifference::Status(_) => false,

            // Knowledge diffs are dropped. Two independent SSH stacks legitimately
            // produce different — but equally valid — wire transcripts: the
            // handshake layer differs (KEXINIT algorithm-preference order, host-key
            // blobs, ephemeral keys, banners), and so does the post-NewKeys layer
            // (e.g. wolfSSH sends ServiceAccept where libssh pipelines straight to
            // UserAuthSuccess, and the two emit a different number/order of replies).
            // These are implementation fingerprints, not security properties, and
            // comparing them positionally cross-vendor yields systematic, benign
            // diffs that would swamp triage. Any security-relevant fact they could
            // reveal (a downgrade, a plaintext leak, an unexpected auth result) is
            // already captured as a claim or a security violation above; encode new
            // ones there rather than re-enabling raw transcript comparison.
            TraceDifference::Knowledges(_) => false,
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
