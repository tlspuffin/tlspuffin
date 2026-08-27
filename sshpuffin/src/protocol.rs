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
    /// Uniformised algorithm lists (comma-separated SSH wire names). `None`
    /// leaves the PUT default; `differential_fuzzing_uniformise_put_config` sets
    /// these to a common subset so both PUTs advertise the same KEXINIT and their
    /// static per-implementation capability no longer shows up as a diff.
    /// `#[serde(default)]` keeps older serialized traces (without these fields)
    /// loadable — they deserialize to `None` and are set at execution time.
    #[serde(default)]
    pub kex: Option<String>,
    #[serde(default)]
    pub ciphers: Option<String>,
    #[serde(default)]
    pub macs: Option<String>,
    #[serde(default)]
    pub hostkey_algos: Option<String>,
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
            kex: None,
            ciphers: None,
            macs: None,
            hostkey_algos: None,
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
        use crate::ssh::message::SshMessage;
        // Compare exactly ONE structured level: the individual `SshMessage`.
        // `SshMessage` already recurses into its variants (KexInit, KexEcdhReply,
        // …), so listing those leaves — or the `SshMessageFlight` wrapper —
        // separately only re-reports the same divergence at 3 granularities.
        // Opaque types (RawSshMessage, OnWireData, BinaryPacket, Vec<u8>, banner
        // String) stay excluded: they are ciphertext / framing / version strings
        // with no comparable fields. All within-message noise is handled at the
        // field level via #[comparable_ignore] / #[comparable_synthetic].
        Some(vec![TypeId::of::<SshMessage>()])
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

    fn differential_fuzzing_uniformise_put_config(mut trace: Trace<Self>) -> Trace<Self> {
        // Force every PUT to advertise the SAME negotiable algorithms, so the
        // static per-implementation capability set (libssh offers CTR ciphers,
        // group18, kex-strict, ext-info; wolfSSH does not) no longer surfaces as
        // a KEXINIT diff. The set is the common subset both stacks support AND
        // the differential seeds negotiate (AES-GCM / ecdh-nistp256 / ssh-rsa).
        // Maximal common subset of the two PUTs' DEFAULT advertised sets
        // (measured: libssh 0.11.4 vs wolfSSH). Widest set both stacks support,
        // so the fuzzer keeps full negotiation room while both advertise the
        // same KEXINIT. (Residual, not settable via these APIs: the kex-strict-s
        // / ext-info-s signaling markers each stack auto-appends, and libssh's
        // zlib compression offer.)
        for agent in trace.descriptors.iter_mut() {
            agent.protocol_config.kex = Some(
                "curve25519-sha256,curve25519-sha256@libssh.org,\
                 ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,\
                 diffie-hellman-group16-sha512,diffie-hellman-group-exchange-sha256,\
                 diffie-hellman-group14-sha256"
                    .into(),
            );
            agent.protocol_config.ciphers =
                Some("aes256-gcm@openssh.com,aes128-gcm@openssh.com".into());
            agent.protocol_config.macs = Some("hmac-sha2-256,hmac-sha2-512".into());
            agent.protocol_config.hostkey_algos = Some("rsa-sha2-512,rsa-sha2-256".into());
        }
        for t in trace.prior_traces.iter_mut() {
            *t = Self::differential_fuzzing_uniformise_put_config(t.to_owned());
        }
        trace
    }

    fn differential_fuzzing_filter_diff(diff: &puffin::differential::TraceDifference) -> bool {
        use puffin::differential::{KnowledgeDiff, TraceDifference};

        // decrypt-only RESEARCH mode (a scope selector, not a denoiser, off by
        // default): keep ONLY differences produced by the decryption recipes
        // (Source::Label("Decryption")), dropping status / claim / on-wire
        // transcript diffs so a campaign's objectives are exclusively
        // decrypted-content divergences.
        #[cfg(feature = "decrypt-only")]
        {
            use puffin::trace::Source;
            let is_decryption =
                |s: &Source| matches!(s, Source::Label(Some(x)) if x == "Decryption");
            let decryption_sourced = match diff {
                TraceDifference::Knowledges(KnowledgeDiff::InnerDifference { source, .. }) => {
                    is_decryption(source)
                }
                TraceDifference::Knowledges(KnowledgeDiff::DifferentTypes {
                    first_source,
                    second_source,
                    ..
                }) => is_decryption(first_source) || is_decryption(second_source),
                _ => false,
            };
            if !decryption_sourced {
                return false;
            }
            // fall through to the benign-framing filtering below
        }

        // Denoising lives in the data model (whitelist / comparable_ignore /
        // comparable_synthetic), uniformise_put_config, and — for the decrypted
        // streams — FLIGHT DECRYPTION + SEMANTIC ALIGNMENT (messages compared by
        // variant, with each socket write peeled packet-by-packet). This filter
        // is otherwise FULLY FAIL-CLOSED: content differences of any kind, and
        // presence differences of every kind, are KEPT as objectives — we do NOT
        // broadly whitelist, to avoid masking a real bug. Benign classification
        // of the surviving presence differences (control-plane framing / reply
        // timing) is done downstream as an explicit, precise BENIGN triage bucket
        // (mirroring the TLS triaging pipeline), not by dropping them here.
        //
        // The SOLE exception is the MINIMAL set needed to keep the differential
        // SEEDS at 0 differences: on the clean matching-conversation seeds the two
        // stacks packetize the channel-setup replies differently, so exactly
        // ChannelOpenConfirmation (libssh side) and ChannelSuccess (wolfSSH side)
        // appear on one decrypted stream only. Investigation (transport-level
        // instrumentation of both stacks) confirmed this is benign framing/reply
        // timing, not a protocol/security divergence. We drop ONLY those two exact
        // presence shapes; every other presence/content difference is kept.
        const SEED_BENIGN_PRESENCE: &[&str] = &[
            "SshMessage::ChannelOpenConfirmation",
            "SshMessage::ChannelSuccess",
        ];

        match diff {
            TraceDifference::Knowledges(KnowledgeDiff::DifferentTypes {
                first_type,
                second_type,
                ..
            }) => {
                let seed_benign_framing = (second_type == "()"
                    && SEED_BENIGN_PRESENCE.contains(&first_type.as_str()))
                    || (first_type == "()" && SEED_BENIGN_PRESENCE.contains(&second_type.as_str()));
                !seed_benign_framing
            }
            _ => true,
        }
    }

    // NOTE: we deliberately do NOT override differential_fuzzing_always_compare_knowledge
    // (default false). In decrypt-only mode the short-circuit is PROTECTIVE: when
    // the two PUTs disagree on execution status (e.g. a term-evaluation error or
    // one PUT stopping early), their decrypted streams are from divergent runs and
    // any presence/content difference between them is an execution-divergence
    // artifact, not a clean library divergence. Keeping the short-circuit means the
    // decryption comparison runs ONLY when both PUTs executed identically far, and
    // filter_diff (applied to all diffs) then drops the status diff itself — so a
    // decrypt-only objective is exactly "both PUTs ran cleanly AND their decrypted
    // output differs". That is the sound decryption-differential signal.

    fn differential_fuzzing_alignment_key(
        data: &dyn puffin::protocol::EvaluatedTerm<Self>,
    ) -> String {
        use crate::ssh::message::SshMessage;
        // Align decrypted/on-wire messages by SSH message VARIANT (not just the
        // Rust type `SshMessage`), so like-with-like are compared across the two
        // implementations regardless of how each packetizes its replies.
        if let Some(msg) = data.as_any().downcast_ref::<SshMessage>() {
            // The derived Debug head is the variant name ("ServiceAccept(..)" /
            // "NewKeys"); take the leading identifier.
            let dbg = format!("{msg:?}");
            let name = dbg
                .split(|c: char| c == '(' || c == ' ' || c == '{')
                .next()
                .unwrap_or("")
                .trim();
            format!("SshMessage::{name}")
        } else {
            data.type_name().to_string()
        }
    }
}

impl std::fmt::Display for SshProtocolTypes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "")
    }
}

#[cfg(test)]
mod filter_diff_tests {
    use puffin::differential::{StatusDiff, TraceDifference};
    use puffin::protocol::ProtocolTypes;

    use super::SshProtocolTypes;

    fn status(first: &str, second: &str) -> TraceDifference {
        TraceDifference::Status(StatusDiff {
            first_executed_steps: 0,
            first_status: first.to_string(),
            second_executed_steps: 0,
            second_status: second.to_string(),
            total_step: 9,
        })
    }

    fn keep(diff: &TraceDifference) -> bool {
        SshProtocolTypes::differential_fuzzing_filter_diff(diff)
    }

    // NOTE: an earlier `status_diff_kept_only_on_acceptance_disagreement` test
    // asserted that a both-reject Status diff is DROPPED. The differential is now
    // deliberately fail-closed — every Status diff is kept (both-reject noise is
    // filtered downstream, in decrypt-only mode or the triaging BENIGN buckets,
    // rather than in filter_diff) — so that assertion tested removed behaviour and
    // was deleted. The important property (acceptance divergences are always kept)
    // is covered by `cross_vendor_acceptance_divergences_are_all_kept` below.

    /// Regression guard locking in the conservative keep-behavior against the
    /// ACTUAL diff classes triaged from a libssh-vs-wolfSSH cross-vendor campaign
    /// (2026-06-28). The filter must NEVER be loosened to drop any of these:
    /// each is a genuine cross-vendor acceptance divergence (a stack accepts an
    /// input the other refuses) — the precise differential signal that finds
    /// bugs (e.g. wolfSSH accepting an oversized banner / unusable version that
    /// libssh rejects, or libssh accepting what wolfSSH refuses). A false
    /// negative here means a missed bug, so when in doubt we KEEP.
    #[test]
    fn cross_vendor_acceptance_divergences_are_all_kept() {
        // libssh rejects, wolfSSH accepts — wolfSSH over-permissiveness.
        assert!(keep(&status(
            "Receiving banner: too large banner",
            "Success"
        )));
        assert!(keep(&status(
            "No version of SSH protocol usable (...)",
            "Success"
        )));
        // libssh's own socket-level error on the input vs wolfSSH success. This
        // is libssh's behaviour on that trace (its own error string), NOT a
        // harness/term/IO artifact (those never reach the filter — the engine
        // emits a StatusDiff only when a side is Error::Put, and both-non-Success
        // pairs are dropped above). We deliberately do NOT string-match and drop
        // it: that would be the "too loose" condition that risks hiding a real
        // libssh robustness bug.
        assert!(keep(&status("Socket error: File exists", "Success")));
        // libssh accepts, wolfSSH rejects — libssh leniency.
        assert!(keep(&status("Success", "Unknown error code")));
    }

    /// Completion-claim presence/absence (one PUT reaches the handshake/auth
    /// completion claim, the other does not) is an acceptance divergence and
    /// MUST be kept — it is how an asymmetric *security-state* acceptance
    /// surfaces even though raw Status is filtered for both-reject.
    #[test]
    fn claim_presence_difference_is_kept() {
        use puffin::differential::ClaimDiff;

        let presence = TraceDifference::Claims(ClaimDiff::DifferentTypes {
            agent: 1,
            index: 0,
            first_type: "alloc::boxed::Box<sshpuffin::claim::SshClaimInner>".into(),
            second_type: "()".into(),
        });
        assert!(keep(&presence));
    }

    /// Filter policy: fail closed for everything EXCEPT the minimal seed-benign
    /// framing set (ChannelOpenConfirmation / ChannelSuccess). We deliberately do
    /// NOT broadly whitelist — presence differences of other control-plane kinds
    /// (e.g. ServiceAccept) stay objectives and are classified benign downstream.
    #[test]
    fn fail_closed_except_minimal_seed_framing() {
        use puffin::differential::KnowledgeDiff;
        use puffin::trace::Source;

        let decryption = || Source::Label(Some("Decryption".into()));
        let presence = |kind: &str| {
            TraceDifference::Knowledges(KnowledgeDiff::DifferentTypes {
                index: 0,
                first_type: kind.into(),
                second_type: "()".into(),
                first_source: decryption(),
                second_source: Source::Label(None),
            })
        };

        // Kept (fail closed): security-relevant AND other control-plane framing
        // that is NOT in the minimal seed set.
        for kind in [
            "SshMessage::UserAuthSuccess",
            "SshMessage::UserAuthFailure",
            "SshMessage::ChannelData",
            "SshMessage::Disconnect",
            "SshMessage::ServiceAccept",
            "SshMessage::ChannelOpenFailure",
        ] {
            assert!(keep(&presence(kind)), "{kind} presence must be kept");
        }

        // Dropped: ONLY the two kinds needed to keep the seeds at 0 differences.
        for kind in [
            "SshMessage::ChannelOpenConfirmation",
            "SshMessage::ChannelSuccess",
        ] {
            assert!(
                !keep(&presence(kind)),
                "{kind} seed-framing must be dropped"
            );
        }

        // Content differences are always kept.
        let content = TraceDifference::Knowledges(KnowledgeDiff::InnerDifference {
            index: 0,
            type_name: "sshpuffin::ssh::message::SshMessage".into(),
            diff: "Different(UserAuthSuccess, UserAuthFailure(..))".into(),
            source: decryption(),
        });
        assert!(keep(&content));
    }
}

/// Positive control for the differential *knowledge* comparison.
///
/// The decryption recipes (`differential_fuzzing_terms_to_eval`) feed their
/// decrypted `SshMessage`s into a `KnowledgeStore`, and the two PUTs' stores are
/// compared by `KnowledgeStore::compare` (puffin/src/trace.rs). Reporting "zero
/// `Knowledges` differences across a campaign" is only meaningful if that
/// comparison actually *fires* when the payloads differ — otherwise a null
/// result is a false negative from an inert detector (e.g. the decrypted type
/// being silently dropped by `differential_fuzzing_whitelist`). These tests lock
/// the detector in: two *different* whitelisted `SshMessage`s at the same store
/// position MUST yield a `TraceDifference::Knowledges`, and two equal ones MUST
/// yield none.
#[cfg(test)]
mod knowledge_compare_positive_control {
    use puffin::differential::TraceDifference;
    use puffin::trace::{KnowledgeStore, Source};

    use super::SshProtocolTypes;
    use crate::ssh::message::SshMessage;

    fn decryption_store(msg: SshMessage) -> KnowledgeStore<SshProtocolTypes> {
        let mut store = KnowledgeStore::new();
        // Mirror how trace.rs::compare stores decrypted recipe output.
        store.add_raw_knowledge(msg, None, Source::Label(Some("Decryption".into())), None);
        store
    }

    #[test]
    fn differing_decrypted_messages_produce_a_knowledges_diff() {
        let first = decryption_store(SshMessage::NewKeys);
        let second = decryption_store(SshMessage::UserAuthSuccess);

        let diffs = first
            .compare(&second)
            .expect_err("two different decrypted payloads must be detected as a difference");
        assert!(
            diffs
                .iter()
                .any(|d| matches!(d, TraceDifference::Knowledges(_))),
            "expected a Knowledges difference from the decrypted-store comparison, got {diffs:?}"
        );
    }

    #[test]
    fn equal_decrypted_messages_produce_no_diff() {
        let first = decryption_store(SshMessage::NewKeys);
        let second = decryption_store(SshMessage::NewKeys);
        assert!(
            first.compare(&second).is_ok(),
            "identical decrypted payloads must not be flagged (no false positive)"
        );
    }

    /// Reproduces the EXACT asymmetric decryption observed on
    /// seed_client_attacker_pubkey_aesgcm: wolfSSH decrypts one more message
    /// (a ServiceAccept) than libssh at the same recipe position, so the two
    /// decrypted stores are MISALIGNED:
    ///   libssh  = [UserAuthSuccess]
    ///   wolfSSH = [ServiceAccept, UserAuthSuccess]
    /// If `compare` aligns purely by index it will report a difference
    /// (UserAuthSuccess vs ServiceAccept, then () vs UserAuthSuccess); if it
    /// silently swallows the misalignment it will report none. This pins down
    /// whether `differential-execute` returning 0 on that seed is a genuine
    /// agreement or a masked divergence.
    #[test]
    fn misaligned_asymmetric_decryption_is_surfaced() {
        use crate::ssh::message::{ServiceAcceptMessage, SshBytes};

        let mut libssh = KnowledgeStore::new();
        libssh.add_raw_knowledge(
            SshMessage::UserAuthSuccess,
            None,
            Source::Label(Some("Decryption".into())),
            None,
        );

        let mut wolfssh = KnowledgeStore::new();
        wolfssh.add_raw_knowledge(
            SshMessage::ServiceAccept(ServiceAcceptMessage {
                service_name: SshBytes(b"ssh-userauth".to_vec()),
            }),
            None,
            Source::Label(Some("Decryption".into())),
            None,
        );
        wolfssh.add_raw_knowledge(
            SshMessage::UserAuthSuccess,
            None,
            Source::Label(Some("Decryption".into())),
            None,
        );

        let result = libssh.compare(&wolfssh);
        println!("misaligned compare result: {result:?}");
        assert!(
            result.is_err(),
            "asymmetric cross-vendor decryption (wolfSSH decrypts a ServiceAccept \
             libssh does not) MUST surface as a difference, otherwise it is a masked \
             false negative"
        );
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
}
