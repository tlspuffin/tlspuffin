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
        use crate::ssh::transcript::AlignedTranscript;
        // Compare exactly ONE knowledge per stream: the `AlignedTranscript` folded
        // from the whole server flight (ssh/transcript.rs). It is the sole
        // comparison object, so puffin's upstream positional compare pairs the two
        // maps 1:1 and the `comparable` BTreeMap diff does the key-based alignment
        // inside. Everything else in the stores — raw ciphertext/framing, the
        // per-message SshMessage/flight intermediates, the chacha recipe output —
        // is excluded: the fold already carries the full decoded transcript
        // (plaintext KEXINIT + decrypted post-NewKeys), and within-message noise is
        // handled at the field level via #[comparable_ignore] / #[comparable_synthetic].
        Some(vec![TypeId::of::<AlignedTranscript>()])
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
        // Intermediate phase claims (liveness-depth signal for claim coverage)
        // are emitted only by the libssh harness, not wolfSSH, so comparing them
        // cross-vendor is a spurious diff on every run. They carry a distinct
        // TypeShape (see SshClaim::id) so we drop them from differential
        // comparison by type; only completed-handshake claims are compared.
        Some(vec![TypeId::of::<crate::claim::SshProgressClaim>()])
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

    fn differential_fuzzing_filter_diff(_diff: &puffin::differential::TraceDifference) -> bool {
        // FULLY FAIL-CLOSED: every difference — status, security-claim, and the
        // AlignedTranscript's content/presence divergences — is KEPT as an
        // objective. We do NOT whitelist anything here (the old ChannelOpen*/
        // ChannelSuccess "seed-benign" whitelist was dangerous: a presence
        // whitelist keyed on message kind cannot tell a benign framing difference
        // from a real acceptance divergence, so it could mask a bug — exactly the
        // concern that motivated this rework).
        //
        // Denoising instead lives where it is PROVABLY safe:
        //   * structural, in the data model — the AlignedTranscript's key-based
        //     alignment (ssh/transcript.rs), #[comparable_ignore] /
        //     #[comparable_synthetic] on message fields, and uniformise_put_config;
        //   * seed-level — the differential-corpus seeds are constructed to be
        //     genuinely 0-diff (e.g. a channel request the two stacks answer
        //     identically), rather than diffing-then-whitelisting;
        //   * downstream — benign CLASSES (strict-kex/ext-info marker asymmetry,
        //     reply pipelining) are labelled as explicit, precise triage buckets
        //     that a human reviews, never dropped before they become objectives.
        true
    }

    // NOTE: alignment is NOT done via puffin's `differential_fuzzing_alignment_key`
    // hook anymore (that hook is reverted to upstream). All semantic alignment of
    // the decrypted messages lives inside sshpuffin's `AlignedTranscript`
    // (ssh/transcript.rs): the fold recipe emits ONE key-aligned `BTreeMap` per
    // stream, and the `comparable` crate's key-based Map diff does the alignment.
    // Likewise `differential_fuzzing_always_compare_knowledge` stays the upstream
    // default (false): in the sound fail-closed mode a status disagreement is
    // itself an objective (and ASYM auth is surfaced structurally by the
    // entity-authentication SecurityClaim, compared unconditionally), so nothing is
    // hidden by the short-circuit.
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

    /// Filter policy: FULLY fail-closed. Every difference kind is kept — including
    /// the ones the old code dropped as "seed-benign framing"
    /// (ChannelOpenConfirmation / ChannelSuccess). Those are no longer a filter
    /// concern: with the AlignedTranscript's key-based alignment the two stacks'
    /// channel replies align on a canonical channel (so ChannelOpenConfirmation no
    /// longer diverges at all), and any genuine residual is a real objective for a
    /// human to classify downstream — never silently dropped here.
    #[test]
    fn fully_fail_closed_keeps_every_kind() {
        use puffin::differential::KnowledgeDiff;
        use puffin::trace::Source;

        let decryption = || Source::Label(Some("Decryption".into()));

        // Presence differences of EVERY kind are kept (nothing is whitelisted).
        let presence = |kind: &str| {
            TraceDifference::Knowledges(KnowledgeDiff::DifferentTypes {
                index: 0,
                first_type: kind.into(),
                second_type: "()".into(),
                first_source: decryption(),
                second_source: Source::Label(None),
            })
        };
        for kind in [
            "SshMessage::UserAuthSuccess",
            "SshMessage::ServiceAccept",
            "SshMessage::ChannelOpenConfirmation",
            "SshMessage::ChannelSuccess",
            "sshpuffin::ssh::transcript::AlignedTranscript",
        ] {
            assert!(keep(&presence(kind)), "{kind} presence must be kept");
        }

        // Content differences are always kept.
        let content = TraceDifference::Knowledges(KnowledgeDiff::InnerDifference {
            index: 0,
            type_name: "sshpuffin::ssh::transcript::AlignedTranscript".into(),
            diff: "Changed([Removed(UserAuthSuccess)])".into(),
            source: decryption(),
        });
        assert!(keep(&content));
    }
}

/// Positive control for the differential *knowledge* comparison (store level).
///
/// The fold recipe (`differential_fuzzing_terms_to_eval`) feeds ONE
/// `AlignedTranscript` per PUT into a `KnowledgeStore`, and the two stores are
/// compared by puffin's upstream `KnowledgeStore::compare`. Reporting "zero
/// differences across a campaign" is only meaningful if that comparison actually
/// *fires* when the transcripts differ — otherwise a null result is a false
/// negative from an inert detector (e.g. the transcript type being dropped by the
/// whitelist). These tests lock the detector in through the REAL store path: two
/// different transcripts MUST yield a `Knowledges` difference, two equal ones MUST
/// yield none, and the whitelist MUST admit `AlignedTranscript`.
#[cfg(test)]
mod knowledge_compare_positive_control {
    use puffin::differential::TraceDifference;
    use puffin::trace::{KnowledgeStore, Source};

    use super::SshProtocolTypes;
    use crate::ssh::message::SshMessage;
    use crate::ssh::transcript::AlignedTranscript;

    fn transcript_store(msgs: Vec<SshMessage>) -> KnowledgeStore<SshProtocolTypes> {
        let mut store = KnowledgeStore::new();
        // Mirror how trace.rs::compare stores the folded recipe output.
        store.add_raw_knowledge(
            AlignedTranscript::from_messages(msgs),
            None,
            Source::Label(Some("Decryption".into())),
            None,
        );
        store
    }

    /// Gate A (must fire): an auth-state divergence — one stack authenticates
    /// (USERAUTH_SUCCESS), the other rejects (USERAUTH_FAILURE) — surfaces through
    /// the real store comparison.
    #[test]
    fn diverging_auth_outcome_produces_a_knowledges_diff() {
        use crate::ssh::message::{NameList, UserAuthFailureMessage};

        let authed = transcript_store(vec![SshMessage::UserAuthSuccess]);
        let rejected = transcript_store(vec![SshMessage::UserAuthFailure(UserAuthFailureMessage {
            authentications_that_can_continue: NameList::empty(),
            partial_success: false,
        })]);

        let diffs = authed
            .compare(&rejected)
            .expect_err("an auth-outcome divergence must be detected");
        assert!(
            diffs
                .iter()
                .any(|d| matches!(d, TraceDifference::Knowledges(_))),
            "expected a Knowledges difference, got {diffs:?}"
        );
    }

    /// Gate A (must fire): a Terrapin-shaped presence divergence — one stack emits
    /// a message the other does not, at the same logical position.
    #[test]
    fn single_sided_message_produces_a_knowledges_diff() {
        let with_success = transcript_store(vec![SshMessage::NewKeys, SshMessage::UserAuthSuccess]);
        let without = transcript_store(vec![SshMessage::NewKeys]);
        assert!(
            with_success.compare(&without).is_err(),
            "a message present on only one side must surface as a difference"
        );
    }

    /// No false positive: identical transcripts compare equal (and this also
    /// proves the whitelist ADMITS AlignedTranscript — a dropped type would make
    /// even differing transcripts compare equal, which the Gate-A tests forbid).
    #[test]
    fn equal_transcripts_produce_no_diff() {
        let a = transcript_store(vec![SshMessage::NewKeys, SshMessage::UserAuthSuccess]);
        let b = transcript_store(vec![SshMessage::NewKeys, SshMessage::UserAuthSuccess]);
        assert!(
            a.compare(&b).is_ok(),
            "identical transcripts must not be flagged (no false positive)"
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

    fn check_trace_security_violation(
        _trace: &Trace<Self::ProtocolTypes>,
        _ctx: &puffin::trace::TraceContext<Self>,
    ) -> Option<&'static str> {
        // The matching-conversation property is now judged by the claims-based
        // DY oracle (`SshSecurityViolationPolicy::check_violation`): it compares
        // the KEX transcript (session id / exchange hash H) and the post-NEWKEYS
        // secure-channel message-type digests, which are derived from the
        // *parsed, MAC-authenticated* message stream.
        //
        // The earlier trace-level byte-stream comparison
        // (`matching_conversation_violation`) is retired as the live oracle: it
        // over-approximated the property by diffing raw delivered bytes, so it
        // flagged corruption of fields SSH explicitly does not protect — padding
        // and SSH_MSG_IGNORE (RFC 4251 §9.3.6) — producing the bulk of the
        // bit-level campaign false positives. The function is kept for its
        // direct unit tests. Returning `None` here leaves the (FP-free) claims
        // oracle as the sole matching-conversation judge.
        None
    }
}
