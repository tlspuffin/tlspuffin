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
use crate::ssh::differential::{
    is_banner_induced_transcript_presence, is_banner_strictness_diff,
    is_fwd_reqsuccess_port_echo_diff, is_userauth_failure_only_diff, renumber_aesgcm_counters,
    shadow_known_benign, shadow_known_bugs, step_has_auto_counter,
};
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
    /// Public-key algorithms the server accepts for user auth, advertised in the
    /// EXT_INFO `server-sig-algs` extension (RFC 8308 §3.1) — distinct from
    /// `hostkey_algos` (KEXINIT host keys). Uniformised so the two PUTs' decrypted
    /// EXT_INFO no longer diverges on static per-implementation capability.
    #[serde(default)]
    pub server_sig_algs: Option<String>,
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
            server_sig_algs: None,
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
                // AES-GCM is the ONLY cipher negotiated in the differential:
                // `differential_fuzzing_uniformise_put_config` pins both PUTs to
                // `aes256-gcm,aes128-gcm`, and chacha20-poly1305 is not even
                // offered. The AES-GCM recipe is framing-INDEPENDENT — it folds
                // the whole s2c stream via `((server, *)/RawSshMessageFlight)` +
                // `fn_fold_s2c_transcript`, which re-accumulates the wire bytes and
                // re-deframes, so libssh's and wolfSSH's different packetisation
                // (1 vs 2 on-wire chunks) yields the SAME transcript.
                //
                // The legacy ChaCha20 recipe (`server_decryption_recipes`) is
                // deliberately NOT emitted: it decrypts POSITIONALLY-indexed
                // `(server, N)/OnWireData` chunks, a fragile pattern that binds to
                // one PUT's chunk layout and misaligns against the other's — pure
                // noise now that chacha is never negotiated. To restore chacha
                // support (e.g. if the cipher set is ever widened), add a
                // `fn_fold_s2c_transcript_chacha` and emit it the same
                // framing-independent way, rather than reviving the indexed recipe.
                terms.extend(crate::ssh::seeds::server_decryption_recipes_aesgcm(
                    agent.name,
                ));
            } else if agent.protocol_config.typ == AgentType::Client {
                // Client PUT (attacker plays the server): decrypt the client's c2s
                // stream the same framing-independent way. Only fires on traces
                // with a client PUT agent (server-attacker / two-party seeds); the
                // client-attacker differential corpus has server PUTs only, so its
                // comparisons are unchanged.
                terms.extend(crate::ssh::seeds::client_decryption_recipes_aesgcm(
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
            // EXT_INFO `server-sig-algs` (accepted pubkey auth algos). Without this
            // the two stacks advertise their full — and different — default sets
            // (libssh ~15 incl. ed25519/sk-*/cert variants; wolfSSH ~5 rsa+ecdsa),
            // which the decrypted-EXT_INFO comparison flags as a benign capability
            // diff. Pin both to an identical, byte-for-byte common subset both
            // support and the seeds' RSA auth still satisfies.
            agent.protocol_config.server_sig_algs = Some(
                "rsa-sha2-256,rsa-sha2-512,\
                 ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521"
                    .into(),
            );
        }
        // Recurse into prior traces so a multi-trace seed is uniformised
        // consistently. Every current SSH seed uses `prior_traces: vec![]`, so
        // this is a no-op today; it is kept for correctness if a seed ever
        // introduces prior traces (mirrors the TLS mapper), preventing a
        // prior-trace agent from advertising a different algorithm set than the
        // main trace and thereby manufacturing a spurious KEXINIT divergence.
        for t in trace.prior_traces.iter_mut() {
            *t = Self::differential_fuzzing_uniformise_put_config(t.to_owned());
        }
        trace
    }

    fn differential_fuzzing_filter_diff(diff: &puffin::differential::TraceDifference) -> bool {
        // FULLY FAIL-CLOSED: every difference — status, security-claim, and the
        // AlignedTranscript's content/presence divergences — is KEPT as an
        // objective. We do NOT whitelist anything here (the old ChannelOpen*/
        // ChannelSuccess "seed-benign" whitelist was dangerous: a presence
        // whitelist keyed on message kind cannot tell a benign framing difference
        // from a real acceptance divergence, so it could mask a bug — exactly the
        // concern that motivated this rework).
        //
        // Denoising instead lives where it is PROVABLY safe:
        //   * structural, in the data model — the AlignedTranscript's key-based alignment
        //     (ssh/transcript.rs), #[comparable_ignore] / #[comparable_synthetic] on message
        //     fields, and uniformise_put_config;
        //   * seed-level — the differential-corpus seeds are constructed to be genuinely 0-diff
        //     (e.g. a channel request the two stacks answer identically), rather than
        //     diffing-then-whitelisting;
        //   * downstream — benign CLASSES (strict-kex/ext-info marker asymmetry, reply pipelining)
        //     are labelled as explicit, precise triage buckets that a human reviews, never dropped
        //     before they become objectives.
        //
        // The ONE exception to fail-closed: a divergence CLASS that has been
        // investigated to a documented benign conclusion is "shadowed" (dropped
        // before it becomes an objective) so that long campaigns surface NEW
        // findings instead of re-reporting a closed one. Each shadow is a PRECISE
        // predicate (never a broad type/message whitelist — that is the unsafe
        // pattern rejected above) and the whole set is gated behind
        // SHADOW_KNOWN_BENIGN so it can be re-surfaced by flipping one flag.
        if shadow_known_benign() && is_banner_strictness_diff(diff) {
            // Finding A — pre-auth banner/version strictness. Documented benign
            // in BUG_HUNTING.md / REPORT_triaging.md: no memory-safety issue and
            // no exchange-hash divergence; purely libssh's 127-byte identification
            // cap vs wolfSSH's 255-byte WOLFSSH_PROTOID_LIMIT.
            return false;
        }
        if shadow_known_benign() && is_userauth_failure_only_diff(diff) {
            // Finding 3 — one stack emits a USERAUTH_FAILURE (method-list
            // advertisement) in its decrypted transcript that the other does not.
            // Investigated benign (2026-09-02, 272-objective scan): 0
            // success-asymmetry — in NO objective does either stack reach
            // USERAUTH_SUCCESS; auth fails on BOTH and the only difference is which
            // rejection packet each server emits. NOT an auth bypass or auth-policy
            // divergence. The predicate is GUARDED to only ever drop a
            // USERAUTH_FAILURE-only delta (see `is_userauth_failure_only_diff`): a
            // delta touching USERAUTH_SUCCESS — the genuinely dangerous
            // accept-vs-reject divergence — is NEVER shadowed.
            return false;
        }
        if shadow_known_bugs() && is_fwd_reqsuccess_port_echo_diff(diff) {
            // wolfSSH tcpip-forward REQUEST_SUCCESS port-echo (see
            // findings_phase3/WOLFSSH_TCPIP_FORWARD_PORT_ECHO.md). Both stacks
            // ACCEPT an authorized tcpip-forward, but wolfSSH appends the bound
            // port to SSH_MSG_REQUEST_SUCCESS even for a non-zero (non-dynamic)
            // requested port; RFC 4254 §7.1 returns that uint32 only for a port-0
            // request (OpenSSH and libssh both send a bare reply). Documented,
            // root-caused, still-live-on-master conformance deviation (LOW / not a
            // MUST — §7.1 is descriptive). The `forwarding` seed + its PoC keep the
            // finding on record; this shadow only stops long campaigns
            // re-reporting it.
            //
            // Gated behind SHADOW_KNOWN_BUGS (NOT SHADOW_KNOWN_BENIGN): this is a
            // REAL, documented wolfSSH bug we suppress to avoid re-reporting a
            // closed finding — categorically different from the benign non-findings
            // above, and re-surfaceable INDEPENDENTLY of them for a bug-focused
            // re-audit. GUARDED (see `is_fwd_reqsuccess_port_echo_diff`) to fire
            // ONLY on a both-accepted, response_data-only, purely-additive port
            // echo — an accept-vs-reject forward divergence (RequestFailure vs
            // RequestSuccess) or any other message change is NEVER shadowed.
            return false;
        }
        true
    }

    /// Context-aware set filter (see the puffin-core hook). Applies the per-diff
    /// `filter_diff` to every difference AND handles one thing a per-diff filter
    /// structurally cannot: when a banner-strictness *status* reject is shadowed,
    /// the rejecting side never produced a decrypted transcript, so the knowledge
    /// layer shows a `AlignedTranscript vs ()` PRESENCE diff — the SAME banner
    /// divergence surfacing again, not a new finding. Drop that presence diff too,
    /// but ONLY when a banner reject co-occurs in this trace. A blanket
    /// `AlignedTranscript vs ()` shadow would be UNSAFE: that shape is exactly how
    /// a genuine "one stack completes, the other does not" divergence looks, so it
    /// must survive whenever there is no banner reject to explain it.
    fn differential_fuzzing_filter_diffs(
        diffs: Vec<puffin::differential::TraceDifference>,
    ) -> Vec<puffin::differential::TraceDifference> {
        let banner_shadowed = shadow_known_benign() && diffs.iter().any(is_banner_strictness_diff);
        diffs
            .into_iter()
            .filter(|d| {
                // per-diff shadows (banner status, userauth-failure-only knowledge)
                if !Self::differential_fuzzing_filter_diff(d) {
                    return false;
                }
                // context-aware: the transcript-presence form of a shadowed banner
                if banner_shadowed && is_banner_induced_transcript_presence(d) {
                    return false;
                }
                true
            })
            .collect()
    }

    /// Per-execution AES-GCM packet-counter renumbering (see the module-level
    /// `renumber_aesgcm_counters`). A seed authors its c2s
    /// `fn_encrypt_packet_aesgcm` calls with the `fn_u32_auto` sentinel counter;
    /// this pass rewrites each to its true wire position so that step-deleting /
    /// reordering mutations keep the GCM nonce sequence valid — the mechanism that
    /// lets the mutator autonomously reach the RFC 4253 §7.1 incomplete-rekey state
    /// from an honest seed (rather than only from a hand-crafted reproducer).
    ///
    /// FAST PATH: a read-only symbol scan returns `None` (no clone) unless some
    /// recipe actually carries the sentinel, so every TLS trace and every SSH trace
    /// using explicit `fn_u32_N` counters is untouched and allocation-free.
    fn preprocess_trace(trace: &Trace<Self>) -> Option<Trace<Self>> {
        if !trace.steps.iter().any(step_has_auto_counter) {
            return None;
        }
        let mut trace = trace.clone();
        renumber_aesgcm_counters(&mut trace);
        Some(trace)
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
