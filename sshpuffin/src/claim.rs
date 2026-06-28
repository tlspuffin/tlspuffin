use comparable::Comparable;
use puffin::agent::AgentName;
use puffin::algebra::dynamic_function::TypeShape;
use puffin::claims::Claim;
use puffin::error::Error;
use puffin::protocol::{EvaluatedTerm, Extractable, ProtocolTypes};
use puffin::trace::{Knowledge, Source, StepNumber};
use puffin::{codec, dummy_codec, dummy_extract_knowledge, dummy_extract_knowledge_codec};

use crate::protocol::SshProtocolTypes;

/// The security-relevant state captured at a claim point. Currently a single
/// claim type — emitted once the SSH transport handshake completes — carrying
/// the negotiated algorithms and the agent's role. This is what the DY security
/// oracle (`violation.rs`) compares between the client and the server.
#[derive(Debug, Clone, Comparable, PartialEq)]
pub struct SshClaimInner {
    /// true if this claim was emitted by the server side of the connection.
    pub is_server: bool,
    /// Negotiated key-exchange algorithm (`ssh_get_kex_algo`).
    pub kex: String,
    /// Negotiated incoming/outgoing ciphers (`ssh_get_cipher_in/out`).
    pub cipher_in: String,
    pub cipher_out: String,
    /// Negotiated incoming/outgoing MACs (`ssh_get_hmac_in/out`).
    pub hmac_in: String,
    pub hmac_out: String,
    /// The agent's belief about how (and as whom) the peer authenticated, used
    /// by the entity-authentication / impersonation oracle. On the server side:
    /// the method that succeeded ("password" / "publickey" / ""), the user name,
    /// and — for publickey — the SHA-256 fingerprint of the public key the
    /// server cryptographically verified and authorized. Empty fingerprint for
    /// non-publickey methods.
    pub auth_method: String,
    pub auth_user: String,
    pub auth_key_fingerprint: Vec<u8>,
    /// KEX-transcript binding: the SSH session identifier, i.e. the exchange
    /// hash `H` of the first key exchange (RFC 4253 §7.2). `H` binds
    /// `V_C,V_S,I_C,I_S,K_S,e,f,K` (§8), so two honest peers share it iff they
    /// had a matching key-exchange conversation. Empty when unavailable (no
    /// completed KEX, or a PUT that does not expose it). Per-execution value
    /// (depends on the ephemeral DH keys), so it is excluded from differential
    /// comparison; the oracle only checks client/server *agreement* within one
    /// run.
    #[comparable_ignore]
    pub session_id: Vec<u8>,
    /// Channel-data integrity: order-sensitive digests over the message-type
    /// byte of every packet on the secure channel (post-NEWKEYS), per
    /// direction (`tx` = sent by this peer, `rx` = received). In a faithful
    /// relay one peer's `tx` equals its partner's `rx`; a dropped / injected /
    /// reordered secure-channel message (Terrapin) breaks that crosswise
    /// equality. 0 = unavailable. Per-execution; excluded from differential
    /// comparison (used only for cross-endpoint agreement).
    #[comparable_ignore]
    pub secure_tx_digest: u64,
    #[comparable_ignore]
    pub secure_rx_digest: u64,
    /// Coarse protocol phase this claim was emitted at (liveness depth): one of
    /// [`PHASE_INIT`]/[`PHASE_KEX`]/[`PHASE_AUTH`]/[`PHASE_DONE`]. Intermediate
    /// (`< PHASE_DONE`) claims are emitted even by runs that abort mid-handshake
    /// and exist only to feed the claim-coverage feedback (liveness-depth
    /// gradient); the security oracle considers only `PHASE_DONE` claims. The
    /// completion claim is `PHASE_DONE`. Excluded from differential comparison.
    #[comparable_ignore]
    pub phase: u8,
    /// Per-direction total packet counts (handshake depth). Refine the
    /// liveness-depth coverage for runs that abort before the secure channel
    /// (digests still 0) and that the coarse `phase` does not separate. Bucketed
    /// in `coverage_key`. Excluded from differential comparison.
    #[comparable_ignore]
    pub rx_count: u32,
    #[comparable_ignore]
    pub tx_count: u32,
}

/// Protocol phases for [`SshClaimInner::phase`] (liveness depth).
pub const PHASE_INIT: u8 = 0;
pub const PHASE_KEX: u8 = 1;
pub const PHASE_AUTH: u8 = 2;
pub const PHASE_DONE: u8 = 3;

/// SHA-256 fingerprint of the *attacker-controlled* client identity key (key A):
/// the one whose private key / signing function IS present in the term-algebra
/// signature. It is the only publickey identity a Dolev-Yao attacker can produce
/// a valid signature for. Authenticating as any other key is impersonation.
///
/// Kept in lockstep with key A (`fn_client_a_pubkey_blob`): this is
/// `SHA-256(A's public-key blob)`, matching what libssh reports via
/// `ssh_get_publickey_hash`. Verified by `print_attacker_key_fingerprint`.
pub const ATTACKER_PUBKEY_SHA256: [u8; 32] = [
    164, 158, 186, 199, 118, 204, 58, 128, 55, 44, 68, 42, 197, 76, 45, 122, 159, 212, 94, 126,
    147, 234, 100, 129, 209, 165, 90, 44, 126, 27, 39, 41,
];

impl SshClaimInner {
    /// Canonicalize vendor-specific algorithm names to their SSH wire form so
    /// claims are comparable across implementations. libssh already reports wire
    /// names (`curve25519-sha256`, `aes256-gcm@openssh.com`, `aead-gcm`); wolfSSH
    /// reports human descriptions (`ECDH`, `AES-256 GCM`,
    /// `AES256 GCM (in ETM mode)`). Both collapse to the same token here, so a
    /// surviving cross-vendor claim diff signals a *real* negotiation divergence
    /// (e.g. a downgrade), not naming noise. Auth fields are left untouched (they
    /// are already canonical: "publickey"/"password", user name, key fingerprint).
    pub(crate) fn canonicalize(mut self) -> Self {
        self.kex = canon_kex(&self.kex);
        self.cipher_in = canon_cipher(&self.cipher_in);
        self.cipher_out = canon_cipher(&self.cipher_out);
        self.hmac_in = canon_mac(&self.hmac_in);
        self.hmac_out = canon_mac(&self.hmac_out);
        self
    }
}

/// Canonicalize a key-exchange name. Both libssh's `curve25519-sha256` and
/// wolfSSH's `ECDH` (over Curve25519, the only curve our seeds negotiate) map to
/// the wire name.
fn canon_kex(s: &str) -> String {
    let t = s.trim().to_ascii_lowercase();
    if t.contains("curve25519") || t == "ecdh" {
        return "curve25519-sha256".to_string();
    }
    t
}

/// Canonicalize a cipher name to its SSH wire form.
fn canon_cipher(s: &str) -> String {
    let t = s.trim().to_ascii_lowercase();
    if t.contains("chacha20") || t.contains("poly1305") {
        return "chacha20-poly1305@openssh.com".to_string();
    }
    let bits = if t.contains("128") {
        "128"
    } else if t.contains("192") {
        "192"
    } else {
        "256"
    };
    if t.contains("gcm") {
        return format!("aes{bits}-gcm@openssh.com");
    }
    if t.contains("aes") && (t.contains("ctr") || t.contains("sdctr")) {
        return format!("aes{bits}-ctr");
    }
    if t.contains("aes") && t.contains("cbc") {
        return format!("aes{bits}-cbc");
    }
    t
}

/// Canonicalize a MAC name. AEAD ciphers carry an *implicit* MAC that each
/// library names differently (libssh `aead-gcm`/`aead-poly1305`; wolfSSH
/// `AES256 GCM (in ETM mode)`); these collapse to a size-independent AEAD token
/// so the cipher field (which does carry the key size) remains the place where a
/// real downgrade shows up.
fn canon_mac(s: &str) -> String {
    let t = s.trim().to_ascii_lowercase();
    if t.contains("poly1305") || t.contains("chacha20") {
        return "aead-poly1305".to_string();
    }
    if t.contains("gcm") {
        return "aead-gcm".to_string();
    }
    if t.contains("sha2-512") || t.contains("sha-512") || t.contains("sha512") {
        return "hmac-sha2-512".to_string();
    }
    if t.contains("sha2-256") || t.contains("sha-256") || t.contains("sha256") {
        return "hmac-sha2-256".to_string();
    }
    if t.contains("sha-1-96") || t.contains("sha1-96") {
        return "hmac-sha1-96".to_string();
    }
    if t.contains("sha-1") || t.contains("sha1") {
        return "hmac-sha1".to_string();
    }
    t
}

/// Coarse bucket for per-direction packet counts in the claim coverage key:
/// fine in the handshake range (`0..=15`), then a few log-ish buckets, so
/// channel-data count variation collapses instead of exploding the DY-state
/// cell space (which blew the corpus up 5x with a flat cap of 63).
fn ssh_count_bucket(n: u32) -> u8 {
    match n {
        0..=15 => n as u8,
        16..=31 => 16,
        32..=63 => 17,
        64..=255 => 18,
        _ => 19,
    }
}

dummy_extract_knowledge_codec!(SshProtocolTypes, Box<SshClaimInner>);

#[derive(Debug, Clone, Comparable, PartialEq)]
pub struct SshClaim {
    agent_name: AgentName,
    inner: Box<SshClaimInner>,
    /// The trace step at which the claim was emitted. Excluded from differential
    /// comparison: it records *where in the trace* the handshake completed, not
    /// security state. Two implementations reach the claim point after a
    /// different number of intermediate messages (e.g. wolfSSH does an explicit
    /// ServiceAccept round-trip where libssh pipelines), so the step index
    /// differs benignly cross-vendor. The security content is in `inner`.
    #[comparable_ignore]
    step: Option<StepNumber>,
}

impl SshClaim {
    pub fn new(agent_name: AgentName, inner: SshClaimInner) -> Self {
        Self {
            agent_name,
            inner: Box::new(inner),
            step: None,
        }
    }

    /// Access the captured security state.
    pub fn data(&self) -> &SshClaimInner {
        &self.inner
    }
}

dummy_extract_knowledge_codec!(SshProtocolTypes, SshClaim);

impl Claim for SshClaim {
    type PT = SshProtocolTypes;

    fn agent_name(&self) -> AgentName {
        self.agent_name
    }

    fn id(&self) -> TypeShape<SshProtocolTypes> {
        TypeShape::of::<SshClaimInner>()
    }

    fn inner(&self) -> Box<dyn EvaluatedTerm<SshProtocolTypes>> {
        Box::new(self.inner.clone())
    }

    fn set_step(&mut self, step: Option<StepNumber>) {
        self.step = step;
    }

    fn get_step(&self) -> Option<StepNumber> {
        self.step.clone()
    }

    /// Projection for protocol-agnostic claim-trajectory coverage: a hash of the
    /// *semantic* conversation state this claim records, with the per-execution
    /// random `session_id` (the exchange hash H) deliberately omitted so two
    /// runs of the same conversation collapse to one key (no always-true
    /// feedback). The per-direction post-NEWKEYS message-type digests are
    /// deterministic — a dropped / injected / reordered secure-channel message
    /// (the matching-conversation signal) changes them and so yields a new
    /// coverage cell. `DefaultHasher` is keyed with fixed (0,0) seeds, hence
    /// stable across the forked fuzzer processes.
    fn coverage_key(&self) -> Option<u64> {
        use std::hash::{Hash, Hasher};

        // A/B toggle: with `PUFFIN_NO_CLAIM_COV` set, opt every claim out of
        // coverage (claim map stays empty, the claim feedback never fires) =>
        // edge-coverage-only baseline (arm A). Unset => edge + claim coverage
        // (arm B). Read once per process.
        static DISABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        if *DISABLED.get_or_init(|| std::env::var_os("PUFFIN_NO_CLAIM_COV").is_some()) {
            return None;
        }

        let d = &self.inner;
        let mut h = std::collections::hash_map::DefaultHasher::new();
        d.phase.hash(&mut h);
        // Handshake-depth resolution, COARSELY bucketed. The first A/B re-run
        // showed that fine count buckets (cap 63) explode the cell space —
        // channel-data traces have widely varying counts, so the corpus blew up
        // 5x. Buckets give fine resolution only in the handshake range (~0-15
        // packets/direction) and collapse everything above, which is the only
        // range that distinguishes liveness depth.
        ssh_count_bucket(d.rx_count).hash(&mut h);
        ssh_count_bucket(d.tx_count).hash(&mut h);
        d.is_server.hash(&mut h);
        d.kex.hash(&mut h);
        d.cipher_in.hash(&mut h);
        d.cipher_out.hash(&mut h);
        d.hmac_in.hash(&mut h);
        d.hmac_out.hash(&mut h);
        d.auth_method.hash(&mut h);
        d.auth_user.hash(&mut h);
        d.auth_key_fingerprint.hash(&mut h);
        // Deliberately OMITTED from coverage: the per-direction post-NEWKEYS
        // message-type-sequence digests. They are *high-cardinality* (one value
        // per distinct channel-data sequence) and behave like a counter — the
        // A/B re-runs showed they explode the cell space and inflate the corpus
        // (B 4-5x A). They belong in the ORACLE (exact matching-conversation
        // check), not the coverage signal. The Terrapin-class divergence is
        // still captured here coarsely via the bucketed packet counts (a dropped
        // EXT_INFO makes the victim's rx_count one lower => a different cell).
        // Also omitted (per-execution random): session_id.
        Some(h.finish())
    }
}
