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
}

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
}
