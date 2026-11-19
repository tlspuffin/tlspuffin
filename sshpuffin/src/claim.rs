use comparable::Comparable;
use puffin::agent::AgentName;
use puffin::algebra::dynamic_function::TypeShape;
use puffin::claims::Claim;
use puffin::error::Error;
use puffin::protocol::{EvaluatedTerm, Extractable, ProtocolTypes};
use puffin::trace::{Knowledge, Source, StepNumber};
use puffin::{codec, dummy_codec, dummy_extract_knowledge, dummy_extract_knowledge_codec};

use crate::protocol::SshProtocolTypes;

/// The server's entity-authentication belief at handshake completion — the SSH
/// analogue of TLS's FINISHED claim. Emitted once per agent when the harness'
/// auth callback has APPROVED an authorized credential (put.c `emit_handshake_claim`),
/// so its mere presence means "this stack believes it authenticated a peer", and
/// its fields say WHOM.
///
/// This is what the wire cannot tell us: `USERAUTH_SUCCESS` is identity-less, so
/// the decrypted transcript proves *that* a peer was authenticated but not *which*
/// one. Comparing these claims across the two PUTs therefore catches
/// identity/impersonation divergences (one stack believes it authenticated user A,
/// the other user B, from the same input) that the transcript comparison cannot.
///
/// The auth-belief fields are the ones *compared* across PUTs. `session_id` (the
/// first-KEX exchange hash H) is also carried, but is `#[comparable_ignore]`: it
/// differs by construction between two stacks with independent ephemeral keys, so
/// comparing it would manufacture benign differences. It is decoded solely so the
/// s2c decryption recipe can source each PUT's own H — via
/// `fn_claim_exchange_hash` — instead of reconstructing
/// it from a hard-coded (and mutation-stale) client KEXINIT. The C harness also
/// builds channel digests / packet counts; those stay undecoded (matching-
/// conversation / Terrapin substrate, a separate concern).
#[derive(Debug, Clone, Comparable, PartialEq, Default)]
pub struct SshClaimInner {
    /// Method the server believes succeeded: "publickey" / "password" / "".
    pub auth_method: String,
    /// User name the server authenticated.
    pub auth_user: String,
    /// SHA-256 fingerprint of the authenticated public key (empty for password/none).
    pub auth_key_fp: Vec<u8>,
    /// First-KEX exchange hash H (== SSH session id, RFC 4253 §7.2). Decryption
    /// material only — NOT compared (differs per-stack by construction).
    #[comparable_ignore]
    pub session_id: Vec<u8>,
    /// CVE-2025-14942 oracle flag (the C `Claim.auth_while_keying`): the client
    /// reached the server-userauth-accepted state (`serverState >=
    /// SERVER_USERAUTH_ACCEPT_DONE`) while the transport was still keying
    /// (`isKeying != 0`) — i.e. it accepted a user-authentication-protocol message
    /// out of order, during key exchange, which the fixed wolfSSH client rejects.
    /// `SshSecurityViolationPolicy::check_violation` keys on this. NOT compared
    /// across PUTs (an honest handshake never sets it, so it is identically false
    /// on both stacks for every 0-diff trace): it is a one-sided safety signal, not
    /// a conversation-matching field.
    #[comparable_ignore]
    pub auth_while_keying: bool,
    /// Coarse protocol phase (C `Claim.phase`): 2 = post-KEX, 3 = handshake complete.
    /// The entity-auth oracle targets the completion claim (phase 3). NOT compared.
    #[comparable_ignore]
    pub phase: u8,
    /// Entity-authentication oracle fields (`SshSecurityViolationPolicy`).
    /// This agent's role (C `Claim.role`): 0 = client, 1 = server. Lets the oracle
    /// pick the client vs the server claim (host auth is client-only; user-auth
    /// authorization is server-only; the two-party matching-conversation check pairs
    /// one of each). NOT compared across PUTs.
    #[comparable_ignore]
    pub role: u8,
    /// P1 (server side, user authentication): the library had cryptographically
    /// verified a publickey signature by the time it decided this login (wolfSSH
    /// `hasSignature`). A server that reached authenticated with `had_signature ==
    /// false` accepted a login that proved no key. NOT compared across PUTs.
    #[comparable_ignore]
    pub had_signature: bool,
    /// P2 (client side, host authentication): the client verified a server host-key
    /// signature over H during key exchange (its public-key-check callback fired and
    /// the handshake proceeded). A client that reached user-auth-accepted with
    /// `host_authenticated == false` accepted a session from a server that proved no
    /// host key. NOT compared across PUTs.
    #[comparable_ignore]
    pub host_authenticated: bool,
    /// Opt-in: the emitting harness populates `role`/`had_signature`/`host_authenticated`.
    /// The oracle applies the P1/P2/P3 checks only to claims with this set, so an
    /// un-instrumented harness (fields default to false) is never read as a bypass.
    #[comparable_ignore]
    pub entity_auth_checked: bool,
}
dummy_extract_knowledge_codec!(SshProtocolTypes, Box<SshClaimInner>);

#[derive(Debug, Clone, Comparable, PartialEq)]
pub struct SshClaim {
    agent_name: AgentName,
    inner: Box<SshClaimInner>,
    /// Trace step at which the claim was emitted (set by the framework). NOT
    /// compared across PUTs: it is harness/library drain-timing metadata (the two
    /// stacks reach a given claim point at different trace steps — e.g. the
    /// post-KEX claim lands at step 5 on one and 6 on the other), which is benign
    /// and would otherwise manufacture a spurious per-claim difference. Only the
    /// per-agent auth belief in `inner` is the security-relevant comparison.
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

    /// The decoded auth-belief fields (used by the security oracle).
    pub fn inner_ref(&self) -> &SshClaimInner {
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
        // Must match the concrete type `inner()` yields (a `Box<SshClaimInner>`,
        // the registered EvaluatedTerm type) so a decryption-recipe Variable typed
        // `Box<SshClaimInner>` resolves via `find_claim` (which matches on `id()`).
        TypeShape::of::<Box<SshClaimInner>>()
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
