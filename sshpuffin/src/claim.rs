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
