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
/// Only the auth-belief fields are carried (and hence compared). The richer claim
/// the C harness also builds — `session_id` (the exchange hash, which differs by
/// construction between two stacks with independent ephemeral keys), packet
/// counts, and channel digests — is deliberately NOT decoded here: it would
/// manufacture benign claim differences. Those come back later as the
/// matching-conversation / Terrapin substrate, with the appropriate ignores.
#[derive(Debug, Clone, Comparable, PartialEq, Default)]
pub struct SshClaimInner {
    /// Method the server believes succeeded: "publickey" / "password" / "".
    pub auth_method: String,
    /// User name the server authenticated.
    pub auth_user: String,
    /// SHA-256 fingerprint of the authenticated public key (empty for password/none).
    pub auth_key_fp: Vec<u8>,
}
dummy_extract_knowledge_codec!(SshProtocolTypes, Box<SshClaimInner>);

#[derive(Debug, Clone, Comparable, PartialEq)]
pub struct SshClaim {
    agent_name: AgentName,
    inner: Box<SshClaimInner>,
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
