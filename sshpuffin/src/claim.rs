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
    /// Rolling FNV-1a digest of the raw byte stream this agent received (rx)
    /// and sent (tx) up to the claim point. The matching-conversation oracle
    /// compares one peer's `tx_digest` against the other's `rx_digest`.
    pub rx_digest: u64,
    pub tx_digest: u64,
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
