// Minimal wiring of sppuffin into the puffin framework.
// This is intentionally tiny: it provides the required type aliases and
// minimal trait implementations so sppuffin can be referenced by the
// workspace and later expanded.

use std::any::TypeId;

use puffin::agent::{AgentDescriptor, ProtocolDescriptorConfig};
use puffin::algebra::dynamic_function::FunctionAttributes;
use puffin::define_signature;
use puffin::protocol::ProtocolTypes;
use puffin::trace::Trace;
use serde::{Deserialize, Serialize};
use puffin::trace::Knowledge;
use puffin::error::Error as PuffinError;
use puffin::trace::Source;
use puffin::algebra::AnyMatcher;

use crate::message::SwissMessage;

use crate::{fn_impl::*, seed_simple_three_terms};

// Provide a signature exposing only two JNI-backed functions for now: new and length
define_signature!(
    SPP_SIGNATURE<SwissProtocolTypes>,
    fn_new_immutable_byte_array
    fn_immutable_byte_array_length
);

#[derive(Clone, Debug)]
pub struct SwissMessageFlight {
    pub messages: Vec<SwissMessage>,
}

impl SwissMessageFlight {
    pub fn new() -> Self {
        Self { messages: vec![] }
    }
}

// Minimal opaque message types omitted for the prototype. The full protocol
// message/coding implementations can be added later when needed.

// A very small PUT config that satisfies the ProtocolDescriptorConfig bound.
#[derive(Clone, Debug, Serialize, Deserialize, Hash)]
pub struct SwissPUTConfig {
    pub try_reuse: bool,
}

impl Default for SwissPUTConfig {
    fn default() -> Self {
        Self { try_reuse: false }
    }
}

impl ProtocolDescriptorConfig for SwissPUTConfig {
    fn is_reusable_with(&self, other: &Self) -> bool {
        self.try_reuse == other.try_reuse
    }
}

use comparable::Comparable;



// Small wrapper for u64 so it can be used as an EvaluatedTerm in the signature
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Comparable)]
pub struct SppU64(pub u64);

impl puffin::codec::Codec for SppU64 {
    fn encode(&self, bytes: &mut Vec<u8>) {
        <u64 as puffin::codec::Codec>::encode(&self.0, bytes);
    }

    fn read(r: &mut puffin::codec::Reader) -> Option<Self> {
        <u64 as puffin::codec::Codec>::read(r).map(SppU64)
    }
}

impl puffin::protocol::Extractable<SwissProtocolTypes> for SppU64 {
    fn extract_knowledge<'a>(
        &'a self,
        knowledges: &mut Vec<Knowledge<'a, SwissProtocolTypes>>,
        _matcher: Option<<SwissProtocolTypes as ProtocolTypes>::Matcher>,
        source: &'a Source,
    ) -> Result<(), PuffinError> {
        knowledges.push(Knowledge {
            source,
            matcher: None,
            data: self,
        });
        Ok(())
    }
}

impl ProtocolTypes for SwissProtocolTypes {
    type Matcher = AnyMatcher;
    type PUTConfig = SwissPUTConfig;

    fn signature() -> &'static puffin::algebra::signature::Signature<Self> {
        &SPP_SIGNATURE
    }

    fn differential_fuzzing_whitelist() -> Option<Vec<std::any::TypeId>> {
        None
    }

    fn differential_fuzzing_terms_to_eval(
        _agents: &Vec<AgentDescriptor<Self::PUTConfig>>,
    ) -> Vec<puffin::algebra::Term<Self>> {
        vec![]
    }

    fn differential_fuzzing_claims_blacklist() -> Option<Vec<TypeId>> {
        None
    }

    fn differential_fuzzing_uniformise_put_config(trace: Trace<Self>) -> Trace<Self> {
        trace
    }

    fn differential_fuzzing_filter_diff(_diff: &puffin::differential::TraceDifference) -> bool {
        true
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct SwissProtocolBehavior;

// Minimal stub types so SwissProtocolBehavior can implement ProtocolBehavior and be used by PutRegistry.
// These are intentionally trivial and only exist to satisfy trait bounds for integration with puffin.

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Comparable)]
pub struct SwissOpaqueMessage;

impl puffin::codec::Codec for SwissOpaqueMessage {
    fn encode(&self, _bytes: &mut Vec<u8>) {}
    fn read(_r: &mut puffin::codec::Reader) -> Option<Self> {
        Some(SwissOpaqueMessage)
    }
}

impl<'a> puffin::protocol::Extractable<SwissProtocolTypes> for SwissOpaqueMessage {
    fn extract_knowledge<'b>(
        &'b self,
        _knowledges: &mut Vec<puffin::trace::Knowledge<'b, SwissProtocolTypes>>,
        _matcher: Option<<SwissProtocolTypes as puffin::protocol::ProtocolTypes>::Matcher>,
        _source: &'b puffin::trace::Source,
    ) -> Result<(), puffin::error::Error> {
        Ok(())
    }
}

impl puffin::protocol::OpaqueProtocolMessage<SwissProtocolTypes> for SwissOpaqueMessage {
    fn debug(&self, _info: &str) {}
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Comparable)]
pub struct SwissOpaqueMessageFlight {
    pub messages: Vec<SwissOpaqueMessage>,
}

impl Default for SwissOpaqueMessageFlight {
    fn default() -> Self {
        Self { messages: vec![] }
    }
}

impl puffin::codec::Codec for SwissOpaqueMessageFlight {
    fn encode(&self, bytes: &mut Vec<u8>) {
        for m in &self.messages {
            m.encode(bytes);
        }
    }

    fn read(r: &mut puffin::codec::Reader) -> Option<Self> {
        let mut msgs = Vec::new();
        while let Some(m) = SwissOpaqueMessage::read(r) {
            msgs.push(m);
        }
        Some(SwissOpaqueMessageFlight { messages: msgs })
    }
}

impl puffin::protocol::OpaqueProtocolMessageFlight<SwissProtocolTypes, SwissOpaqueMessage>
    for SwissOpaqueMessageFlight
{
    fn new() -> Self {
        Self::default()
    }

    fn debug(&self, _info: &str) {}

    fn push(&mut self, msg: SwissOpaqueMessage) {
        self.messages.push(msg);
    }
}

impl From<SwissOpaqueMessage> for SwissOpaqueMessageFlight {
    fn from(m: SwissOpaqueMessage) -> Self {
        SwissOpaqueMessageFlight { messages: vec![m] }
    }
}

impl<'a> puffin::protocol::Extractable<SwissProtocolTypes> for SwissOpaqueMessageFlight {
    fn extract_knowledge<'b>(
        &'b self,
        knowledges: &mut Vec<puffin::trace::Knowledge<'b, SwissProtocolTypes>>,
        matcher: Option<<SwissProtocolTypes as puffin::protocol::ProtocolTypes>::Matcher>,
        source: &'b puffin::trace::Source,
    ) -> Result<(), puffin::error::Error> {
        knowledges.push(puffin::trace::Knowledge {
            source,
            matcher,
            data: self,
        });
        for m in &self.messages {
            m.extract_knowledge(knowledges, None, source)?;
        }
        Ok(())
    }
}

impl puffin::protocol::ProtocolMessage<SwissProtocolTypes, SwissOpaqueMessage>
    for SwissOpaqueMessage
{
    fn create_opaque(&self) -> SwissOpaqueMessage {
        self.clone()
    }

    fn debug(&self, _info: &str) {}
}

impl
    puffin::protocol::ProtocolMessageFlight<
        SwissProtocolTypes,
        SwissOpaqueMessage,
        SwissOpaqueMessage,
        SwissOpaqueMessageFlight,
    > for SwissOpaqueMessageFlight
{
    fn new() -> Self {
        Self::default()
    }

    fn push(&mut self, msg: SwissOpaqueMessage) {
        self.messages.push(msg);
    }

    fn debug(&self, _info: &str) {}
}

// Minimal Claim type
#[derive(Clone, Debug, PartialEq, Comparable, Serialize, Deserialize)]
pub struct SwissClaim;

impl puffin::codec::Codec for SwissClaim {
    fn encode(&self, _bytes: &mut Vec<u8>) {}
    fn read(_r: &mut puffin::codec::Reader) -> Option<Self> {
        Some(SwissClaim)
    }
}

impl<'a> puffin::protocol::Extractable<SwissProtocolTypes> for SwissClaim {
    fn extract_knowledge<'b>(
        &'b self,
        _knowledges: &mut Vec<puffin::trace::Knowledge<'b, SwissProtocolTypes>>,
        _matcher: Option<<SwissProtocolTypes as puffin::protocol::ProtocolTypes>::Matcher>,
        _source: &'b puffin::trace::Source,
    ) -> Result<(), puffin::error::Error> {
        Ok(())
    }
}

impl puffin::claims::Claim for SwissClaim {
    type PT = SwissProtocolTypes;

    fn agent_name(&self) -> puffin::agent::AgentName {
        // use default AgentName for stub
        puffin::agent::AgentName::new()
    }

    fn id(&self) -> puffin::algebra::dynamic_function::TypeShape<SwissProtocolTypes> {
        puffin::algebra::dynamic_function::TypeShape::of::<()>()
    }

    fn inner(&self) -> Box<dyn puffin::protocol::EvaluatedTerm<SwissProtocolTypes>> {
        Box::new(())
    }

    fn set_step(&mut self, _step: Option<puffin::trace::StepNumber>) {}

    fn get_step(&self) -> Option<puffin::trace::StepNumber> {
        None
    }
}

// Minimal SecurityViolationPolicy stub
pub struct SwissSecurityViolationPolicy;
impl puffin::claims::SecurityViolationPolicy for SwissSecurityViolationPolicy {
    type C = SwissClaim;

    fn check_violation(_claims: &[Self::C]) -> Option<&'static str> {
        None
    }
}

impl puffin::protocol::ProtocolBehavior for SwissProtocolBehavior {
    type Claim = SwissClaim;
    type OpaqueProtocolMessage = SwissOpaqueMessage;
    type OpaqueProtocolMessageFlight = SwissOpaqueMessageFlight;
    type ProtocolMessage = SwissOpaqueMessage; // reuse
    type ProtocolMessageFlight = SwissOpaqueMessageFlight;
    type ProtocolTypes = SwissProtocolTypes;
    type SecurityViolationPolicy = SwissSecurityViolationPolicy;

    fn create_corpus(
        _put: puffin::put::PutDescriptor,
    ) -> Vec<(puffin::trace::Trace<SwissProtocolTypes>, &'static str)> {
        println!("Creating corpus for SwissProtocolBehavior");
        let trace = seed_simple_three_terms();
        vec![(trace, "initial-seed")]
    }

    fn try_read_bytes(
        _bitstring: &[u8],
        _ty: std::any::TypeId,
    ) -> Result<Box<dyn puffin::protocol::EvaluatedTerm<SwissProtocolTypes>>, puffin::error::Error>
    {
        Err(puffin::error::Error::Codec(
            "try_read_bytes not implemented".to_string(),
        ))
    }
}
