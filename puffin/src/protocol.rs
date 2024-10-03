use std::fmt::Debug;

use crate::algebra::signature::Signature;
use crate::algebra::Matcher;
use crate::claims::{Claim, SecurityViolationPolicy};
use crate::codec::Codec;
use crate::error::Error;
use crate::trace::{Knowledge, Source, Trace};

/// Provide a way to extract knowledge out of a Message/OpaqueMessage or any type that
/// might be used in a precomputation
pub trait ExtractKnowledge<M: Matcher>: std::fmt::Debug {
    /// Fill `knowledge` with new knowledge gathered form the type implementing ExtractKnowledge
    /// by recursively calling extract_knowledge on all contained element
    /// This will put source as the source of all the produced knowledge, matcher is also passed
    /// recursively but might be overwritten by a type with a more specific matcher
    fn extract_knowledge<'a>(
        &'a self,
        knowledges: &mut Vec<Knowledge<'a, M>>,
        matcher: Option<M>,
        source: &'a Source,
    ) -> Result<(), Error>;
}

/// Store a message flight, a vec of all the messages sent by the PUT between two steps
pub trait ProtocolMessageFlight<
    Mt: Matcher,
    M: ProtocolMessage<Mt, O>,
    O: OpaqueProtocolMessage<Mt>,
    OF: OpaqueProtocolMessageFlight<Mt, O>,
>: Clone + Debug + From<M> + TryFrom<OF> + Into<OF> + ExtractKnowledge<Mt>
{
    fn new() -> Self;
    fn push(&mut self, msg: M);
    fn debug(&self, info: &str);
}

/// Store a flight of opaque messages, a vec of all the messages sent by the PUT between two steps
pub trait OpaqueProtocolMessageFlight<Mt: Matcher, O: OpaqueProtocolMessage<Mt>>:
    Clone + Debug + Codec + From<O> + ExtractKnowledge<Mt>
{
    fn new() -> Self;
    fn debug(&self, info: &str);
    fn push(&mut self, msg: O);
}

/// A structured message. This type defines how all possible messages of a protocol.
/// Usually this is implemented using an `enum`.
pub trait ProtocolMessage<Mt: Matcher, O: OpaqueProtocolMessage<Mt>>:
    Clone + Debug + ExtractKnowledge<Mt>
{
    fn create_opaque(&self) -> O;
    fn debug(&self, info: &str);
}

/// A non-structured version of [`ProtocolMessage`]. This can be used for example for encrypted
/// messages which do not have a structure.
pub trait OpaqueProtocolMessage<Mt: Matcher>: Clone + Debug + Codec + ExtractKnowledge<Mt> {
    fn debug(&self, info: &str);
}

/// Deframes a stream of bytes into distinct [OpaqueProtocolMessages](OpaqueProtocolMessage).
/// A deframer is usually state-ful. This means it produces as many messages from the input bytes
/// and stores them.
pub trait ProtocolMessageDeframer<Mt: Matcher> {
    type OpaqueProtocolMessage: OpaqueProtocolMessage<Mt>;

    fn pop_frame(&mut self) -> Option<Self::OpaqueProtocolMessage>;
    fn read(&mut self, rd: &mut dyn std::io::Read) -> std::io::Result<usize>;
}

/// Defines the protocol which is being tested.
///
/// The fuzzer is generally abstract over the used protocol. We assume that protocols have
/// [opaque messages](ProtocolBehavior::OpaqueProtocolMessage), [structured
/// messages](ProtocolBehavior::ProtocolMessage), and a way to [deframe](ProtocolMessageDeframer) an
/// arbitrary stream of bytes into messages.
///
/// Also the library allows the definition of a type for [claims](Claim) and a
/// (security policy)[SecurityViolationPolicy] over
/// sequences of them. Finally, there is a [matcher](Matcher) which allows traces to include
/// queries for [knowledge](crate::trace::Knowledge).
pub trait ProtocolBehavior: 'static {
    type Matcher: Matcher;
    type Claim: Claim;
    type SecurityViolationPolicy: SecurityViolationPolicy<Self::Claim>;

    type ProtocolMessage: ProtocolMessage<Self::Matcher, Self::OpaqueProtocolMessage>;
    type OpaqueProtocolMessage: OpaqueProtocolMessage<Self::Matcher>;
    type ProtocolMessageFlight: ProtocolMessageFlight<
        Self::Matcher,
        Self::ProtocolMessage,
        Self::OpaqueProtocolMessage,
        Self::OpaqueProtocolMessageFlight,
    >;
    type OpaqueProtocolMessageFlight: OpaqueProtocolMessageFlight<Self::Matcher, Self::OpaqueProtocolMessage>
        + From<Self::ProtocolMessageFlight>;

    /// Get the signature that is used in the protocol
    fn signature() -> &'static Signature;

    /// Creates a sane initial seed corpus.
    fn create_corpus() -> Vec<(Trace<Self::Matcher>, &'static str)>;
}
