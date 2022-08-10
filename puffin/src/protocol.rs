use std::fmt::Debug;

use crate::{
    algebra::{signature::Signature, Matcher},
    claims::{Claim, SecurityViolationPolicy},
    codec::Codec,
    error::Error,
    put_registry::PutRegistry,
    stream::MessageResult,
    trace::Trace,
    variable_data::VariableData,
};

/// A structured message. This type defines how all possible messages of a protocol.
/// Usually this is implemented using an `enum`.
pub trait ProtocolMessage<O: OpaqueProtocolMessage>: Clone + Debug + Codec {
    fn create_opaque(&self) -> O;
    fn debug(&self, info: &str);
}

/// A non-structured version of [`ProtocolMessage`]. This can be used for example for encrypted messages
/// which do not have a structure.
pub trait OpaqueProtocolMessage: Clone + Debug + Codec {
    fn debug(&self, info: &str);
}

/// Deframes a stream of bytes into distinct [OpaqueProtocolMessages](OpaqueProtocolMessage).
/// A deframer is usually state-ful. This means it produces as many messages from the input bytes
/// and stores them.
pub trait MessageDeframer<M: ProtocolMessage<O>, O: OpaqueProtocolMessage> {
    fn new() -> Self;
    fn pop_frame(&mut self) -> Option<O>;
    fn encode(&self) -> Vec<u8>;
    fn read(&mut self, rd: &mut dyn std::io::Read) -> std::io::Result<usize>;
}

/// Defines the protocol which is being tested.
/// The fuzzer is generally abstract over the used protocol. We assume that protocols have
/// [opaque messages](OpaqueMessage), [structured messages](Message),
/// and a way to [deframe](MessageDeframer) an arbitrary stream of bytes into messages.
///
/// Also the library allows the definition of a type for [claims](Claim) and a
/// (security policy)[SecurityViolationPolicy] over
/// sequences of them. Finally, there is a [matcher](Matcher) which allows traces to include
/// queries for [knowledge](crate::trace::Knowledge).
pub trait ProtocolBehavior: 'static {
    type Claim: Claim;
    type SecurityViolationPolicy: SecurityViolationPolicy<Self::Claim>;

    type ProtocolMessage: ProtocolMessage<Self::OpaqueProtocolMessage>;
    type OpaqueProtocolMessage: OpaqueProtocolMessage;
    type MessageDeframer: MessageDeframer<Self::ProtocolMessage, Self::OpaqueProtocolMessage>;

    type Matcher: Matcher;

    /// Get the signature which is used in the protocol
    fn signature() -> &'static Signature;

    /// Gets the registry for concrete programs-under-test.
    fn registry() -> &'static PutRegistry<Self>
    where
        Self: Sized;

    /// Creates a sane initial seed corpus.
    fn create_corpus() -> Vec<(Trace<Self::Matcher>, &'static str)>;

    /// Creates a [`M̀atcher`] which matches the supplied [`MessageResult`].
    fn extract_query_matcher(
        message_result: &MessageResult<Self::ProtocolMessage, Self::OpaqueProtocolMessage>,
    ) -> Self::Matcher;

    /// Extracts as much data from the message as possible. Depending on the protocol,
    /// the extraction can be more fine-grained to more coarse.
    fn extract_knowledge(
        message: &MessageResult<Self::ProtocolMessage, Self::OpaqueProtocolMessage>,
    ) -> Result<Vec<Box<dyn VariableData>>, Error>;
}
