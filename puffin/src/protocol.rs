use std::fmt::Debug;

use crate::{
    algebra::{signature::Signature, Matcher},
    claims::{Claim, SecurityViolationPolicy},
    error::Error,
    io::MessageResult,
    put_registry::PutRegistry,
    trace::Trace,
    variable_data::VariableData,
};

/// A structured message. This type defines how all possible messages of a protocol.
/// Usually this is implemented using an `enum`.
pub trait Message<O: OpaqueMessage<Self>>: Clone + Debug {
    fn create_opaque(&self) -> O;
    fn debug(&self, info: &str);
}

/// A non-structured version of [`Message`]. This can be used for example for encrypted messages
/// which do not have a structure.
pub trait OpaqueMessage<M: Message<Self>>: Clone + Debug {
    fn encode(&self) -> Vec<u8>;
    fn into_message(self) -> Result<M, Error>;
    fn debug(&self, info: &str);
}

/// Deframes a stream of bytes into distinct [OpaqueMessages](OpaqueMessage).
/// A deframer is usually state-ful. This means it produces as many messages from the input bytes
/// and stores them.
pub trait MessageDeframer<M: Message<O>, O: OpaqueMessage<M>> {
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

    type Message: Message<Self::OpaqueMessage>;
    type OpaqueMessage: OpaqueMessage<Self::Message>;
    type MessageDeframer: MessageDeframer<Self::Message, Self::OpaqueMessage>;

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
        message_result: &MessageResult<Self::Message, Self::OpaqueMessage>,
    ) -> Self::Matcher;

    /// Extracts as much data from the message as possible. Depending on the protocol,
    /// the extraction can be more fine-grained to more coarse.
    fn extract_knowledge(
        message: &MessageResult<Self::Message, Self::OpaqueMessage>,
    ) -> Result<Vec<Box<dyn VariableData>>, Error>;
}
