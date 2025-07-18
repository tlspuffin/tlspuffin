use std::any::{Any, TypeId};
use std::fmt::{Debug, Display};
use std::hash::Hash;

use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::agent::ProtocolDescriptorConfig;
use crate::algebra::signature::Signature;
use crate::algebra::Matcher;
use crate::claims::{Claim, SecurityViolationPolicy};
use crate::codec;
use crate::error::Error;
use crate::put::PutDescriptor;
use crate::trace::{Knowledge, Source, Trace};

pub trait AsAny {
    fn as_any(&self) -> &dyn Any;
}

impl<T: 'static> AsAny for T {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Fill `knowledges` with new knowledge gathered form the type implementing EvaluatedTerm
/// by recursively calling extract_knowledge on all contained element
/// Knowledges can be extracted from using `extract_knowledge`
pub trait Extractable<PT: ProtocolTypes>: std::fmt::Debug + AsAny
where
    Self: 'static,
{
    /// Fill `knowledges` with new knowledge gathered form the type implementing `EvaluatedTerm`
    /// by recursively calling `extract_knowledge` on all contained element
    /// This will put source as the source of all the produced knowledge, matcher is also passed
    /// recursively but might be overwritten by a type with a more specific matcher
    fn extract_knowledge<'a>(
        &'a self,
        knowledges: &mut Vec<Knowledge<'a, PT>>,
        matcher: Option<PT::Matcher>,
        source: &'a Source,
    ) -> Result<(), Error>;
}

/// Implement Extractable for all Vec of types implementing Extractable
impl<PT: ProtocolTypes, T: EvaluatedTerm<PT> + Clone + codec::Codec + 'static> Extractable<PT>
    for Vec<T>
where
    Vec<T>: codec::Codec,
{
    fn extract_knowledge<'a>(
        &'a self,
        knowledges: &mut Vec<Knowledge<'a, PT>>,
        matcher: Option<<PT as ProtocolTypes>::Matcher>,
        source: &'a Source,
    ) -> Result<(), Error> {
        knowledges.push(Knowledge {
            source,
            matcher: matcher.clone(),
            data: self,
        });

        for k in self {
            k.extract_knowledge(knowledges, matcher.clone(), source)?;
        }
        Ok(())
    }
}

/// Implement Extractable for all Option of types implementing Extractable
impl<PT: ProtocolTypes, T: Extractable<PT> + Clone + 'static> Extractable<PT> for Option<T>
where
    Option<T>: codec::Codec,
{
    fn extract_knowledge<'a>(
        &'a self,
        knowledges: &mut Vec<Knowledge<'a, PT>>,
        matcher: Option<<PT as ProtocolTypes>::Matcher>,
        source: &'a Source,
    ) -> Result<(), Error> {
        knowledges.push(Knowledge {
            source,
            matcher: matcher.clone(),
            data: self,
        });

        match self {
            Some(x) => x.extract_knowledge(knowledges, matcher, source)?,
            None => (),
        }
        Ok(())
    }
}

/// `EvaluatedTerm`: have both Codec and a way to extract knowledge out of a Message/OpaqueMessage
/// or any type that might be used in a precomputation
pub trait EvaluatedTerm<PT: ProtocolTypes>:
    codec::CodecP + Extractable<PT> + Debug + AsAny + 'static
where
    Self: 'static,
{
    fn type_id(&self) -> TypeId {
        Any::type_id(self)
    }

    fn type_name(&self) -> &'static str {
        std::any::type_name::<Self>()
    }

    fn boxed(&self) -> Box<dyn EvaluatedTerm<PT>>;
}
impl<T, PT: ProtocolTypes> EvaluatedTerm<PT> for T
where
    T: codec::CodecP + Extractable<PT> + 'static + Clone,
{
    fn boxed(&self) -> Box<dyn EvaluatedTerm<PT>> {
        Box::new(self.clone())
    }
}

/// Store a message flight, a vec of all the messages sent by the PUT between two steps
pub trait ProtocolMessageFlight<
    PT: ProtocolTypes,
    M: ProtocolMessage<PT, O>,
    O: OpaqueProtocolMessage<PT>,
    OF: OpaqueProtocolMessageFlight<PT, O>,
>: Clone + Debug + From<M> + TryFrom<OF> + Into<OF> + EvaluatedTerm<PT>
{
    fn new() -> Self;
    fn push(&mut self, msg: M);
    fn debug(&self, info: &str);
}

/// Store a flight of opaque messages, a vec of all the messages sent by the PUT between two steps
// We require codec::Codec to be able to read a bitstring and produce an owned
// `OpaqueProtocolMessageFlight<PT>` so we use the `Sized` version of `Codec`
pub trait OpaqueProtocolMessageFlight<PT: ProtocolTypes, O: OpaqueProtocolMessage<PT>>:
    Clone + Debug + codec::Codec + From<O> + EvaluatedTerm<PT>
{
    fn new() -> Self;
    fn debug(&self, info: &str);
    fn push(&mut self, msg: O);
}

/// A structured message. This type defines how all possible messages of a protocol.
/// Usually this is implemented using an `enum`.
pub trait ProtocolMessage<PT: ProtocolTypes, O: OpaqueProtocolMessage<PT>>:
    Clone + Debug + EvaluatedTerm<PT>
{
    fn create_opaque(&self) -> O;
    fn debug(&self, info: &str);
}

/// A non-structured version of [`ProtocolMessage`]. This can be used for example for encrypted
/// messages which do not have a structure.
pub trait OpaqueProtocolMessage<PT: ProtocolTypes>: Clone + Debug + EvaluatedTerm<PT> {
    fn debug(&self, info: &str);
}

/// Deframes a stream of bytes into distinct [`OpaqueProtocolMessages`](OpaqueProtocolMessage).
///
/// A deframer is usually state-ful. This means it produces as many messages from the input bytes
/// and stores them.
pub trait ProtocolMessageDeframer<PT: ProtocolTypes> {
    type OpaqueProtocolMessage: OpaqueProtocolMessage<PT>;

    fn pop_frame(&mut self) -> Option<Self::OpaqueProtocolMessage>;
    fn read(&mut self, rd: &mut dyn std::io::Read) -> std::io::Result<usize>;
}

/// Defines the types used to manipulate and concretize Terms
pub trait ProtocolTypes:
    'static + Clone + Hash + Display + Debug + Serialize + DeserializeOwned
{
    type Matcher: Matcher;
    type PUTConfig: ProtocolDescriptorConfig;

    /// Get the signature that is used in the protocol
    fn signature() -> &'static Signature<Self>;
}

/// Defines the protocol which is being tested.
///
/// The fuzzer is generally abstract over the used protocol. We assume that protocols have
/// [opaque messages](ProtocolBehavior::OpaqueProtocolMessage), [structured
/// messages](ProtocolBehavior::ProtocolMessage), and a way to [deframe](ProtocolMessageDeframer) an
/// arbitrary stream of bytes into messages.
///
/// Also the library allows the definition of a type for [claims](Claim) and a
/// (security policy)[`SecurityViolationPolicy`] over
/// sequences of them. Finally, there is a [matcher](Matcher) which allows traces to include
/// queries for [knowledge](crate::trace::Knowledge).
pub trait ProtocolBehavior: 'static {
    type ProtocolTypes: ProtocolTypes;
    type Claim: Claim<PT = Self::ProtocolTypes>;
    type SecurityViolationPolicy: SecurityViolationPolicy<C = Self::Claim>;
    type ProtocolMessage: ProtocolMessage<Self::ProtocolTypes, Self::OpaqueProtocolMessage>;
    type OpaqueProtocolMessage: OpaqueProtocolMessage<Self::ProtocolTypes>;
    type ProtocolMessageFlight: ProtocolMessageFlight<
        Self::ProtocolTypes,
        Self::ProtocolMessage,
        Self::OpaqueProtocolMessage,
        Self::OpaqueProtocolMessageFlight,
    >;
    type OpaqueProtocolMessageFlight: OpaqueProtocolMessageFlight<Self::ProtocolTypes, Self::OpaqueProtocolMessage>
        + From<Self::ProtocolMessageFlight>;

    /// Creates a sane initial seed corpus.
    fn create_corpus(put: PutDescriptor) -> Vec<(Trace<Self::ProtocolTypes>, &'static str)>;

    /// Downcast from `Box<dyn Any>` and encode as bitstring any message as per the PB's internal
    /// structure
    fn any_get_encoding(message: &dyn EvaluatedTerm<Self::ProtocolTypes>) -> Vec<u8> {
        /// Use the `codecP::get_encoding` method to encode any `EvaluatedTerm<PT>`
        codec::CodecP::get_encoding(message)
    }

    /// Try to read a bitstring and interpret it as the `TypeShape`, which is the type of a message
    /// as per the PB's internal structure This is expected to fail for many types of messages!
    fn try_read_bytes(
        bitstring: &[u8],
        ty: TypeId,
    ) -> Result<Box<dyn EvaluatedTerm<Self::ProtocolTypes>>, Error>;
}

// -- Macros --
#[macro_export]
macro_rules! dummy_extract_knowledge {
    ($protocol_type:ty, $extract_type:ty) => {
        impl Extractable<$protocol_type> for $extract_type {
            fn extract_knowledge<'a>(
                &'a self,
                _knowledges: &mut Vec<Knowledge<'a, $protocol_type>>,
                _matcher: Option<<$protocol_type as ProtocolTypes>::Matcher>,
                _source: &'a Source,
            ) -> Result<(), Error> {
                log::warn!(
                    "Trying to extract a dummy type: {}",
                    stringify!($extract_type)
                );
                Ok(())
            }
        }
    };
}

#[macro_export]
macro_rules! dummy_codec {
    ($protocol_type:ty, $extract_type:ty) => {
        impl codec::CodecP for $extract_type {
            fn encode(&self, _bytes: &mut Vec<u8>) {
                log::warn!(
                    "Trying to encode a dummy type: {}",
                    stringify!($extract_type)
                );
            }

            fn read(&mut self, _r: &mut codec::Reader) -> Result<(), Error> {
                log::warn!("Trying to read a dummy type: {}", stringify!($extract_type));
                Ok(())
            }
        }
    };
}

#[macro_export]
macro_rules! dummy_extract_knowledge_codec {
    ($protocol_type:ty, $extract_type:ty) => {
        dummy_extract_knowledge!($protocol_type, $extract_type);
        dummy_codec!($protocol_type, $extract_type);
    };
}

#[macro_export]
macro_rules! atom_extract_knowledge {
    ($protocol_type:ty, $extract_type:ty) => {
        impl Extractable<$protocol_type> for $extract_type {
            fn extract_knowledge<'a>(
                &'a self,
                knowledges: &mut Vec<Knowledge<'a, $protocol_type>>,
                matcher: Option<<$protocol_type as ProtocolTypes>::Matcher>,
                source: &'a Source,
            ) -> Result<(), Error> {
                log::trace!("Extract atom: {}", stringify!($extract_type));
                knowledges.push(Knowledge {
                    source,
                    matcher,
                    data: self,
                });
                Ok(())
            }
        }
    };
}
