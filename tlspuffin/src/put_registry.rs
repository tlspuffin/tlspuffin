use puffin::{
    agent::{AgentDescriptor, AgentName},
    algebra::signature::Signature,
    error::Error,
    io::MessageResult,
    protocol::{MessageDeframer, ProtocolBehavior},
    put::{Put, PutDescriptor, PutName},
    put_registry::{Factory, PutRegistry},
    trace::Trace,
    variable_data::VariableData,
};

use crate::{
    claims::TlsClaim,
    extraction::extract_knowledge,
    query::TlsQueryMatcher,
    tls::{seeds::create_corpus, violation::TlsSecurityViolationPolicy, TLS_SIGNATURE},
};

#[derive(Clone)]
pub struct TLSProtocolBehavior;

impl ProtocolBehavior for TLSProtocolBehavior {
    type Claim = TlsClaim;
    type SecurityViolationPolicy = TlsSecurityViolationPolicy;
    type Message = rustls::msgs::message::Message;
    type OpaqueMessage = rustls::msgs::message::OpaqueMessage;
    type MessageDeframer = rustls::msgs::deframer::MessageDeframer;

    type Matcher = TlsQueryMatcher;

    fn signature() -> &'static Signature {
        &TLS_SIGNATURE
    }

    fn registry() -> &'static PutRegistry<Self> {
        &TLS_PUT_REGISTRY
    }

    fn create_corpus() -> Vec<(Trace<Self::Matcher>, &'static str)> {
        Vec::from(create_corpus())
    }

    fn extract_query_matcher(
        message_result: &MessageResult<Self::Message, Self::OpaqueMessage>,
    ) -> Self::Matcher {
        TlsQueryMatcher::try_from(message_result).unwrap()
    }

    fn extract_knowledge(message: &Self::Message) -> Result<Vec<Box<dyn VariableData>>, Error> {
        extract_knowledge(message)
    }
}

pub const OPENSSL111_PUT: PutName = PutName(['O', 'P', 'E', 'N', 'S', 'S', 'L', '1', '1', '1']);
pub const WOLFSSL520_PUT: PutName = PutName(['W', 'O', 'L', 'F', 'S', 'S', 'L', '5', '2', '0']);
pub const TCP_PUT: PutName = PutName(['T', 'C', 'P', '_', '_', '_', '_', '_', '_', '_']);

pub const TLS_PUT_REGISTRY: PutRegistry<TLSProtocolBehavior> = PutRegistry {
    factories: &[
        crate::tcp::new_tcp_factory,
        #[cfg(feature = "openssl-binding")]
        crate::openssl::new_openssl_factory,
        #[cfg(feature = "wolfssl-binding")]
        crate::wolfssl::new_wolfssl_factory,
    ],
    default: DEFAULT_PUT_FACTORY,
};

pub const DEFAULT_PUT_FACTORY: fn() -> Box<dyn Factory<TLSProtocolBehavior>> = {
    cfg_if::cfg_if! {
        if #[cfg(feature = "openssl-binding")] {
            crate::openssl::new_openssl_factory
        } else if #[cfg(feature = "wolfssl-binding")] {
            crate::wolfssl::new_wolfssl_factory
        } else {
             crate::tcp::new_tcp_factory
        }
    }
};
