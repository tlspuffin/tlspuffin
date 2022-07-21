use puffin::{
    agent::{AgentDescriptor, AgentName},
    algebra::signature::Signature,
    claims::Policy,
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
    tls::{seeds::create_corpus, violation::is_violation, TLS_SIGNATURE},
};

#[derive(Clone)]
pub struct TLSProtocolBehavior;

impl ProtocolBehavior for TLSProtocolBehavior {
    type Claim = TlsClaim;
    type Message = rustls::msgs::message::Message;
    type OpaqueMessage = rustls::msgs::message::OpaqueMessage;
    type MessageDeframer = rustls::msgs::deframer::MessageDeframer;
    type QueryMatcher = TlsQueryMatcher;

    fn policy() -> Policy<Self::Claim> {
        Policy { func: is_violation }
    }

    fn extract_knowledge(message: &Self::Message) -> Result<Vec<Box<dyn VariableData>>, Error> {
        extract_knowledge(message)
    }

    fn signature() -> &'static Signature {
        &TLS_SIGNATURE
    }

    fn create_corpus() -> Vec<(Trace<Self::QueryMatcher>, &'static str)> {
        Vec::from(create_corpus())
    }

    fn registry() -> &'static PutRegistry<Self> {
        &TLS_PUT_REGISTRY
    }

    fn extract_query_matcher(
        message_result: &MessageResult<Self::Message, Self::OpaqueMessage>,
    ) -> Self::QueryMatcher {
        TlsQueryMatcher::try_from(message_result).unwrap()
    }
}

pub const OPENSSL111_PUT: PutName = PutName(['O', 'P', 'E', 'N', 'S', 'S', 'L', '1', '1', '1']);
pub const WOLFSSL520_PUT: PutName = PutName(['W', 'O', 'L', 'F', 'S', 'S', 'L', '5', '2', '0']);
pub const TCP_CLIENT_PUT: PutName = PutName(['T', 'C', 'P', 'C', 'L', 'I', 'E', 'N', 'T', '_']);
pub const TCP_SERVER_PUT: PutName = PutName(['T', 'C', 'P', 'S', 'E', 'R', 'V', 'E', 'R', '_']);

pub const TLS_PUT_REGISTRY: PutRegistry<TLSProtocolBehavior> = PutRegistry {
    factories: &[
        crate::tcp::new_tcp_client_factory,
        crate::tcp::new_tcp_server_factory,
        #[cfg(feature = "openssl-binding")]
        crate::openssl::new_openssl_factory,
        #[cfg(feature = "wolfssl-binding")]
        crate::wolfssl::new_wolfssl_factory,
    ],
};

pub const CURRENT_PUT_NAME: PutName = {
    cfg_if::cfg_if! {
        if #[cfg(feature = "openssl-binding")] {
            OPENSSL111_PUT
        } else if #[cfg(feature = "wolfssl-binding")] {
            WOLFSSL520_PUT
        } else {
            puffin::put_registry::DUMMY_PUT
        }
    }
};

pub fn current_put() -> PutDescriptor {
    PutDescriptor {
        name: CURRENT_PUT_NAME,
        ..PutDescriptor::default()
    }
}
