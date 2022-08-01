use std::io::Read;

use puffin::{
    algebra::{signature::Signature, AnyMatcher},
    error::Error,
    io::MessageResult,
    protocol::{Message, MessageDeframer, OpaqueMessage, ProtocolBehavior},
    put_registry::PutRegistry,
    trace::Trace,
    variable_data::VariableData,
};

use crate::{
    claim::SshClaim,
    ssh::{
        deframe::SshMessageDeframer,
        message::{
            KexEcdhInitMessage, KexEcdhReplyMessage, KexInitMessage, RawMessage, SshMessage,
            SshMessage::KexEcdhReply,
        },
        SSH_SIGNATURE,
    },
    violation::SshSecurityViolationPolicy,
    SSH_PUT_REGISTRY,
};

#[derive(Clone)]
pub struct SshProtocolBehavior {}

impl ProtocolBehavior for SshProtocolBehavior {
    type Claim = SshClaim;
    type SecurityViolationPolicy = SshSecurityViolationPolicy;
    type Message = SshMessage;
    type OpaqueMessage = RawMessage;
    type MessageDeframer = SshMessageDeframer; // fixme: probably only needed for memory buffer -> remove
    type Matcher = AnyMatcher;

    fn signature() -> &'static Signature {
        &SSH_SIGNATURE
    }

    fn registry() -> &'static PutRegistry<Self>
    where
        Self: Sized,
    {
        &SSH_PUT_REGISTRY
    }

    fn create_corpus() -> Vec<(Trace<Self::Matcher>, &'static str)> {
        vec![] // TODO
    }

    fn extract_query_matcher(
        message_result: &MessageResult<Self::Message, Self::OpaqueMessage>,
    ) -> Self::Matcher {
        AnyMatcher // TODO
    }

    fn extract_knowledge(
        message: &MessageResult<Self::Message, Self::OpaqueMessage>,
    ) -> Result<Vec<Box<dyn VariableData>>, Error> {
        let knowledge: Vec<Box<dyn VariableData>> = match message {
            MessageResult(None, opaque_message) => match opaque_message {
                RawMessage::Banner(banner) => vec![Box::new(banner.clone())],
                RawMessage::Packet(packet) => vec![],
            },
            MessageResult(Some(message), _) => match message {
                SshMessage::KexInit(KexInitMessage {
                    cookie,
                    kex_algorithms,
                    server_host_key_algorithms,
                    encryption_algorithms_server_to_client,
                    encryption_algorithms_client_to_server,
                    mac_algorithms_client_to_server,
                    mac_algorithms_server_to_client,
                    compression_algorithms_client_to_server,
                    compression_algorithms_server_to_client,
                    languages_client_to_server,
                    languages_server_to_client,
                    first_kex_packet_follows,
                }) => {
                    vec![
                        Box::new(cookie.clone()),
                        Box::new(kex_algorithms.clone()),
                        Box::new(server_host_key_algorithms.clone()),
                        Box::new(encryption_algorithms_server_to_client.clone()),
                        Box::new(encryption_algorithms_client_to_server.clone()),
                        Box::new(mac_algorithms_client_to_server.clone()),
                        Box::new(mac_algorithms_server_to_client.clone()),
                        Box::new(compression_algorithms_client_to_server.clone()),
                        Box::new(compression_algorithms_server_to_client.clone()),
                        Box::new(languages_client_to_server.clone()),
                        Box::new(languages_server_to_client.clone()),
                        Box::new(first_kex_packet_follows.clone()),
                    ]
                }
                SshMessage::KexEcdhInit(KexEcdhInitMessage {
                    ephemeral_public_key,
                }) => vec![Box::new(ephemeral_public_key.clone())],
                SshMessage::KexEcdhReply(KexEcdhReplyMessage {
                    public_host_key,
                    ephemeral_public_key,
                    signature,
                }) => vec![
                    Box::new(public_host_key.clone()),
                    Box::new(ephemeral_public_key.clone()),
                    Box::new(signature.clone()),
                ],
            },
        };

        Ok(knowledge)
    }
}
