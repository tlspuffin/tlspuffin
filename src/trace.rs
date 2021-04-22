use core::fmt;
use std::any::Any;

use openssl::symm::Cipher;
use rustls::internal::msgs::codec::Codec;
use rustls::internal::msgs::enums::ContentType::Handshake as RecordHandshake;
use rustls::internal::msgs::enums::{Compression, HandshakeType};
use rustls::internal::msgs::handshake::{
    ClientExtension, ClientHelloPayload, HandshakeMessagePayload, HandshakePayload,
    ServerExtension, SessionID,
};
use rustls::internal::msgs::message::Message;
use rustls::internal::msgs::message::MessagePayload::Handshake;
use rustls::{CipherSuite, ProtocolVersion};

use crate::agent::{Agent, AgentName};
use crate::debug::{debug_message, debug_message_with_info};
use crate::variable::{
    AgreedCipherSuiteData, AgreedCompressionData, CipherSuiteData, ClientExtensionData,
    CompressionData, Metadata, RandomData, ServerExtensionData, SessionIDData, VariableData,
    VersionData,
};
#[allow(unused)] // used in docs
use crate::io::Channel;

pub struct TraceContext {
    variables: Vec<Box<dyn VariableData>>,
    agents: Vec<Agent>,
}

impl TraceContext {
    pub fn new() -> Self {
        Self {
            variables: vec![],
            agents: vec![],
        }
    }

    pub fn add_variable(&mut self, variable: Box<dyn VariableData>) {
        self.variables.push(variable)
    }

    pub fn add_variables<I>(&mut self, variables: I)
    where
        I: IntoIterator<Item = Box<dyn VariableData>>,
    {
        for variable in variables {
            self.add_variable(variable)
        }
    }

    // Why do we need to extend Any here? do we need to make sure that the types T are known during
    // compile time?
    fn downcast<T: Any>(variable: &dyn AsRef<dyn VariableData>) -> Option<&T> {
        variable.as_ref().as_any().downcast_ref::<T>()
    }

    pub fn get_variable<T: Any>(&self, agent: AgentName) -> Option<&T> {
        for variable in &self.variables {
            if variable.get_metadata().owner != agent {
                continue;
            }

            if let Some(derived) = TraceContext::downcast(variable) {
                return Some(derived);
            }
        }
        None
    }

    pub fn get_variable_set<T: Any>(&self, agent: AgentName) -> Vec<&T> {
        let mut variables: Vec<&T> = Vec::new();
        for variable in &self.variables {
            if variable.get_metadata().owner != agent {
                continue;
            }

            if let Some(derived) = TraceContext::downcast(variable) {
                variables.push(derived);
            }
        }
        variables
    }

    /// Adds data to the inbound [`Channel`] of the [`Agent`] referenced by the parameter "to".
    pub fn add_to_inbound(&mut self, to: AgentName, buf: &dyn AsRef<[u8]>) {
        let mut iter = self.agents.iter_mut();

        if let Some(to_agent) = iter.find(|agent| agent.name == to) {
            to_agent.stream.add_to_inbound(buf.as_ref());
        }
    }

    /// Takes data from the outbound [`Channel`] of the [`Agent`] referenced by the parameter "from".
    pub fn take_from_outbound(&mut self, from: AgentName) -> Result<Vec<u8>, String> {
        let mut iter = self.agents.iter_mut();

        if let Some(from_agent) = iter.find(|agent| agent.name == from) {
            return from_agent
                .stream
                .take_from_outbound()
                .ok_or::<String>("Failed to take data from inbound channel".to_string());
        }

        Err(format!("Could not find agent {}", from))
    }

    fn add_agent(&mut self, agent: Agent) -> AgentName {
        let name = agent.name;
        self.agents.push(agent);
        return name;
    }

    pub fn new_agent(&mut self) -> AgentName {
        return self.add_agent(Agent::new());
    }

    pub fn new_openssl_agent(&mut self, server: bool) -> AgentName {
        return self.add_agent(Agent::new_openssl(server));
    }
}

pub struct Trace<'a> {
    pub steps: Vec<Step<'a>>,
}

impl<'a> Trace<'a> {
    pub fn execute(&mut self, ctx: &mut TraceContext) {
        for step in self.steps.iter_mut() {
            step.action.execute(step, ctx);
        }
    }
}

impl fmt::Display for Trace<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}\n", "Trace:")?;
        for step in &self.steps {
            let expect = step.action.to_string().to_lowercase().contains("expect"); // TODO, add api
            write!(
                f,
                "{} {} {}\t({})\n",
                step.from,
                if expect { "🠐" } else { "🠒" }, // expect sends data back therefore invert arrow
                step.to,
                step.action
            )?;
        }
        Ok(())
    }
}

pub struct Step<'a> {
    /// * If action is a SendAction: The Agent from which the message is sent.
    /// * If action is a ExpectAction: The Agent from which we expect the message.
    pub from: AgentName,
    /// * If action is a SendAction: The Agent which will receive the message.
    /// * If action is a ExpectAction: The Agent which expects the message.
    pub to: AgentName,
    pub action: &'a (dyn Action + 'static),
}

pub trait Action: fmt::Display {
    fn execute(&self, step: &Step, ctx: &mut TraceContext);
}

pub trait SendAction: Action {
    fn craft(&self, ctx: &TraceContext, agent: AgentName) -> Result<Vec<u8>, ()>;
}

pub trait ExpectAction: Action {
    fn expect(&self, step: &Step, ctx: &mut TraceContext);
}

// parsing utils

pub fn receive_handshake_payload(step: &Step, ctx: &mut TraceContext) -> Option<HandshakePayload> {
    let option = match ctx.take_from_outbound(step.to) {
        Ok(buffer) => {
            debug_message_with_info("Received", &buffer);

            if let Some(mut message) = Message::read_bytes(&buffer) {
                message.decode_payload();

                match message.payload {
                    Handshake(payload) => Some((buffer, payload.payload)),
                    _ => None,
                }
            } else {
                // decoding failed
                None
            }
        }
        Err(msg) => {
            panic!("{}", msg)
        }
    };

    if let Some((buffer, payload)) = option {
        ctx.add_to_inbound(step.from, &buffer);
        return Some(payload);
    }

    return None;
}

// Expect ServerHello

pub struct ServerHelloExpectAction {}

impl fmt::Display for ServerHelloExpectAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", "Expect ServerHello")
    }
}

impl Action for ServerHelloExpectAction {
    fn execute(&self, step: &Step, ctx: &mut TraceContext) {
        self.expect(step, ctx);
    }
}

impl ServerHelloExpectAction {
    pub fn new() -> Self {
        Self {}
    }
}

impl ExpectAction for ServerHelloExpectAction {
    fn expect(&self, step: &Step, ctx: &mut TraceContext) {
        if let Some(HandshakePayload::ServerHello(payload)) = receive_handshake_payload(step, ctx) {
            let owner = step.from; // corresponds to the OpenSSL client usually

            ctx.add_variables(
                payload
                    .extensions
                    .iter()
                    .map(|extension: &ServerExtension| {
                        Box::new(ServerExtensionData::static_extension(
                            owner,
                            extension.clone(),
                        )) as Box<dyn VariableData> // it is important to cast here: https://stackoverflow.com/questions/48180008/how-can-i-box-the-contents-of-an-iterator-of-a-type-that-implements-a-trait
                    })
                    .chain::<Vec<Box<dyn VariableData>>>(vec![
                        Box::new(RandomData {
                            metadata: Metadata { owner },
                            data: payload.random,
                        }),
                        Box::new(AgreedCipherSuiteData {
                            metadata: Metadata { owner },
                            data: payload.cipher_suite,
                        }),
                        Box::new(AgreedCompressionData {
                            metadata: Metadata { owner },
                            data: payload.compression_method,
                        }),
                        Box::new(VersionData {
                            metadata: Metadata { owner },
                            data: payload.legacy_version,
                        }),
                    ])
                    .collect::<Vec<Box<dyn VariableData>>>(),
            );
        } else {
            // no ServerHello or decoding failed
        }
    }
}

// ClientHello

pub struct ClientHelloSendAction {}

impl fmt::Display for ClientHelloSendAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", "Send ClientHello")
    }
}

impl Action for ClientHelloSendAction {
    fn execute(&self, step: &Step, ctx: &mut TraceContext) {
        let result = self.craft(ctx, step.from);

        match result {
            Ok(buffer) => {
                debug_message(&buffer);
                ctx.add_to_inbound(step.to, &buffer);
            }
            _ => {
                error!(
                    "Unable to craft message in {:?}",
                    std::any::type_name::<Self>()
                );
            }
        }
    }
}

impl ClientHelloSendAction {
    pub fn new() -> Self {
        Self {}
    }
}

impl SendAction for ClientHelloSendAction {
    fn craft(&self, ctx: &TraceContext, agent: AgentName) -> Result<Vec<u8>, ()> {
        return if let (
            Some(client_version),
            Some(random),
            Some(session_id),
            ciphersuits,
            compression_methods,
            extensions,
        ) = (
            ctx.get_variable::<VersionData>(agent),
            ctx.get_variable::<RandomData>(agent),
            ctx.get_variable::<SessionIDData>(agent),
            ctx.get_variable_set::<CipherSuiteData>(agent),
            ctx.get_variable_set::<CompressionData>(agent),
            ctx.get_variable_set::<ClientExtensionData>(agent),
        ) {
            let payload = Handshake(HandshakeMessagePayload {
                typ: HandshakeType::ClientHello,
                payload: HandshakePayload::ClientHello(ClientHelloPayload {
                    client_version: client_version.data,
                    random: random.data.clone(),
                    session_id: session_id.data,
                    cipher_suites: ciphersuits.into_iter().map(|c| c.data).collect(),
                    compression_methods: compression_methods.into_iter().map(|c| c.data).collect(),
                    extensions: extensions.into_iter().map(|c| c.data.clone()).collect(),
                }),
            });
            let message = Message {
                typ: RecordHandshake,
                version: ProtocolVersion::TLSv1_3,
                payload,
            };

            let mut buffer: Vec<u8> = Vec::new();
            message.encode(&mut buffer);
            Ok(buffer)
        } else {
            Err(())
        };
    }
}

// Expect ClientHello

pub struct ClientHelloExpectAction {}

impl fmt::Display for ClientHelloExpectAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", "Expect ClientHello")
    }
}

impl Action for ClientHelloExpectAction {
    fn execute(&self, step: &Step, ctx: &mut TraceContext) {
        self.expect(step, ctx);
    }
}

impl ClientHelloExpectAction {
    pub fn new() -> Self {
        Self {}
    }
}

impl ExpectAction for ClientHelloExpectAction {
    fn expect(&self, step: &Step, ctx: &mut TraceContext) {
        if let Some(HandshakePayload::ClientHello(payload)) = receive_handshake_payload(step, ctx) {
            let owner = step.from;

            let simple_variables: Vec<Box<dyn VariableData>> = vec![
                Box::new(RandomData {
                    metadata: Metadata { owner },
                    data: payload.random,
                }),
                Box::new(SessionIDData {
                    metadata: Metadata { owner },
                    data: payload.session_id,
                }),
                Box::new(VersionData {
                    metadata: Metadata { owner },
                    data: payload.client_version,
                }),
            ];
            ctx.add_variables(
                simple_variables
                    .into_iter()
                    .chain(
                        payload
                            .extensions
                            .iter()
                            .map(|extension: &ClientExtension| {
                                Box::new(ClientExtensionData::static_extension(
                                    owner,
                                    extension.clone(),
                                )) as Box<dyn VariableData>
                            }),
                    )
                    .chain(
                        payload
                            .compression_methods
                            .iter()
                            .map(|compression: &Compression| {
                                Box::new(CompressionData::static_extension(
                                    owner,
                                    compression.clone(),
                                )) as Box<dyn VariableData>
                            }),
                    )
                    .chain(
                        payload
                            .cipher_suites
                            .iter()
                            .map(|cipher_suite: &CipherSuite| {
                                Box::new(CipherSuiteData::static_extension(
                                    owner,
                                    cipher_suite.clone(),
                                )) as Box<dyn VariableData>
                            }),
                    )
                    .collect::<Vec<Box<dyn VariableData>>>(),
            );
        } else {
            // no ServerHello or decoding failed
        }
    }
}
