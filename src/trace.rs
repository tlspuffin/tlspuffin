use std::any::Any;
use std::io::Write;

use rustls::internal::msgs::codec::Codec;
use rustls::internal::msgs::enums::ContentType::Handshake as RecordHandshake;
use rustls::internal::msgs::enums::HandshakeType;
use rustls::internal::msgs::handshake::{
    ClientHelloPayload, HandshakeMessagePayload, HandshakePayload,
};
use rustls::internal::msgs::message::Message;
use rustls::internal::msgs::message::MessagePayload::Handshake;
use rustls::ProtocolVersion;

use crate::agent::{Agent, AgentName};
use crate::debug::debug_message;
use crate::io::Outgoing;
use crate::variable::{
    CipherSuiteData, ClientVersionData, CompressionData, ExtensionData, RandomData, SessionIDData,
    VariableData,
};

pub struct TraceContext {
    variables: Vec<Box<dyn VariableData>>,
    agents: Vec<Agent>,
}

impl TraceContext {
    pub fn new() -> TraceContext {
        TraceContext {
            variables: vec![],
            agents: vec![],
        }
    }

    pub fn add_variable(&mut self, data: Box<dyn VariableData>) {
        self.variables.push(data)
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

    pub fn send(&mut self, to: AgentName, buf: &dyn AsRef<[u8]>) {
        let mut iter = self.agents.iter_mut();

        if let Some(to_agent) = iter.find(|agent| agent.name == to) {
            to_agent.stream.extend_incoming(buf.as_ref());
        }
    }

    pub fn receive(&mut self, from: AgentName) -> Result<Outgoing<'_>, String> {
        let mut iter = self.agents.iter_mut();

        if let Some(from_agent) = iter.find(|agent| agent.name == from) {
            return Ok(from_agent.stream.take_outgoing());
        }

        Err(format!("Could not find agent {}", from))
    }

    pub fn new_agent(&mut self) -> AgentName {
        let agent = Agent::new();
        let name = agent.name;
        self.agents.push(agent);
        return name;
    }

    pub fn new_openssl_agent(&mut self) -> AgentName {
        let agent = Agent::new_openssl();
        let name = agent.name;
        self.agents.push(agent);
        return name;
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

pub struct Step<'a> {
    pub from: AgentName,
    pub to: AgentName,
    pub action: &'a (dyn Action + 'static),
}

pub trait Action {
    fn execute(&self, step: &Step, ctx: &mut TraceContext);
}

pub trait SendAction: Action {
    fn craft(&self, ctx: &TraceContext, agent: AgentName) -> Result<Vec<u8>, ()>;
}

pub trait ExpectAction: Action {
    fn get_concrete_variables(&self) -> Vec<String>; // Variables and the actual values
}

// ServerHello

pub struct ServerHelloExpectAction {}

impl Action for ServerHelloExpectAction {
    fn execute(&self, step: &Step, ctx: &mut TraceContext) {
        match ctx.receive(step.from) {
            Ok(buffer) => {
                debug_message(&buffer);
            }
            Err(msg) => {
                panic!("{}", msg)
            }
        }
    }
}

impl ServerHelloExpectAction {
    pub fn new() -> ServerHelloExpectAction {
        ServerHelloExpectAction {}
    }
}

impl ExpectAction for ClientHelloSendAction {
    fn get_concrete_variables(&self) -> Vec<String> {
        todo!()
    }
}

// ClientHello

pub struct ClientHelloSendAction {}

impl Action for ClientHelloSendAction {
    fn execute(&self, step: &Step, ctx: &mut TraceContext) {
        let result = self.craft(ctx, step.from);

        match result {
            Ok(buffer) => {
                debug_message(&buffer);
                ctx.send(step.to, &buffer);
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
    pub fn new() -> ClientHelloSendAction {
        ClientHelloSendAction {}
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
            ctx.get_variable::<ClientVersionData>(agent),
            ctx.get_variable::<RandomData>(agent),
            ctx.get_variable::<SessionIDData>(agent),
            ctx.get_variable_set::<CipherSuiteData>(agent),
            ctx.get_variable_set::<CompressionData>(agent),
            ctx.get_variable_set::<ExtensionData>(agent),
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
