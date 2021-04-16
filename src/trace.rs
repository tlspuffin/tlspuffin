use rustls::internal::msgs::codec::Codec;
use rustls::internal::msgs::enums::ContentType::Handshake as RecordHandshake;
use rustls::internal::msgs::enums::{AlertLevel, HandshakeType};
use rustls::internal::msgs::handshake::{
    ClientHelloPayload, HandshakeMessagePayload, HandshakePayload,
};
use rustls::internal::msgs::message::Message;
use rustls::internal::msgs::message::MessagePayload::Handshake;
use rustls::ProtocolVersion;

use crate::agent::{Agent, AgentName};
use crate::debug::debug_message;
use crate::openssl_server;
use crate::openssl_server::openssl_version;
use crate::variable::{
    CipherSuiteData, ClientVersionData, CompressionData, ExtensionData, RandomData, SessionIDData,
    VariableData,
};
use crate::io::MemoryStream;

pub struct TraceContext {
    variables: Vec<Box<dyn VariableData>>,
    agents: Vec<Agent>,
}

impl TraceContext {
    pub fn new() -> TraceContext {
        TraceContext { variables: vec![], agents: vec![] }
    }

    pub fn add_variable(&mut self, data: Box<dyn VariableData>) {
        self.variables.push(data)
    }

    fn downcast<T: 'static>(variable: &Box<dyn VariableData>) -> Option<&T> {
        (**variable).as_any().downcast_ref::<T>()
    }

    fn get_variable<T: 'static>(&self) -> Option<&T> {
        for variable in self.variables.as_slice() {
            if let Some(derived) = TraceContext::downcast(variable) {
                return Some(derived);
            }
        }
        None
    }

    fn get_variable_set<T: 'static>(&self) -> Vec<&T> {
        let mut variables: Vec<&T> = Vec::new();
        for variable in self.variables.as_slice() {
            if let Some(derived) = TraceContext::downcast(variable) {
                variables.push(derived);
            }
        }
        variables
    }

    pub fn publish(&mut self, sending_agent_name: AgentName, data: &dyn AsRef<[u8]>) {
        for agent in self.agents.iter_mut() {
            if agent.name != sending_agent_name {
                agent.stream.extend_incoming(data.as_ref());
            }
        }
    }

    pub fn new_agent(&mut self) -> AgentName {
        let agent = Agent::new();
        let name = agent.name;
        self.agents.push(agent);
        return name;
    }
}

pub struct Trace {
    pub steps: Vec<Box<dyn Step>>
}

impl Trace {
    pub fn execute(&mut self, ctx: &mut TraceContext) {
        for step in self.steps.iter_mut() {
            step.execute(ctx);
        }
    }
}

pub trait Step {
    fn execute(&mut self, ctx: &mut TraceContext);
}

pub trait SendStep: Step {
    fn craft(&self, ctx: &TraceContext) -> Result<Vec<u8>, ()>;
}

pub enum ExpectType {
    Alert(AlertLevel),
    Handshake(HandshakeType),
}

pub trait ExpectStep: Step {
    fn get_type(&self) -> ExpectType;
    fn get_concrete_variables(&self) -> Vec<String>; // Variables and the actual values
}

// ServerHello

pub struct ServerHelloExpectStep {
}

impl Step for ServerHelloExpectStep {
    fn execute(&mut self, ctx: &mut TraceContext) {
        // TODO
        // let buffer = ctx.receive_from_previous();
        // openssl_server::process(ssl_stream)
    }
}

impl ServerHelloExpectStep {
    pub fn new(agent: AgentName) -> ServerHelloExpectStep {
        ServerHelloExpectStep { }
    }
}

impl ExpectStep for ClientHelloSendStep {
    fn get_type(&self) -> ExpectType {
        todo!()
    }

    fn get_concrete_variables(&self) -> Vec<String> {
        todo!()
    }
}

// ClientHello

pub struct ClientHelloSendStep {
    pub agent: AgentName,
}

impl Step for ClientHelloSendStep {
    fn execute(&mut self, ctx: &mut TraceContext) {
        let result = self.craft(ctx);

        match result {
            Ok(buffer) => {
                debug_message(&buffer);
                //ctx.publish(self.agent, &buffer);
            }
            _ => {
                println!("Error");
            }
        }
    }
}

impl ClientHelloSendStep {
    pub fn new(agent: AgentName) -> ClientHelloSendStep {
        ClientHelloSendStep { agent }
    }
}

impl SendStep for ClientHelloSendStep {
    fn craft(&self, ctx: &TraceContext) -> Result<Vec<u8>, ()> {
        return if let (
            Some(client_version),
            Some(random),
            Some(session_id),
            ciphersuits,
            compression_methods,
            extensions,
        ) = (
            ctx.get_variable::<ClientVersionData>(),
            ctx.get_variable::<RandomData>(),
            ctx.get_variable::<SessionIDData>(),
            ctx.get_variable_set::<CipherSuiteData>(),
            ctx.get_variable_set::<CompressionData>(),
            ctx.get_variable_set::<ExtensionData>(),
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

            let mut out: Vec<u8> = Vec::new();
            message.encode(&mut out);
            Ok(out)
        } else {
            Err(())
        };
    }
}
