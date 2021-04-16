use rustls::internal::msgs::codec::Codec;
use rustls::internal::msgs::enums::{AlertLevel, HandshakeType};
use rustls::internal::msgs::enums::ContentType::Handshake as RecordHandshake;
use rustls::internal::msgs::handshake::{
    ClientHelloPayload, HandshakeMessagePayload, HandshakePayload,
};
use rustls::internal::msgs::message::Message;
use rustls::internal::msgs::message::MessagePayload::Handshake;
use rustls::ProtocolVersion;

use crate::variable::{
    CipherSuiteData, ClientVersionData, CompressionData, ExtensionData, RandomData,
    SessionIDData, VariableData,
};

pub struct TraceContext {
    variables: Vec<Box<dyn VariableData>>,
}

impl TraceContext {
    pub fn new() -> TraceContext {
        TraceContext { variables: vec![] }
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
}

pub struct Trace {
    pub steps: Vec<Box<dyn Step>>,
}

impl Trace {
    pub fn execute(&self, ctx: &TraceContext) -> Vec<u8> {
        let mut buffer = Vec::new();
        for step in self.steps.iter() {
            buffer.extend(step.execute(ctx));
        }

        buffer
    }
}

pub trait Step {
    fn execute(&self, ctx: &TraceContext) -> Vec<u8>;
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

pub struct ServerHelloExpectStep {}

impl Step for ServerHelloExpectStep {
    fn execute(&self, ctx: &TraceContext) -> Vec<u8> {
        todo!()
    }
}

impl ServerHelloExpectStep {
    pub fn new() -> Self {
        ServerHelloExpectStep {}
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

pub struct ClientHelloSendStep {}

impl Step for ClientHelloSendStep {
    fn execute(&self, ctx: &TraceContext) -> Vec<u8> {
        let result = self.craft(ctx);

        match result {
            Ok(buffer) => {
                //print_as_message(&buffer);
                buffer
            }
            _ => {
                println!("Error");
                vec![]
            }
        }
    }
}

impl ClientHelloSendStep {
    pub fn new() -> ClientHelloSendStep {
        ClientHelloSendStep {}
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
