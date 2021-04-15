use crate::variable::{AsAny, CipherSuiteData, ClientVersionData, CompressionData, RandomData, SessionIDData, VariableData, ExtensionData};
use rustls::internal::msgs::codec::Codec;
use rustls::internal::msgs::enums::ContentType::Handshake as RecordHandshake;
use rustls::internal::msgs::enums::ProtocolVersion::TLSv1_2;
use rustls::internal::msgs::enums::{AlertLevel, Compression, HandshakeType};
use rustls::internal::msgs::handshake::{
    ClientExtension, ClientHelloPayload, HandshakeMessagePayload, HandshakePayload, Random,
    SessionID,
};
use rustls::internal::msgs::message::Message;
use rustls::internal::msgs::message::MessagePayload::Handshake;
use rustls::{CipherSuite, ProtocolVersion};
use crate::util::print_as_message;

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
    pub fn execute(&self, ctx: &TraceContext) {
        for step in self.steps.iter() {
            step.execute(ctx)
        }
    }
}

pub trait Step {
    fn execute(&self, ctx: &TraceContext);
}

pub enum ExpectType {
    Alert(AlertLevel),
    Handshake(HandshakeType),
}

pub trait ExpectStep: Step {
    fn get_type(&self) -> ExpectType;
    fn get_concrete_variables(&self) -> Vec<String>; // Variables and the actual values
}

pub trait SendStep: Step {
    fn craft(&self, ctx: &TraceContext) -> Result<Vec<u8>, ()>;
}

pub struct ClientHelloSendStep {}

impl Step for ClientHelloSendStep {
    fn execute(&self, ctx: &TraceContext) {
        let result = self.craft(ctx);

        match result {
            Ok(buffer) => print_as_message(&buffer),
            _ => panic!("Error"),
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
                version: TLSv1_2,
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

// Instructions

enum InstructionType {
    RESET,
}

struct InstructionStep {
    typ: InstructionType,
}

impl Step for InstructionStep {
    fn execute(&self, ctx: &TraceContext) {
        todo!()
    }
}
