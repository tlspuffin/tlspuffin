use crate::variable::{AsAny, ClientVersion, RandomVariableValue, Variable, VariableData};
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
use std::env::var;
use std::ptr::null;

pub struct TraceContext {
    variables: Vec<Box<dyn VariableData>>
}

impl TraceContext {
    pub fn new() -> TraceContext {
        TraceContext { variables: vec![] }
    }

    fn get_variable<T: 'static>(&self) -> Option<&ClientVersion> {
        for variable in self.variables.as_slice() {
            if let Some(derived) = (**variable).as_any().downcast_ref::<ClientVersion>() {
                return Some(derived)
            }
        }
        None
    }

    pub fn add_variable(&mut self, data: Box<dyn VariableData>) {
        self.variables.push(data)
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
    fn get_concrete_variables(&self) -> Vec<Variable>; // Variables and the actual values
}

pub trait SendStep: Step {
    fn craft(&self, ctx: &TraceContext) -> Result<Vec<u8>, ()>;
}

struct ClientHelloData {
    client_version: ProtocolVersion,
    random: Random,
    session_id: SessionID,
    cipher_suites: Vec<CipherSuite>,
    compression_methods: Vec<Compression>,
}
pub struct ClientHelloSendStep {
    modifiers: Vec<Variable>,
}

impl Step for ClientHelloSendStep {
    fn execute(&self, ctx: &TraceContext) {
        let result = self.craft(ctx);

        match result {
            Ok(buffer) => println!("Created packet!"),
            _ => panic!("Error")
        }
    }
}

impl ClientHelloSendStep {
    pub fn new(modifiers: Vec<Variable>) -> ClientHelloSendStep {
        ClientHelloSendStep { modifiers }
    }
}



impl SendStep for ClientHelloSendStep {
    fn craft(&self, ctx: &TraceContext) -> Result<Vec<u8>, ()> {
        return if let Some(client_version) = ctx.get_variable::<ClientVersion>() {
            let bytes: [u8; 1] = [5];
            let random = [0u8; 32];
            let payload = Handshake(HandshakeMessagePayload {
                typ: HandshakeType::ClientHello,
                payload: HandshakePayload::ClientHello(ClientHelloPayload {
                    client_version: client_version.data,
                    random: Random::from_slice(&random),
                    session_id: SessionID::new(&bytes),
                    cipher_suites: vec![],
                    compression_methods: vec![],
                    extensions: vec![],
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
