use crate::variable::Variable;
use crate::variable::VariableType;
use rustls::internal::msgs::enums::{AlertLevel, Compression, HandshakeType};
use rustls::internal::msgs::handshake::{ClientExtension, Random, SessionID};
use rustls::{CipherSuite, ProtocolVersion};

pub struct TraceContext {}

impl TraceContext {
    fn save(variable: Variable, data: &[u8]) {
        todo!()
    }

    fn concretize<'a>(variable: Variable) -> &'a [u8] {
        todo!()
    }
}

pub struct Trace {
    pub steps: Vec<Box<dyn Step>>,
}

impl Trace {
    fn execute(&self) {
        for step in self.steps.iter() {
            step.execute();
        }
    }
}

pub trait Step {
    fn execute(&self);
}

enum ExpectType {
    Alert(AlertLevel),
    Handshake(HandshakeType),
}

pub trait Expect {
    fn get_type(&self) -> ExpectType;
}

pub trait Send {
    fn dependencies(&self) -> Vec<Variable>;

    fn needed_size(&self) -> usize;
    fn craft(&self, buffer: &mut [u8]) -> Result<usize, ()>;
}

struct ClientHello {
    pub client_version: ProtocolVersion,
    pub random: Random,
    pub session_id: SessionID,
    pub cipher_suites: Vec<CipherSuite>,
    pub compression_methods: Vec<Compression>,
    pub extensions: Vec<ClientExtension>,
}

impl Send for ClientHello {
    fn dependencies(&self) -> Vec<Variable> {
        return vec![Variable {
            name: "client_version",
            typ: VariableType::BINARY,
        }];
    }

    fn needed_size(&self) -> usize {
        todo!()
    }

    fn craft(&self, buffer: &mut [u8]) -> Result<usize, ()> {
        todo!()
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
    fn execute(&self) {
        todo!()
    }
}
