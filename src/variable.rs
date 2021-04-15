use rustls::internal::msgs::handshake::{Random, SessionID};
use rustls::ProtocolVersion;
use std::any::Any;
use rand;
use rand::random;

pub trait AsAny {
    fn as_any(&self) -> &dyn Any;
}

impl<T: Any> AsAny for T {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

// VariableData trait should include AsAny so that `as_any` is in its vtable.
pub trait VariableData: Any + AsAny {
    fn get_variable(&self) -> &'static Variable;
}

pub trait RandomVariableValue<T> {
    fn random_value() -> T;
}

// ClientVersion

pub struct ClientVersionData {
    pub variable: &'static Variable,
    pub data: ProtocolVersion,
}

impl VariableData for ClientVersionData {
    fn get_variable(&self) -> &'static Variable {
        self.variable
    }
}

impl RandomVariableValue<ClientVersionData> for ClientVersionData {
    fn random_value() -> ClientVersionData {
        return ClientVersionData {
            variable: &Variable::ClientVersion,
            data: ProtocolVersion::TLSv1_3,
        };
    }
}

// Random

pub struct RandomData {
    pub variable: &'static Variable,
    pub data: Random,
}

impl VariableData for RandomData {
    fn get_variable(&self) -> &'static Variable {
        self.variable
    }
}

impl RandomVariableValue<RandomData> for RandomData {
    fn random_value() -> RandomData {
        let random_data: [u8; 32] = rand::random();
        return RandomData {
            variable: &Variable::ClientVersion,
            data: Random::from_slice(&random_data),
        };
    }
}

// SessionId

pub struct SessionIDData {
    pub variable: &'static Variable,
    pub data: SessionID,
}

impl VariableData for SessionIDData {
    fn get_variable(&self) -> &'static Variable {
        self.variable
    }
}

impl RandomVariableValue<SessionIDData> for SessionIDData {
    fn random_value() -> SessionIDData {
        let random_data: [u8; 32]  = rand::random();
        return SessionIDData {
            variable: &Variable::ClientVersion,
            data: SessionID::new(&random_data),
        };
    }
}

pub enum Variable {
    ClientVersion,
    SessionId,
    Random,
}
