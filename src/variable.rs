use rustls::internal::msgs::handshake::{SessionID, Random};
use rustls::ProtocolVersion;
use std::any::Any;

pub trait AsAny {
    fn as_any(&self) -> &dyn Any;
}

impl<T: Any> AsAny for T {
    fn as_any(&self) -> &dyn Any { self }
}

// Derived trait should include AsAny so that `as_any` is in its vtable.
pub trait VariableData: Any + AsAny {
    fn get_variable(&self) -> &'static Variable;
}

// Concrete type implementing Derived.
pub struct ClientVersion {
    pub variable: &'static Variable,
    pub data: ProtocolVersion
}

impl VariableData for ClientVersion {
    fn get_variable(&self) -> &'static Variable {
        self.variable
    }
}

pub trait RandomVariableValue<T> {
    fn random_value() -> T;
}

impl RandomVariableValue<ClientVersion> for ClientVersion {
    fn random_value() -> ClientVersion {
        return ClientVersion {
            variable: &Variable::ClientVersion,
            data: ProtocolVersion::TLSv1_3
        };
    }
}

pub enum Variable {
    ClientVersion,
    SessionId,
    Random,
}
