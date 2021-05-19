use std::any::{Any, TypeId};

use dyn_clone::DynClone;
use rand;
use rand::random;
use rand::seq::SliceRandom;
use rustls::internal::msgs::base::PayloadU16;
use rustls::internal::msgs::enums::{Compression, NamedGroup, ServerNameType};
use rustls::internal::msgs::handshake::{
    ClientExtension, KeyShareEntry, Random, ServerExtension, SessionID,
};
use rustls::internal::msgs::handshake::{ServerName, ServerNamePayload};
use rustls::{CipherSuite, ProtocolVersion, SignatureScheme};

use crate::agent::AgentName;
use crate::term::Variable;

pub trait AsAny {
    fn as_any(&self) -> &dyn Any;
}

impl<T: Any> AsAny for T {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

pub trait VariableData: AsAny {
    fn clone_box(&self) -> Box<dyn VariableData>;
    fn clone_any_box(&self) -> Box<dyn Any>;
    fn get_type_id(&self) -> TypeId;
}

impl<T: 'static> VariableData for T
where
    T: Clone,
{
    fn clone_box(&self) -> Box<dyn VariableData> {
        Box::new(self.clone())
    }

    fn clone_any_box(&self) -> Box<dyn Any> {
        Box::new(self.clone())
    }

    fn get_type_id(&self) -> TypeId
    {
        self.type_id()
    }
}

