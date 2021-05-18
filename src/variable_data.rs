use std::any::{Any, TypeId};

use dyn_clone::DynClone;
use rand;
use rand::random;
use rand::seq::SliceRandom;
use rustls::{CipherSuite, ProtocolVersion, SignatureScheme};
use rustls::internal::msgs::base::PayloadU16;
use rustls::internal::msgs::enums::{Compression, NamedGroup, ServerNameType};
use rustls::internal::msgs::handshake::{
    ClientExtension, KeyShareEntry, Random, ServerExtension, SessionID,
};
use rustls::internal::msgs::handshake::{ServerName, ServerNamePayload};

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

// VariableData trait should include AsAny so that `as_any` is in its vtable.
pub trait VariableData: Any + AsAny + DynClone {
    fn get_data(&self) -> &dyn Any;

    fn get_type_id(&self) -> TypeId {
        self.get_data().type_id()
    }

    fn clone_data(&self) -> Box<dyn Any>;
}

dyn_clone::clone_trait_object!(VariableData);

#[macro_export]
macro_rules! variable_data {
    ($data:ty => $variable_data:ident) => (
        #[derive(Clone)]
        pub struct $variable_data {
            pub data: $data,
        }

        impl VariableData for $variable_data {
            fn get_data(&self) -> &dyn Any {
                self.data.as_any()
            }
            fn clone_data(&self) -> Box<dyn Any> {
                Box::new(self.data.clone())
            }
        }
    )
}

variable_data!(ProtocolVersion => VersionData);
variable_data!(Random => RandomData);
variable_data!(CipherSuite => AgreedCipherSuiteData);
variable_data!(Compression => AgreedCompressionData);
variable_data!(SessionID => SessionIDData);
variable_data!(CipherSuite => CipherSuiteData);
variable_data!(Compression => CompressionData);
variable_data!(ClientExtension => ClientExtensionData);
variable_data!(ServerExtension => ServerExtensionData);
