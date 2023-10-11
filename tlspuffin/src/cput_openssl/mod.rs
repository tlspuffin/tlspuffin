use std::ffi::{CStr, CString};

use libc::{c_char, c_int, c_long, c_uchar, c_uint, c_void};

use crate::{
    protocol::TLSProtocolBehavior,
    put_registry::C_PUT,
    tls::rustls::msgs::message::{Message, OpaqueMessage},
};

use puffin::{
    agent::{AgentDescriptor, AgentName},
    error::Error,
    protocol::MessageResult,
    put::Put,
    put::PutName,
    put_registry::Factory,
    stream::Stream,
    trace::TraceContext,
};

pub fn new_cput_openssl_factory() -> Box<dyn Factory<TLSProtocolBehavior>> {
    struct CPUTOpenSSLFactory;
    impl Factory<TLSProtocolBehavior> for CPUTOpenSSLFactory {
        fn create(
            &self,
            context: &TraceContext<TLSProtocolBehavior>,
            agent_descriptor: &AgentDescriptor,
        ) -> Result<Box<dyn Put<TLSProtocolBehavior>>, Error> {
            Ok(Box::new(CPUTOpenSSL::new().map_err(|err| {
                Error::Put(format!("Failed to create client/server: {}", err))
            })?))
        }

        fn name(&self) -> PutName {
            C_PUT
        }

        fn version(&self) -> String {
            CPUTOpenSSL::version()
        }
    }

    Box::new(CPUTOpenSSLFactory)
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct C_PUT_TYPE {
    pub version: ::std::option::Option<unsafe extern "C" fn() -> *const ::std::os::raw::c_char>,
}

extern "C" {
    pub static mut CPUT: C_PUT_TYPE;
}

#[repr(C)]
pub struct SSL {
    pub dummy_field: c_int,
}

extern "C" {
    pub fn new_ssl() -> *mut SSL;
}

pub struct CPUTOpenSSL {}

impl Stream<Message, OpaqueMessage> for CPUTOpenSSL {
    fn add_to_inbound(&mut self, result: &OpaqueMessage) {
        panic!("C PUT (OpenSSL) stream not implemented")
    }

    fn take_message_from_outbound(
        &mut self,
    ) -> Result<Option<MessageResult<Message, OpaqueMessage>>, Error> {
        panic!("C PUT (OpenSSL) stream not implemented")
    }
}

impl Put<TLSProtocolBehavior> for CPUTOpenSSL {
    fn progress(&mut self, _agent_name: &AgentName) -> Result<(), Error> {
        panic!("C PUT (OpenSSL) not implemented")
    }

    fn reset(&mut self, agent_name: AgentName) -> Result<(), Error> {
        panic!("C PUT (OpenSSL) not implemented")
    }

    fn descriptor(&self) -> &AgentDescriptor {
        panic!("C PUT (OpenSSL) not implemented")
    }

    fn rename_agent(&mut self, agent_name: AgentName) -> Result<(), Error> {
        panic!("C PUT (OpenSSL) not implemented")
    }

    fn describe_state(&self) -> &str {
        panic!("C PUT (OpenSSL) not implemented")
    }

    fn is_state_successful(&self) -> bool {
        panic!("C PUT (OpenSSL) not implemented")
    }

    fn set_deterministic(&mut self) -> Result<(), Error> {
        panic!("C PUT (OpenSSL) not implemented")
    }

    fn shutdown(&mut self) -> String {
        panic!("C PUT (OpenSSL) not implemented")
    }

    fn version() -> String {
        unsafe {
            CStr::from_ptr((CPUT.version.unwrap())())
                .to_str()
                .unwrap()
                .to_owned()
        }
    }
}

impl CPUTOpenSSL {
    fn new() -> Result<CPUTOpenSSL, Error> {
        Err(Error::Agent("C PUT OpenSSL not implemented".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::new_cput_openssl_factory;
    use super::CPUTOpenSSL;
    use puffin::put::Put;

    #[test]
    fn create_cput_openssl_factory() {
        new_cput_openssl_factory();
        return;
    }

    #[test]
    fn create_cput_openssl() {
        CPUTOpenSSL::new();
        return;
    }

    #[test]
    fn valid_cput_version() {
        assert_eq!(CPUTOpenSSL::version(), "0.0.1-dummy-cputopenssl");
        return;
    }
}
