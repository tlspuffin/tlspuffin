use log::{error, info};
use puffin::codec::Codec;
use std::cell::RefCell;
use std::io::{ErrorKind, Read};
use std::rc::Rc;

use libc::{c_void, size_t};

use crate::static_certs::{ALICE_CERT, ALICE_PRIVATE_KEY, BOB_CERT, BOB_PRIVATE_KEY, EVE_CERT};
use crate::{
    protocol::TLSProtocolBehavior,
    put::TlsPutConfig,
    put_registry::C_PUT,
    tls::rustls::msgs::{
        deframer::MessageDeframer,
        message::{Message, OpaqueMessage},
    },
};

use puffin::{
    agent::{AgentDescriptor, AgentName, AgentType},
    error::Error,
    protocol::{MessageResult, ProtocolMessageDeframer},
    put::{Put, PutName},
    put_registry::Factory,
    stream::Stream,
    trace::TraceContext,
};

use tlspuffin_cbindings::bindings::{
    AGENT_DESCRIPTOR, AGENT_TYPE_CLIENT, AGENT_TYPE_SERVER, CPUT, PEM, TLS_VERSION_V1_2,
    TLS_VERSION_V1_3,
};

use tlspuffin_cbindings::{to_string, CError};

pub fn new_cput_openssl_factory() -> Box<dyn Factory<TLSProtocolBehavior>> {
    struct CPUTOpenSSLFactory;
    impl Factory<TLSProtocolBehavior> for CPUTOpenSSLFactory {
        fn create(
            &self,
            context: &TraceContext<TLSProtocolBehavior>,
            agent_descriptor: &AgentDescriptor,
        ) -> Result<Box<dyn Put<TLSProtocolBehavior>>, Error> {
            let put_descriptor = context.put_descriptor(agent_descriptor);

            let options = &put_descriptor.options;

            let use_clear = options
                .get_option("use_clear")
                .map(|value| value.parse().unwrap_or(false))
                .unwrap_or(false);

            // FIXME: Add non-clear method like in wolfssl
            if !use_clear {
                info!("OpenSSL put does not support clearing mode")
            }

            let config = TlsPutConfig {
                descriptor: agent_descriptor.clone(),
                claims: context.claims().clone(),
                authenticate_peer: agent_descriptor.typ == AgentType::Client
                    && agent_descriptor.server_authentication
                    || agent_descriptor.typ == AgentType::Server
                        && agent_descriptor.client_authentication,
                extract_deferred: Rc::new(RefCell::new(None)),
                use_clear,
            };

            Ok(Box::new(CPUTOpenSSL::new(config).map_err(|err| {
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

pub struct CPUTOpenSSL {
    pub config: TlsPutConfig,
    pub deframer: MessageDeframer,
    pub c_agent: *mut c_void,
}

macro_rules! pem {
    ( $pemder:expr ) => {
        PEM {
            bytes: $pemder.0.as_ptr(),
            length: $pemder.0.len(),
        }
    };
}

macro_rules! ccall {
    ( $function_name:ident ) => {
        (CPUT.$function_name.unwrap())()
    };
    ( $function_name:ident, $($arg:expr),*) => {
        (CPUT.$function_name.unwrap())($($arg),*)
    };
}

macro_rules! take_res {
    ( $call:expr ) => {
        *unsafe { Box::from_raw($call as *mut Result<String, CError>) }
    };
}

macro_rules! r_ccall {
    ( $function_name:ident ) => {
        take_res!(ccall!($function_name))
    };
    ( $function_name:ident, $($arg:expr),*) => {
        take_res!(ccall!($function_name, $($arg),*))
    };
}

impl Stream<Message, OpaqueMessage> for CPUTOpenSSL {
    fn add_to_inbound(&mut self, message: &OpaqueMessage) {
        let bytes = message.get_encoding();
        let mut written = 0usize;
        let result = r_ccall!(
            add_inbound,
            self.c_agent,
            bytes.as_ptr(),
            bytes.len(),
            &mut written as *mut usize
        );

        if let Err(cerror) = result {
            error!("C PUT agent add_to_inbound() failed: {}", cerror.reason);
        }

        return;
    }

    fn take_message_from_outbound(
        &mut self,
    ) -> Result<Option<MessageResult<Message, OpaqueMessage>>, Error> {
        let opaque_message = loop {
            if let Some(opaque_message) = self.deframer.pop_frame() {
                break Some(opaque_message);
            } else {
                let mut reader = CReader {
                    c_agent: self.c_agent,
                };

                match self.deframer.read(&mut reader) {
                    Ok(v) => {
                        if v == 0 {
                            break None;
                        }
                    }
                    Err(err) => match err.kind() {
                        ErrorKind::WouldBlock => {
                            // This is not a hard error. It just means we will should read again from
                            // the TCPStream in the next steps.
                            break None;
                        }
                        _ => return Err(err.into()),
                    },
                }
            }
        };

        if let Some(opaque_message) = opaque_message {
            let message = match opaque_message.clone().try_into() {
                Ok(message) => Some(message),
                Err(err) => {
                    error!("Failed to decode message! This means we maybe need to remove logical checks from rustls! {}", Into::<Error>::into(err));
                    None
                }
            };

            Ok(Some(MessageResult(message, opaque_message)))
        } else {
            // no message to return
            Ok(None)
        }
    }
}

struct CReader {
    c_agent: *mut c_void,
}

impl Read for CReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut readbytes = 0usize as size_t;

        let result = r_ccall!(
            take_outbound,
            self.c_agent,
            buf.as_mut_ptr(),
            buf.len(),
            &mut readbytes
        );

        match result {
            Ok(_) => Ok(readbytes),
            Err(cerror) => Err(cerror.into()),
        }
    }
}

impl Put<TLSProtocolBehavior> for CPUTOpenSSL {
    fn progress(&mut self, _agent_name: &AgentName) -> Result<(), Error> {
        r_ccall!(progress, self.c_agent)?;

        Ok(())
    }

    fn reset(&mut self, _agent_name: AgentName) -> Result<(), Error> {
        r_ccall!(reset, self.c_agent)?;

        Ok(())
    }

    fn descriptor(&self) -> &AgentDescriptor {
        &self.config.descriptor
    }

    fn rename_agent(&mut self, agent_name: AgentName) -> Result<(), Error> {
        unsafe { ccall!(rename, self.c_agent, agent_name.into()) };
        Ok(())
    }

    fn describe_state(&self) -> String {
        unsafe { to_string(ccall!(describe_state, self.c_agent)) }
    }

    fn is_state_successful(&self) -> bool {
        unsafe { ccall!(is_state_successful, self.c_agent) }
    }

    fn set_deterministic(&mut self) -> Result<(), Error> {
        unsafe { ccall!(set_deterministic, self.c_agent) };
        Ok(())
    }

    fn shutdown(&mut self) -> String {
        unsafe { to_string(ccall!(shutdown, self.c_agent)) }
    }

    fn version() -> String {
        unsafe { to_string(ccall!(version)) }
    }
}

impl CPUTOpenSSL {
    fn new(config: TlsPutConfig) -> Result<CPUTOpenSSL, Error> {
        let descriptor = match config.descriptor.typ {
            AgentType::Server => make_descriptor(
                &config,
                &pem!(ALICE_CERT),
                &pem!(ALICE_PRIVATE_KEY),
                &[&pem!(BOB_CERT) as *const _, &pem!(EVE_CERT) as *const _],
            ),
            AgentType::Client => make_descriptor(
                &config,
                &pem!(BOB_CERT),
                &pem!(BOB_PRIVATE_KEY),
                &[&pem!(ALICE_CERT) as *const _, &pem!(EVE_CERT) as *const _],
            ),
        };

        let c_agent = unsafe { ccall!(create, &descriptor as *const _) };

        Ok(CPUTOpenSSL {
            config,
            c_agent,
            deframer: MessageDeframer::new(),
        })
    }
}

impl Drop for CPUTOpenSSL {
    fn drop(&mut self) {
        unsafe { ccall!(destroy, self.c_agent) }
    }
}

fn make_descriptor(
    config: &TlsPutConfig,
    cert: &PEM,
    pkey: &PEM,
    store: &[*const PEM],
) -> AGENT_DESCRIPTOR {
    AGENT_DESCRIPTOR {
        name: config.descriptor.name.into(),
        type_: match config.descriptor.typ {
            AgentType::Client => AGENT_TYPE_CLIENT,
            AgentType::Server => AGENT_TYPE_SERVER,
        },
        tls_version: match config.descriptor.tls_version {
            puffin::agent::TLSVersion::V1_3 => TLS_VERSION_V1_3,
            puffin::agent::TLSVersion::V1_2 => TLS_VERSION_V1_2,
        },
        client_authentication: config.descriptor.client_authentication,
        server_authentication: config.descriptor.server_authentication,

        cert: cert as *const _,
        pkey: pkey as *const _,

        store: store.as_ptr(),
        store_length: store.len() as size_t,
    }
}

#[cfg(test)]
mod tests {
    use super::new_cput_openssl_factory;

    #[test]
    fn create_cput_openssl_factory() {
        new_cput_openssl_factory();
        return;
    }
}
