use log::{error, info};
use puffin::codec::Codec;
use std::cell::RefCell;
use std::ffi::CStr;
use std::io::{ErrorKind, Read};
use std::rc::Rc;

use libc::size_t;

use crate::static_certs::{
    ALICE_CERT, ALICE_PRIVATE_KEY, BOB_CERT, BOB_PRIVATE_KEY, EVE_CERT, PEMDER,
};
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

use crate::cput_openssl::bindings::{
    AGENT_DESCRIPTOR, AGENT_TYPE_CLIENT, AGENT_TYPE_SERVER, CPUT, C_TLSPUFFIN, PEM,
    TLS_VERSION_V1_2, TLS_VERSION_V1_3,
};

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
    pub c_data: *mut ::std::os::raw::c_void,
}

impl Stream<Message, OpaqueMessage> for CPUTOpenSSL {
    fn add_to_inbound(&mut self, message: &OpaqueMessage) {
        let bytes = message.get_encoding();
        let mut written = 0usize;
        unsafe {
            (CPUT.add_inbound.unwrap())(
                self.c_data,
                bytes.as_ptr(),
                bytes.len(),
                &mut written as *mut usize,
            )
        };
    }

    fn take_message_from_outbound(
        &mut self,
    ) -> Result<Option<MessageResult<Message, OpaqueMessage>>, Error> {
        let opaque_message = loop {
            if let Some(opaque_message) = self.deframer.pop_frame() {
                break Some(opaque_message);
            } else {
                let mut reader = CReader {
                    c_data: self.c_data,
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
    c_data: *mut ::std::os::raw::c_void,
}

impl Read for CReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut readbytes = 0usize as size_t;
        unsafe {
            (CPUT.take_outbound.unwrap())(self.c_data, buf.as_mut_ptr(), buf.len(), &mut readbytes)
        };

        Ok(readbytes)
    }
}

impl Put<TLSProtocolBehavior> for CPUTOpenSSL {
    fn progress(&mut self, agent_name: &AgentName) -> Result<(), Error> {
        unsafe { (CPUT.progress.unwrap())(self.c_data, (*agent_name).into()) };
        Ok(())
    }

    fn reset(&mut self, agent_name: AgentName) -> Result<(), Error> {
        unsafe { (CPUT.reset.unwrap())(self.c_data, agent_name.into()) };
        Ok(())
    }

    fn descriptor(&self) -> &AgentDescriptor {
        &self.config.descriptor
    }

    fn rename_agent(&mut self, agent_name: AgentName) -> Result<(), Error> {
        unsafe { (CPUT.rename_agent.unwrap())(self.c_data, agent_name.into()) };
        Ok(())
    }

    fn describe_state(&self) -> &str {
        unsafe {
            CStr::from_ptr((CPUT.describe_state.unwrap())(self.c_data))
                .to_str()
                .unwrap()
        }
    }

    fn is_state_successful(&self) -> bool {
        unsafe { (CPUT.is_state_successful.unwrap())(self.c_data) }
    }

    fn set_deterministic(&mut self) -> Result<(), Error> {
        unsafe { (CPUT.set_deterministic.unwrap())(self.c_data) };
        Ok(())
    }

    fn shutdown(&mut self) -> String {
        unsafe {
            CStr::from_ptr((CPUT.shutdown.unwrap())(self.c_data))
                .to_str()
                .unwrap()
                .to_string()
        }
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
    fn new(config: TlsPutConfig) -> Result<CPUTOpenSSL, Error> {
        let c_data = unsafe { (CPUT.create.unwrap())(Box::into_raw(make_descriptor(&config))) };

        Ok(CPUTOpenSSL {
            config,
            c_data,
            deframer: MessageDeframer::new(),
        })
    }
}

#[no_mangle]
pub static TLSPUFFIN: C_TLSPUFFIN = C_TLSPUFFIN {
    error: Some(c_log_error),
    warn: Some(c_log_warn),
    info: Some(c_log_info),
    debug: Some(c_log_debug),
    trace: Some(c_log_trace),
};

macro_rules! define_extern_c_log {
    ( $level:ident, $name:ident ) => {
        unsafe extern "C" fn $name(message: *const ::std::os::raw::c_char) {
            log::log!(
                log::Level::$level,
                "{}",
                CStr::from_ptr(message).to_string_lossy()
            );
        }
    };
}

define_extern_c_log!(Error, c_log_error);
define_extern_c_log!(Warn, c_log_warn);
define_extern_c_log!(Info, c_log_info);
define_extern_c_log!(Debug, c_log_debug);
define_extern_c_log!(Trace, c_log_trace);

impl Into<PEM> for PEMDER {
    fn into(self) -> PEM {
        PEM {
            bytes: self.0.as_ptr(),
            length: self.0.len(),
        }
    }
}

fn make_descriptor(config: &TlsPutConfig) -> Box<AGENT_DESCRIPTOR> {
    let (cert, pkey, store) = match config.descriptor.typ {
        AgentType::Server => (ALICE_CERT, ALICE_PRIVATE_KEY, [BOB_CERT, EVE_CERT]),
        AgentType::Client => (BOB_CERT, BOB_PRIVATE_KEY, [ALICE_CERT, EVE_CERT]),
    };

    let store = store
        .iter()
        .map(|c| Box::into_raw(Box::new(Into::<PEM>::into(*c))))
        .chain(std::iter::once(std::ptr::null_mut()))
        .collect();

    Box::new(AGENT_DESCRIPTOR {
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

        cert: Into::<PEM>::into(cert),
        pkey: Into::<PEM>::into(pkey),

        store: Box::into_raw(store) as *mut _,
    })
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
