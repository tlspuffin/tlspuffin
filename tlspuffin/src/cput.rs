use std::{
    cell::RefCell,
    io::{ErrorKind, Read},
    rc::Rc,
};

use puffin::{
    agent::AgentType,
    codec::Codec,
    error::Error,
    protocol::{OpaqueProtocolMessageFlight, ProtocolMessageDeframer},
    put::Put,
    put_registry::Factory,
    stream::Stream,
    VERSION_STR,
};
use security_claims::Claim;
use tls_harness::{
    to_string, CError, CPutHarness, CPutLibrary, AGENT_DESCRIPTOR, AGENT_TYPE, CLAIMER_CB,
    C_PUT_INTERFACE, PEM, TLS_VERSION,
};

use crate::{
    claims::TlsClaim,
    protocol::{OpaqueMessageFlight, TLSProtocolBehavior},
    put::TlsPutConfig,
    query::TlsQueryMatcher,
    static_certs::{ALICE_CERT, ALICE_PRIVATE_KEY, BOB_CERT, BOB_PRIVATE_KEY, EVE_CERT},
    tls::rustls::msgs::{
        deframer::MessageDeframer,
        message::{Message, OpaqueMessage},
    },
};

pub fn new_factory(
    harness: CPutHarness,
    library: CPutLibrary,
    interface: C_PUT_INTERFACE,
) -> Box<dyn Factory<TLSProtocolBehavior>> {
    Box::new(TlsCPut {
        harness,
        library,
        interface,
    })
}

#[derive(Clone)]
struct TlsCPut {
    harness: CPutHarness,
    library: CPutLibrary,
    interface: C_PUT_INTERFACE,
}

impl Factory<TLSProtocolBehavior> for TlsCPut {
    fn create(
        &self,
        agent_descriptor: &puffin::agent::AgentDescriptor,
        claims: &puffin::claims::GlobalClaimList<
            <TLSProtocolBehavior as puffin::protocol::ProtocolBehavior>::Claim,
        >,
        options: &puffin::put::PutOptions,
    ) -> Result<Box<dyn puffin::put::Put<TLSProtocolBehavior>>, puffin::error::Error> {
        let use_clear = options
            .get_option("use_clear")
            .map(|value| value.parse().unwrap_or(false))
            .unwrap_or(false);

        let config = TlsPutConfig {
            descriptor: agent_descriptor.clone(),
            claims: claims.clone(),
            authenticate_peer: agent_descriptor.typ == AgentType::Client
                && agent_descriptor.server_authentication
                || agent_descriptor.typ == AgentType::Server
                    && agent_descriptor.client_authentication,
            extract_deferred: Rc::new(RefCell::new(None)),
            use_clear,
        };

        Ok(Box::new(TlsCAgent::new(self, config).map_err(|err| {
            Error::Put(format!("Failed to create client/server: {}", err))
        })?))
    }

    fn kind(&self) -> puffin::put_registry::PutKind {
        puffin::put_registry::PutKind::CPUT
    }

    fn name(&self) -> String {
        self.library.config_name.to_string()
    }

    fn versions(&self) -> Vec<(String, String)> {
        vec![
            (
                "harness".to_owned(),
                format!("{} ({})", self.harness.name, VERSION_STR),
            ),
            (
                "library".to_owned(),
                format!(
                    "{} ({} / {})",
                    self.library.config_name, self.library.version, self.library.config_hash
                ),
            ),
        ]
    }

    fn rng_reseed(&self) {
        if self.interface.rng_reseed.is_none() {
            log::debug!("[RNG] reseed failed ({}): not supported", self.name());
            return;
        }

        const DEFAULT_SEED: [u8; 8] = 42u64.to_le().to_ne_bytes();

        log::debug!("[RNG] reseed ({})", self.name());
        unsafe {
            (self.interface.rng_reseed.unwrap())(DEFAULT_SEED.as_ptr(), DEFAULT_SEED.len());
        }
    }

    fn supports(&self, capability: &str) -> bool {
        self.harness.capabilities.contains(capability)
    }

    fn clone_factory(&self) -> Box<dyn Factory<TLSProtocolBehavior>> {
        Box::new(self.clone())
    }
}

struct TlsCAgent {
    put: TlsCPut,
    config: TlsPutConfig,
    deframer: MessageDeframer,
    c_agent: *mut libc::c_void,
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
    ( $put:expr, $function_name:ident ) => {
        ($put.interface.$function_name.unwrap())()
    };
    ( $put:expr, $function_name:ident, $($arg:expr),*) => {
        ($put.interface.$function_name.unwrap())($($arg),*)
    };
}

macro_rules! take_res {
    ( $call:expr ) => {
        *unsafe { Box::from_raw($call as *mut Result<String, CError>) }
    };
}

macro_rules! r_ccall {
    ( $put:expr, $function_name:ident ) => {
        take_res!(ccall!($put, $function_name))
    };
    ( $put:expr, $function_name:ident, $($arg:expr),*) => {
        take_res!(ccall!($put, $function_name, $($arg),*))
    };
}

impl TlsCAgent {
    fn new(put: &TlsCPut, config: TlsPutConfig) -> Result<Self, Error> {
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

        let c_agent = unsafe { ccall!(put, create, &descriptor as *const _) };
        if c_agent.is_null() {
            return Err(Error::Put("C agent creation failed".to_owned()));
        }

        let mut agent = Self {
            put: put.clone(),
            config,
            deframer: MessageDeframer::new(),
            c_agent,
        };

        agent.register_claimer();

        Ok(agent)
    }

    fn register_claimer(&mut self) {
        unsafe {
            use crate::claims::claims_helpers;

            let claims = self.config.claims.clone();
            let protocol_version = self.config.descriptor.tls_version;
            let origin = self.config.descriptor.typ;
            let agent_name = self.config.descriptor.name;

            let claimer = make_claimer(move |claim: Claim| {
                if let Some(data) = claims_helpers::to_claim_data(protocol_version, claim) {
                    claims.deref_borrow_mut().claim_sized(TlsClaim {
                        agent_name,
                        origin,
                        protocol_version,
                        data,
                    })
                }
            });

            ccall!(
                self.put,
                register_claimer,
                self.c_agent,
                &claimer as *const _
            );
        }
    }
}

impl Put<TLSProtocolBehavior> for TlsCAgent {
    fn progress(&mut self) -> Result<(), puffin::error::Error> {
        r_ccall!(self.put, progress, self.c_agent)?;
        Ok(())
    }

    fn reset(&mut self, new_name: puffin::agent::AgentName) -> Result<(), puffin::error::Error> {
        self.config.descriptor.name = new_name;
        r_ccall!(self.put, reset, self.c_agent, new_name.into())?;
        self.register_claimer();
        Ok(())
    }

    fn descriptor(&self) -> &puffin::agent::AgentDescriptor {
        &self.config.descriptor
    }

    fn describe_state(&self) -> String {
        unsafe { to_string(ccall!(self.put, describe_state, self.c_agent)) }
    }

    fn is_state_successful(&self) -> bool {
        unsafe { ccall!(self.put, is_state_successful, self.c_agent) }
    }

    fn shutdown(&mut self) -> String {
        todo!()
    }

    fn version() -> String
    where
        Self: Sized,
    {
        todo!()
    }
}

impl Stream<TlsQueryMatcher, Message, OpaqueMessage, OpaqueMessageFlight> for TlsCAgent {
    fn add_to_inbound(&mut self, message_flight: &OpaqueMessageFlight) {
        let bytes = message_flight.get_encoding();
        let mut written = 0usize;
        let result = r_ccall!(
            self.put,
            add_inbound,
            self.c_agent,
            bytes.as_ptr(),
            bytes.len(),
            &mut written as *mut usize
        );

        if let Err(cerror) = result {
            log::error!("C PUT agent add_to_inbound() failed: {}", cerror.reason);
        }
    }

    fn take_message_from_outbound(&mut self) -> Result<Option<OpaqueMessageFlight>, Error> {
        let mut flight = OpaqueMessageFlight::new();
        loop {
            if let Some(opaque_message) = self.deframer.pop_frame() {
                flight.push(opaque_message);
            } else {
                let mut reader = CReader {
                    put: &self.put,
                    c_agent: self.c_agent,
                };

                match self.deframer.read(&mut reader) {
                    Ok(v) => {
                        if v == 0 {
                            break;
                        }
                    }
                    Err(err) => match err.kind() {
                        ErrorKind::WouldBlock => {
                            // This is not a hard error. It just means we will should read again from
                            // the TCPStream in the next steps.
                            break;
                        }
                        _ => return Err(err.into()),
                    },
                }
            }
        }

        Ok((!flight.messages.is_empty()).then_some(flight))
    }
}

impl Drop for TlsCAgent {
    fn drop(&mut self) {
        unsafe {
            ccall!(self.put, destroy, self.c_agent);
        }
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
            AgentType::Client => AGENT_TYPE::CLIENT,
            AgentType::Server => AGENT_TYPE::SERVER,
        },
        tls_version: match config.descriptor.tls_version {
            puffin::agent::TLSVersion::V1_3 => TLS_VERSION::V1_3,
            puffin::agent::TLSVersion::V1_2 => TLS_VERSION::V1_2,
        },
        client_authentication: config.descriptor.client_authentication,
        server_authentication: config.descriptor.server_authentication,

        cert: cert as *const _,
        pkey: pkey as *const _,

        store: store.as_ptr(),
        store_length: store.len() as libc::size_t,
    }
}

extern "C" fn notify(ctx: *mut libc::c_void, c: Claim) {
    let callback: &mut Box<dyn FnMut(Claim)> =
        unsafe { &mut *(ctx as *mut std::boxed::Box<dyn FnMut(Claim)>) };

    callback(c);
}

extern "C" fn destroy(ctx: *mut libc::c_void) {
    let _: Box<Box<dyn FnMut(Claim)>> = unsafe { Box::from_raw(ctx as *mut _) };
}

fn make_claimer<F>(callback: F) -> CLAIMER_CB
where
    F: FnMut(Claim) + 'static,
{
    let cb: Box<Box<dyn FnMut(Claim)>> = Box::new(Box::new(callback));

    CLAIMER_CB {
        context: Box::into_raw(cb) as *mut _,
        notify: Some(notify),
        destroy: Some(destroy),
    }
}

struct CReader<'a> {
    put: &'a TlsCPut,
    c_agent: *mut libc::c_void,
}

impl<'a> Read for CReader<'a> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut readbytes = 0usize as libc::size_t;

        let result = r_ccall!(
            self.put,
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
