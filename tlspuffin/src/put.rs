use std::cell::RefCell;
use std::collections::HashSet;
use std::ffi::CString;
use std::io::Read;
use std::rc::Rc;

use puffin::agent::AgentDescriptor;
use puffin::algebra::dynamic_function::TypeShape;
use puffin::claims::GlobalClaimList;
use puffin::error::Error;
use puffin::harness::{to_string, CError};
use puffin::protocol::{OpaqueProtocolMessageFlight, ProtocolBehavior, ProtocolMessageDeframer};
use puffin::put::{Put, PutOptions};
use puffin::put_registry::Factory;
use puffin::stream::Stream;
use security_claims::Claim;

use crate::claims::TlsClaim;
use crate::protocol::{
    AgentType, OpaqueMessageFlight, TLSDescriptorConfig, TLSProtocolBehavior, TLSProtocolTypes,
    TLSVersion,
};
use crate::put_registry::bindings::{
    AGENT, CLAIMER_CB, PEM, TLS_AGENT_DESCRIPTOR, TLS_AGENT_ROLE, TLS_PUT_INTERFACE, TLS_VERSION,
};
use crate::static_certs::{ALICE_CERT, ALICE_PRIVATE_KEY, BOB_CERT, BOB_PRIVATE_KEY, EVE_CERT};
use crate::tls::rustls::msgs::deframer::MessageDeframer;

/// Static configuration for creating a new agent state for the PUT
#[derive(Clone, Debug)]
pub struct TlsPutConfig {
    pub descriptor: AgentDescriptor<TLSDescriptorConfig>,
    pub claims: GlobalClaimList<TlsClaim>,
    pub authenticate_peer: bool,
    pub extract_deferred: Rc<RefCell<Option<TypeShape<TLSProtocolTypes>>>>,
    pub use_clear: bool,
}

impl TlsPutConfig {
    pub fn new(
        agent_descriptor: &AgentDescriptor<TLSDescriptorConfig>,
        claims: &GlobalClaimList<<TLSProtocolBehavior as ProtocolBehavior>::Claim>,
        options: &PutOptions,
    ) -> TlsPutConfig {
        let use_clear = options
            .get_option("use_clear")
            .map(|value| value.parse().unwrap_or(false))
            .unwrap_or(false);

        TlsPutConfig {
            descriptor: agent_descriptor.clone(),
            claims: claims.clone(),
            authenticate_peer: agent_descriptor.protocol_config.typ == AgentType::Client
                && agent_descriptor.protocol_config.server_authentication
                || agent_descriptor.protocol_config.typ == AgentType::Server
                    && agent_descriptor.protocol_config.client_authentication,
            extract_deferred: Rc::new(RefCell::new(None)),
            use_clear,
        }
    }
}

#[derive(Clone, Debug)]
pub struct CPut {
    name: String,
    harness_version: String,
    library_version: String,
    capabilities: HashSet<String>,
    interface: TLS_PUT_INTERFACE,
}

impl CPut {
    pub fn new(
        name: impl Into<String>,
        harness_version: impl Into<String>,
        library_version: impl Into<String>,
        capabilities: HashSet<String>,
        interface: TLS_PUT_INTERFACE,
    ) -> Self {
        Self {
            name: name.into(),
            harness_version: harness_version.into(),
            library_version: library_version.into(),
            capabilities,
            interface,
        }
    }
}

impl Factory<TLSProtocolBehavior> for CPut {
    fn create(
        &self,
        agent_descriptor: &AgentDescriptor<TLSDescriptorConfig>,
        claims: &GlobalClaimList<<TLSProtocolBehavior as ProtocolBehavior>::Claim>,
        options: &PutOptions,
    ) -> Result<Box<dyn Put<TLSProtocolBehavior>>, Error> {
        Ok(Box::new(CAgent::new(
            self,
            TlsPutConfig::new(agent_descriptor, claims, options),
        )?))
    }

    fn name(&self) -> String {
        self.name.clone()
    }

    fn versions(&self) -> Vec<(String, String)> {
        vec![
            ("harness".to_string(), self.harness_version.clone()),
            ("library".to_string(), self.library_version.clone()),
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
        self.capabilities.contains(capability)
    }

    fn clone_factory(&self) -> Box<dyn Factory<TLSProtocolBehavior>> {
        Box::new(self.clone())
    }
}

pub struct CAgent {
    put: CPut,
    config: TlsPutConfig,
    deframer: MessageDeframer,
    c_agent: AGENT,
}

macro_rules! pem {
    ($pemder:expr) => {
        PEM {
            bytes: $pemder.0.as_ptr(),
            length: $pemder.0.len(),
        }
    };
}

macro_rules! ccall {
    ( $put:expr, $function_name:ident ) => {
        ($put.interface.agent_interface.$function_name.unwrap())()
    };
    ( $put:expr, $function_name:ident, $($arg:expr),*) => {
        ($put.interface.agent_interface.$function_name.unwrap())($($arg),*)
    };
}

macro_rules! take_res {
    ($call:expr) => {
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

impl CAgent {
    fn new(put: &CPut, config: TlsPutConfig) -> Result<Self, Error> {
        let server_cert = pem!(ALICE_CERT);
        let server_pkey = pem!(ALICE_PRIVATE_KEY);
        let client_cert = pem!(BOB_CERT);
        let client_pkey = pem!(BOB_PRIVATE_KEY);
        let other_cert = pem!(EVE_CERT);

        let server_store = [&client_cert as *const _, &other_cert];
        let client_store = [&server_cert as *const _, &other_cert];
        let ciphers_tls13 = CString::new(
            config
                .descriptor
                .protocol_config
                .cipher_string_tls13
                .clone(),
        )
        .unwrap();
        let ciphers_tls12 = CString::new(
            config
                .descriptor
                .protocol_config
                .cipher_string_tls12
                .clone(),
        )
        .unwrap();
        let groups = config
            .descriptor
            .protocol_config
            .groups
            .clone()
            .map_or(None, |x| Some(CString::new(x.clone()).unwrap()));

        let descriptor = match config.descriptor.protocol_config.typ {
            AgentType::Server => make_descriptor(
                &config,
                &server_cert,
                &server_pkey,
                &server_store,
                &ciphers_tls13,
                &ciphers_tls12,
                &groups,
            ),
            AgentType::Client => make_descriptor(
                &config,
                &client_cert,
                &client_pkey,
                &client_store,
                &ciphers_tls13,
                &ciphers_tls12,
                &groups,
            ),
        };

        let c_agent = unsafe { (put.interface.create.unwrap())(&descriptor as *const _) };
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
            let protocol_version = self.config.descriptor.protocol_config.tls_version;
            let origin = self.config.descriptor.protocol_config.typ;
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

impl Put<TLSProtocolBehavior> for CAgent {
    fn progress(&mut self) -> Result<(), Error> {
        r_ccall!(self.put, progress, self.c_agent)?;
        Ok(())
    }

    fn reset(&mut self, new_name: puffin::agent::AgentName) -> Result<(), Error> {
        self.config.descriptor.name = new_name;
        r_ccall!(
            self.put,
            reset,
            self.c_agent,
            new_name.into(),
            self.config.use_clear as u8
        )?;
        self.register_claimer();
        Ok(())
    }

    fn descriptor(&self) -> &AgentDescriptor<TLSDescriptorConfig> {
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

impl Stream<TLSProtocolBehavior> for CAgent {
    fn add_to_inbound(&mut self, message: &puffin::algebra::ConcreteMessage) {
        let mut written = 0usize;
        let result = r_ccall!(
            self.put,
            add_inbound,
            self.c_agent,
            message.as_ptr(),
            message.len(),
            &mut written as *mut usize
        );

        if let Err(cerror) = result {
            log::error!("C PUT agent add_to_inbound() failed: {}", cerror.reason);
        }
    }

    fn take_message_from_outbound(
        &mut self,
    ) -> Result<Option<<TLSProtocolBehavior as ProtocolBehavior>::OpaqueProtocolMessageFlight>, Error>
    {
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
                        std::io::ErrorKind::WouldBlock => {
                            // This is not a hard error. It just means we will should read again
                            // from the TCPStream in the next steps.
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

impl Drop for CAgent {
    fn drop(&mut self) {
        unsafe {
            ccall!(self.put, destroy, self.c_agent);
        }
    }
}

fn make_descriptor(
    config: &TlsPutConfig,
    cert: *const PEM,
    pkey: *const PEM,
    store: &[*const PEM],
    ciphers_tls13: &CString,
    ciphers_tls12: &CString,
    groups: &Option<CString>,
) -> TLS_AGENT_DESCRIPTOR {
    // eprintln!("{:?}", cert);
    // eprintln!("{:?}", pkey);
    // for pem in store.iter() {
    //     eprintln!("store cert pem ptr: {:?}", pem);
    // }

    TLS_AGENT_DESCRIPTOR {
        name: config.descriptor.name.into(),
        role: match config.descriptor.protocol_config.typ {
            AgentType::Client => TLS_AGENT_ROLE::CLIENT,
            AgentType::Server => TLS_AGENT_ROLE::SERVER,
        },
        tls_version: match config.descriptor.protocol_config.tls_version {
            TLSVersion::V1_3 => TLS_VERSION::V1_3,
            TLSVersion::V1_2 => TLS_VERSION::V1_2,
        },
        client_authentication: config.descriptor.protocol_config.client_authentication,
        server_authentication: config.descriptor.protocol_config.server_authentication,
        cipher_string_tls13: ciphers_tls13.as_ptr(),
        cipher_string_tls12: ciphers_tls12.as_ptr(),
        group_list: if let Some(group_list) = groups {
            group_list.as_ref().as_ptr()
        } else {
            std::ptr::null()
        },

        cert,
        pkey,

        store: store.as_ptr(),
        store_length: store.len() as libc::size_t,
    }
}

extern "C" fn notify(ctx: *mut libc::c_void, c: *mut Claim) {
    if c.is_null() || ctx.is_null() {
        return;
    }

    let c = unsafe { *c };
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
    put: &'a CPut,
    c_agent: AGENT,
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
