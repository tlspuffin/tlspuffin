// FIXME stabilize sshpuffin and reactivate the dead_code lint
#![allow(dead_code)]

use std::collections::HashSet;
use std::ffi::{c_char, c_void, CStr};
use std::io::Read;

use puffin::agent::{AgentDescriptor, AgentName};
use puffin::claims::GlobalClaimList;
use puffin::error::Error;
use puffin::harness::{to_string, CError};
use puffin::protocol::{OpaqueProtocolMessageFlight, ProtocolBehavior, ProtocolMessageDeframer};
use puffin::put::{Put, PutOptions};
use puffin::put_registry::Factory;
use puffin::stream::Stream;

use crate::claim::{SshClaim, SshClaimInner};
use crate::protocol::{AgentType, RawSshMessageFlight, SshDescriptorConfig, SshProtocolBehavior};
use crate::put_registry::bindings::{
    Claim, AGENT, CLAIMER_CB, SSH_AGENT_DESCRIPTOR, SSH_AGENT_ROLE, SSH_PUT_INTERFACE,
};
use crate::ssh::deframe::SshMessageDeframer;

// ── Claim FFI bridge ──────────────────────────────────────────────────────
//
// The C harness exposes a claim callback, but this build does not use claims
// (the security oracle is a no-op). The notify trampoline pushes an empty
// `SshClaimInner` so the FFI contract is satisfied without decoding any claim
// data. Real claim decoding lives in the claims/oracle change set.

/// Opaque data handed back to us on every `notify`/`destroy` call.
struct ClaimerContext {
    claims: GlobalClaimList<SshClaim>,
    agent_name: AgentName,
    #[allow(dead_code)]
    is_server: bool,
}

/// `notify` trampoline: invoked by the C harness at a claim point. This build
/// records an empty claim (claims are unused by the current oracle).
extern "C" fn ssh_claim_notify(context: *mut c_void, _claim: *mut Claim) {
    if context.is_null() {
        return;
    }
    let ctx = unsafe { &*(context as *const ClaimerContext) };
    ctx.claims
        .deref_borrow_mut()
        .claim_sized(SshClaim::new(ctx.agent_name, SshClaimInner));
}

/// `destroy` trampoline: reclaims the boxed `ClaimerContext`.
extern "C" fn ssh_claim_destroy(context: *mut c_void) {
    if !context.is_null() {
        drop(unsafe { Box::from_raw(context as *mut ClaimerContext) });
    }
}

// ── CSshPut: wraps a compiled C PUT registration ──────────────────────────

#[derive(Clone, Debug)]
pub struct CSshPut {
    name: String,
    harness_version: String,
    library_version: String,
    capabilities: HashSet<String>,
    interface: SSH_PUT_INTERFACE,
}

impl CSshPut {
    pub fn new(
        name: impl Into<String>,
        harness_version: impl Into<String>,
        library_version: impl Into<String>,
        capabilities: HashSet<String>,
        interface: SSH_PUT_INTERFACE,
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

impl Factory<SshProtocolBehavior> for CSshPut {
    fn create(
        &self,
        agent_descriptor: &AgentDescriptor<SshDescriptorConfig>,
        claims: &GlobalClaimList<<SshProtocolBehavior as ProtocolBehavior>::Claim>,
        _options: &PutOptions,
    ) -> Result<Box<dyn Put<SshProtocolBehavior>>, Error> {
        Ok(Box::new(CAgent::new(self, agent_descriptor, claims)?))
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

    fn supports(&self, capability: &str) -> bool {
        self.capabilities.contains(capability)
    }

    fn clone_factory(&self) -> Box<dyn Factory<SshProtocolBehavior>> {
        Box::new(self.clone())
    }

    fn rng_reseed(&self) {
        // Reset the PUT's deterministic PRNG to its default seed (NULL buffer).
        // Required before each trace execution so runs are reproducible.
        match self.interface.rng_reseed {
            Some(reseed) => unsafe { reseed(std::ptr::null(), 0) },
            None => log::warn!("[RNG] reseed not available for {}", self.name),
        }
    }
}

// ── macros mirrored from tlspuffin/src/put.rs ─────────────────────────────

macro_rules! ccall {
    ($put:expr, $fn:ident) => {
        ($put.interface.agent_interface.$fn.unwrap())()
    };
    ($put:expr, $fn:ident, $($arg:expr),*) => {
        ($put.interface.agent_interface.$fn.unwrap())($($arg),*)
    };
}

macro_rules! take_res {
    ($call:expr) => {
        *unsafe { Box::from_raw($call as *mut Result<String, CError>) }
    };
}

macro_rules! r_ccall {
    ($put:expr, $fn:ident) => {
        take_res!(ccall!($put, $fn))
    };
    ($put:expr, $fn:ident, $($arg:expr),*) => {
        take_res!(ccall!($put, $fn, $($arg),*))
    };
}

// ── CAgent: one live SSH agent backed by the C harness ────────────────────

pub struct CAgent {
    put: CSshPut,
    descriptor: AgentDescriptor<SshDescriptorConfig>,
    deframer: SshMessageDeframer,
    c_agent: AGENT,
    /// Heap-stable claim callback registered with the C agent. The C side holds
    /// `&*claimer`, so this box must not move for the agent's lifetime, and its
    /// owned `context` is reclaimed in `Drop` via the CB's `destroy` hook.
    claimer: Option<Box<CLAIMER_CB>>,
}

impl CAgent {
    fn new(
        put: &CSshPut,
        descriptor: &AgentDescriptor<SshDescriptorConfig>,
        claims: &GlobalClaimList<SshClaim>,
    ) -> Result<Self, Error> {
        let c_descriptor = SSH_AGENT_DESCRIPTOR {
            name: descriptor.name.into(),
            role: match descriptor.protocol_config.typ {
                AgentType::Client => SSH_AGENT_ROLE::SSH_CLIENT,
                AgentType::Server => SSH_AGENT_ROLE::SSH_SERVER,
            },
        };

        let c_agent = unsafe { (put.interface.create.unwrap())(&c_descriptor as *const _) };

        if c_agent.is_null() {
            return Err(Error::Put("C SSH agent creation failed".to_owned()));
        }

        // No claim callback is registered in this build: the security oracle is
        // a no-op and claims are unused. Leaving the harness claimer unset keeps
        // the C harness from emitting claims, so the cross-vendor differential
        // compares only execution status and knowledge (no spurious claim diffs
        // from harness-specific claim emission).
        let _ = claims;

        Ok(Self {
            put: put.clone(),
            descriptor: descriptor.clone(),
            deframer: SshMessageDeframer::new(),
            c_agent,
            claimer: None,
        })
    }
}

impl Put<SshProtocolBehavior> for CAgent {
    fn progress(&mut self) -> Result<(), Error> {
        r_ccall!(self.put, progress, self.c_agent)?;
        Ok(())
    }

    fn reset(&mut self, new_name: puffin::agent::AgentName) -> Result<(), Error> {
        self.descriptor.name = new_name;
        r_ccall!(self.put, reset, self.c_agent, new_name.into(), 0u8)?;
        Ok(())
    }

    fn descriptor(&self) -> &AgentDescriptor<SshDescriptorConfig> {
        &self.descriptor
    }

    fn describe_state(&self) -> String {
        unsafe { to_string(ccall!(self.put, describe_state, self.c_agent)) }
    }

    fn is_state_successful(&self) -> bool {
        unsafe { ccall!(self.put, is_state_successful, self.c_agent) }
    }

    fn shutdown(&mut self) -> String {
        "shutdown not implemented".to_owned()
    }

    fn version() -> String
    where
        Self: Sized,
    {
        "C harness / libssh".to_owned()
    }
}

impl Stream<SshProtocolBehavior> for CAgent {
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
            // Benign and expected during fuzzing: when a mutated trace drives the
            // PUT to reject input and close the connection, the next inbound write
            // returns EPIPE ("Broken pipe"). This is the PUT correctly tearing
            // down on malformed input, not a harness error — log at DEBUG so it
            // doesn't flood error.log and mask real failures.
            log::debug!("SSH C PUT add_to_inbound() failed: {}", cerror.reason);
        }
    }

    fn take_message_from_outbound(
        &mut self,
        output_flight: &mut Option<RawSshMessageFlight>,
    ) -> Result<(), Error> {
        let mut flight = RawSshMessageFlight::new();

        loop {
            if let Some(msg) = self.deframer.pop_frame() {
                flight.push(msg);
            } else {
                let mut reader = CReader {
                    put: &self.put,
                    c_agent: self.c_agent,
                };

                match self.deframer.read(&mut reader) {
                    Ok(0) => break,
                    Ok(_) => {}
                    Err(err) => match err.kind() {
                        std::io::ErrorKind::WouldBlock => break,
                        _ => {
                            *output_flight = (!flight.messages.is_empty()).then_some(flight);
                            return Err(err.into());
                        }
                    },
                }
            }
        }

        *output_flight = (!flight.messages.is_empty()).then_some(flight);
        Ok(())
    }
}

impl Drop for CAgent {
    fn drop(&mut self) {
        // Destroy the C agent first so it can no longer invoke the callback,
        // then reclaim the callback's context.
        unsafe {
            ccall!(self.put, destroy, self.c_agent);
        }
        if let Some(claimer) = self.claimer.take() {
            if let Some(destroy) = claimer.destroy {
                unsafe { destroy(claimer.context) };
            }
        }
    }
}

// ── CReader: bridges the C take_outbound into Rust's io::Read ────────────

struct CReader<'a> {
    put: &'a CSshPut,
    c_agent: AGENT,
}

impl<'a> Read for CReader<'a> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut readbytes = 0usize;

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
