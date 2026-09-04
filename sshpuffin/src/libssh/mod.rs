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
// The C harness (both libssh and wolfSSH, symmetrically) builds a completion
// claim carrying the server's entity-authentication belief. The notify
// trampoline decodes the auth-belief fields into `SshClaimInner` so the two
// PUTs' claims can be compared (see the SshClaimInner docs). The rest of the C
// claim (session id, counts, digests) is intentionally not decoded yet.

/// Opaque data handed back to us on every `notify`/`destroy` call.
struct ClaimerContext {
    claims: GlobalClaimList<SshClaim>,
    agent_name: AgentName,
    #[allow(dead_code)]
    is_server: bool,
}

/// Read a NUL-terminated C `char` buffer into an owned `String` (lossy on
/// non-UTF-8, which auth user/method names never are).
fn c_str_field_to_string(buf: &[c_char]) -> String {
    let bytes: Vec<u8> = buf
        .iter()
        .take_while(|&&c| c != 0)
        .map(|&c| c as u8)
        .collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

/// `notify` trampoline: invoked by the C harness at a claim point. Decodes the
/// auth-belief fields of the C `Claim` into a comparable `SshClaimInner`.
extern "C" fn ssh_claim_notify(context: *mut c_void, claim: *mut Claim) {
    if context.is_null() || claim.is_null() {
        return;
    }
    let ctx = unsafe { &*(context as *const ClaimerContext) };
    let c = unsafe { &*claim };
    // Keep only claims that CARRY A SESSION ID (H). Both harnesses emit two such
    // claims symmetrically: a post-KEX claim (phase 2, session id set, empty auth
    // belief — fires as soon as KEX completes, so H is available even for traces
    // whose auth is later rejected/aborted) and, on auth success, the completion
    // claim (phase 3, session id + auth belief). Claims WITHOUT a session id are
    // dropped: libssh's phase-1/KEX coverage claim (emitted before KEX finishes,
    // so its session id is empty) — which wolfSSH does not emit — would otherwise
    // desync the two PUTs' claim sequences. The result is a symmetric sequence
    // ([post-KEX] on failure, [post-KEX, completion] on success) that the
    // differential compares position-wise, and `find_claim` always resolves to a
    // session-id-bearing claim for the decryption recipe. session_id itself is
    // #[comparable_ignore] (differs per stack), so only the auth belief is compared.
    if c.session_id_len == 0 {
        return;
    }
    let fp_len = (c.auth_key_fp_len as usize).min(c.auth_key_fp.len());
    let sid_len = (c.session_id_len as usize).min(c.session_id.len());
    let inner = SshClaimInner {
        auth_method: c_str_field_to_string(&c.auth_method),
        auth_user: c_str_field_to_string(&c.auth_user),
        auth_key_fp: c.auth_key_fp[..fp_len].to_vec(),
        session_id: c.session_id[..sid_len].to_vec(),
    };
    ctx.claims
        .deref_borrow_mut()
        .claim_sized(SshClaim::new(ctx.agent_name, inner));
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
    /// Uniformised algorithm-list CStrings passed into the C harness. wolfSSH's
    /// `wolfSSH_CTX_SetAlgoList*` stores the raw pointer (it does NOT copy) and
    /// dereferences it later in `SendKexInit`, so these must stay alive for the
    /// whole agent lifetime — not just across `create()`. Kept here for that.
    _algos: Vec<std::ffi::CString>,
}

impl CAgent {
    fn new(
        put: &CSshPut,
        descriptor: &AgentDescriptor<SshDescriptorConfig>,
        claims: &GlobalClaimList<SshClaim>,
    ) -> Result<Self, Error> {
        // Uniformised algorithm lists (differential fuzzing). Keep the CStrings
        // alive in locals: the C harness reads the pointers synchronously during
        // create(), so they must outlive the call below. A NULL pointer tells the
        // harness to leave the PUT default (single-PUT / non-differential runs).
        let cfg = &descriptor.protocol_config;
        let as_cstring = |s: &Option<String>| {
            s.as_ref()
                .map(|v| std::ffi::CString::new(v.as_str()).unwrap())
        };
        let kex_c = as_cstring(&cfg.kex);
        let ciphers_c = as_cstring(&cfg.ciphers);
        let macs_c = as_cstring(&cfg.macs);
        let hostkey_c = as_cstring(&cfg.hostkey_algos);
        let server_sig_algs_c = as_cstring(&cfg.server_sig_algs);
        let as_ptr =
            |c: &Option<std::ffi::CString>| c.as_ref().map_or(std::ptr::null(), |v| v.as_ptr());

        let c_descriptor = SSH_AGENT_DESCRIPTOR {
            name: descriptor.name.into(),
            role: match cfg.typ {
                AgentType::Client => SSH_AGENT_ROLE::SSH_CLIENT,
                AgentType::Server => SSH_AGENT_ROLE::SSH_SERVER,
            },
            kex: as_ptr(&kex_c),
            ciphers: as_ptr(&ciphers_c),
            macs: as_ptr(&macs_c),
            hostkey_algos: as_ptr(&hostkey_c),
            server_sig_algs: as_ptr(&server_sig_algs_c),
        };

        let c_agent = unsafe { (put.interface.create.unwrap())(&c_descriptor as *const _) };

        if c_agent.is_null() {
            return Err(Error::Put("C SSH agent creation failed".to_owned()));
        }

        // Register the claim callback. The context owns a clone of the global
        // claim list (Rc-backed) plus this agent's identity. The C harness emits a
        // completion claim (auth-belief + the session id / exchange hash H) which
        // the notify trampoline (`ssh_claim_notify`) decodes into `SshClaimInner`.
        // Two consumers: the differential compares the auth-belief fields across
        // PUTs (catching identity-attribution divergences that USERAUTH_SUCCESS, being
        // identity-less on the wire, hides), and the s2c decryption recipe sources
        // each PUT's H from `session_id` (see `fn_claim_exchange_hash`). Requires the
        // vendors built with the "claimer" instrumentation (-DHAS_CLAIMS); without it
        // the harness emits an empty session_id and the recipe falls back to failing
        // decode, which is caught by the verification gates.
        let context = Box::new(ClaimerContext {
            claims: claims.clone(),
            agent_name: descriptor.name,
            is_server: matches!(descriptor.protocol_config.typ, AgentType::Server),
        });
        let claimer = Box::new(CLAIMER_CB {
            context: Box::into_raw(context) as *mut c_void,
            notify: Some(ssh_claim_notify),
            destroy: Some(ssh_claim_destroy),
        });
        if let Some(register) = put.interface.agent_interface.register_claimer {
            unsafe { register(c_agent, &*claimer as *const _) };
        }

        Ok(Self {
            put: put.clone(),
            descriptor: descriptor.clone(),
            deframer: SshMessageDeframer::new(),
            c_agent,
            claimer: Some(claimer),
            // Move (not copy) the CStrings in: their heap buffers keep the same
            // address, so the pointers the harness stored stay valid until Drop.
            _algos: [kex_c, ciphers_c, macs_c, hostkey_c, server_sig_algs_c]
                .into_iter()
                .flatten()
                .collect(),
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
        // The C side restarts the session (a fresh handshake, plaintext again), so
        // the deframer must drop any buffered bytes AND its post-NewKeys encrypted
        // state — otherwise the new handshake's plaintext KEXINIT would be treated
        // as ciphertext.
        self.deframer = SshMessageDeframer::new();
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
