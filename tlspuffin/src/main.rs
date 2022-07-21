//! TODO: Write intro: https://github.com/tlspuffin/tlspuffin/issues/94
//!
//! ### Used protocol and cryptographic libraries
//!
//! In order to easily implement concrete functions, we use several libraries which provide us with predefined encoders for TLS packets, cryptographic primitives, as well as higher level cryptographic operations specific for TLS.
//!
//! We forked the [rustls](https://github.com/ctz/rustls) library for cryptographic operations like deriving secrets. We also use it to encode and decode TLS messages.
//!
//! The cryptographic library [ring](https://github.com/briansmith/ring) allows us to use the derived secrets to encrypt and decrypt TLS messages.
//!
//! # Example
//!
//! ```rust
//! use puffin::agent::{AgentName, AgentDescriptor, TLSVersion::*};
//! use puffin::trace::{Step, TraceContext, Trace, Action, InputAction, OutputAction, Query, TlsMessageType};
//! use puffin::algebra::{Term, signature::Signature};
//! use tlspuffin::tls::fn_impl::fn_client_hello;
//! use rustls::{ProtocolVersion, CipherSuite};
//! use rustls::msgs::handshake::{SessionID, Random, ClientExtension};
//! use rustls::msgs::enums::{Compression, HandshakeType};
//!
//! # let client_put = tlspuffin::put_registry::current_put();
//! # let server_put = tlspuffin::put_registry::current_put();
//!
//! let client: AgentName = AgentName::first();
//! let server: AgentName = client.next();
//!
//! let query = Query {
//!     agent_name: client,
//!     tls_message_type: Some(TlsMessageType::Handshake(Some(HandshakeType::ClientHello))),
//!     counter: 0
//! };
//! let trace = Trace {
//!     prior_traces: vec![],
//!     descriptors: vec![
//!         AgentDescriptor::new_client(client, V1_3, client_put),
//!         AgentDescriptor::new_server(server, V1_3, server_put),
//!     ],
//!     steps: vec![
//!             Step { agent: client, action: Action::Output(OutputAction { }) },
//!             // Client: Hello Client -> Server
//!             Step {
//!                 agent: server,
//!                 action: Action::Input(InputAction {
//!                     recipe: Term::Application(
//!                         Signature::new_function(&fn_client_hello),
//!                         vec![
//!                             Term::Variable(Signature::new_var::<ProtocolVersion>(query)),
//!                             Term::Variable(Signature::new_var::<Random>(query)),
//!                             Term::Variable(Signature::new_var::<SessionID>(query)),
//!                             Term::Variable(Signature::new_var::<Vec<CipherSuite>>(query)),
//!                             Term::Variable(Signature::new_var::<Vec<Compression>>(query)),
//!                             Term::Variable(Signature::new_var::<Vec<ClientExtension>>(query)),
//!                         ],
//!                     ),
//!                 }),
//!             },
//!     // further steps here
//!     ]
//! };
//! let mut ctx = TraceContext::new();
//! trace.execute(&mut ctx).unwrap();
//! ```

use std::process::ExitCode;

use crate::put_registry::PUT_REGISTRY;

mod claims;
mod debug;
mod extraction;
#[cfg(feature = "openssl-binding")]
mod openssl;
mod put;
mod put_registry;
mod query;
mod static_certs;
mod tcp;
mod tls;
#[cfg(feature = "wolfssl-binding")]
mod wolfssl;

pub fn main() -> ExitCode {
    puffin::cli::main(&PUT_REGISTRY)
}
