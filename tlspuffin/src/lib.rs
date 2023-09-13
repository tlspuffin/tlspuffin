//! TODO: Write intro: https://github.com/tlspuffin/tlspuffin/issues/94
//!
//! ### Used protocol and cryptographic libraries
//!
//! In order to easily implement concrete functions, we use several libraries which provide us with predefined encoders for TLS packets, cryptographic primitives, as well as higher level cryptographic operations specific for TLS.
//!
//! We forked the [rustls](https://github.com/ctz/rustls) library for cryptographic operations like deriving secrets. We also use it to encode and decode TLS messages.
//!
//! The cryptographic library [ring](https://github.com/briansmith/ring) allows us to use the derived secrets to encrypt and decrypt TLS messages.
//! # Example
//!
//! ```rust
//! use puffin::agent::{AgentName, AgentDescriptor, TLSVersion::*};
//! use puffin::trace::{Step, TraceContext, Trace, Action, InputAction, OutputAction, Query};
//! use puffin::algebra::{TermEval, Term, signature::Signature};
//! use tlspuffin::tls::fn_impl::fn_client_hello;
//! use tlspuffin::tls::rustls::msgs::handshake::{SessionID, Random, ClientExtension};
//! use tlspuffin::tls::rustls::msgs::enums::{ProtocolVersion, CipherSuite, Compression, HandshakeType};
//! use tlspuffin::put_registry::TLS_PUT_REGISTRY;
//! use tlspuffin::query::TlsQueryMatcher;
//!
//!
//! let client: AgentName = AgentName::first();
//! let server: AgentName = client.next();
//!
//! let trace = Trace {
//!     prior_traces: vec![],
//!     descriptors: vec![
//!         AgentDescriptor::new_client(client, V1_3),
//!         AgentDescriptor::new_server(server, V1_3),
//!     ],
//!     steps: vec![
//!             OutputAction::new_step(client),
//!             // Client: Hello Client -> Server
//!             Step {
//!                 agent: server,
//!                 action: Action::Input(InputAction {
//!                     recipe: TermEval::from(Term::Application(
//!                         Signature::new_function(&fn_client_hello),
//!                         vec![
//!                             TermEval::from(Term::Variable(Signature::new_var_with_type::<ProtocolVersion, _>(
//!                                     client,  
//!                                     Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ClientHello))),
//!                                     0
//!                             ))),
//!                             TermEval::from(Term::Variable(Signature::new_var_with_type::<Random, _>(
//!                                     client,  
//!                                     Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ClientHello))),
//!                                     0
//!                             ))),
//!                             TermEval::from(Term::Variable(Signature::new_var_with_type::<SessionID, _>(
//!                                     client,  
//!                                     Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ClientHello))),
//!                                     0
//!                             ))),
//!                             TermEval::from(Term::Variable(Signature::new_var_with_type::<Vec<CipherSuite>, _>(
//!                                     client,  
//!                                     Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ClientHello))),
//!                                     0
//!                             ))),
//!                             TermEval::from(Term::Variable(Signature::new_var_with_type::<Vec<Compression>, _>(
//!                                     client,  
//!                                     Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ClientHello))),
//!                                     0
//!                             ))),
//!                             TermEval::from(Term::Variable(Signature::new_var_with_type::<Vec<ClientExtension>, _>(
//!                                     client,  
//!                                     Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ClientHello))),
//!                                     0
//!                             ))),
//!                         ],
//!                     )),
//!                 }),
//!             },
//!     // further steps here
//!     ]
//! };
//! ```
//!
//! # Example with `term!` macro
//!
//! ```rust
//! use puffin::agent::AgentName;
//! use puffin::term;
//! use tlspuffin::tls::fn_impl::fn_client_hello;
//! use tlspuffin::tls::rustls::msgs::handshake::{SessionID, Random, ClientExtension};
//! use tlspuffin::tls::rustls::msgs::enums::{Compression, HandshakeType, ProtocolVersion, CipherSuite};
//! use puffin::algebra::TermEval;
//! use tlspuffin::query::TlsQueryMatcher;
//!
//! let client = AgentName::first();
//! let term: TermEval<TlsQueryMatcher> = term! {
//!     fn_client_hello(
//!         ((client, 0)/ProtocolVersion),
//!         ((client, 0)/Random),
//!         ((client, 0)/SessionID),
//!         ((client, 0)/Vec<CipherSuite>),
//!         ((client, 0)/Vec<Compression>),
//!         ((client, 0)/Vec<ClientExtension>)
//!     )
//! };
//! ```
//!

pub mod claims;
pub mod debug;
#[cfg(feature = "openssl-binding")]
pub mod openssl;
mod protocol;
pub mod put;
pub mod put_registry;
pub mod query;
pub mod static_certs;
pub mod tcp;
pub mod tls;
#[cfg(feature = "wolfssl-binding")]
pub mod wolfssl;

#[cfg(test)]
mod integration_tests;
#[cfg(test)]
mod test_utils;
