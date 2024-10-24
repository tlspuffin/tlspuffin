//! TODO: Write intro: <https://github.com/tlspuffin/tlspuffin/issues/94>
//!
//! ### Used protocol and cryptographic libraries
//!
//! In order to easily implement concrete functions, we use several libraries which provide us with
//! predefined encoders for TLS packets, cryptographic primitives, as well as higher level
//! cryptographic operations specific for TLS.
//!
//! We forked the [rustls](https://github.com/ctz/rustls) library for cryptographic operations like deriving secrets. We also use it to encode and decode TLS messages.
//!
//! The cryptographic library [ring](https://github.com/briansmith/ring) allows us to use the derived secrets to encrypt and decrypt TLS messages.
//! # Example
//!
//! ```rust
//! use puffin::agent::TLSVersion::*;
//! use puffin::agent::{AgentDescriptor, AgentName};
//! use puffin::algebra::signature::Signature;
//! use puffin::algebra::{DYTerm, Term};
//! use puffin::input_action;
//! use puffin::trace::{
//!     Action, InputAction, OutputAction, Query, Source, Step, Trace, TraceContext,
//! };
//! use tlspuffin::protocol::TLSProtocolTypes;
//! use tlspuffin::query::TlsQueryMatcher;
//! use tlspuffin::tls::fn_impl::fn_client_hello;
//! use tlspuffin::tls::rustls::msgs::enums::{
//!     CipherSuite, Compression, HandshakeType, ProtocolVersion,
//! };
//! use tlspuffin::tls::rustls::msgs::handshake::{ClientExtension, Random, SessionID};
//!
//! let client: AgentName = AgentName::first();
//! let server: AgentName = client.next();
//!
//! let trace = Trace::<TLSProtocolTypes> {
//!     prior_traces: vec![],
//!     descriptors: vec![
//!         AgentDescriptor::new_client(client, V1_3),
//!         AgentDescriptor::new_server(server, V1_3),
//!     ],
//!     steps: vec![
//!         OutputAction::new_step(client),
//!         // Client: Hello Client -> Server
//!         Step {
//!             agent: server,
//!             action: Action::Input(input_action! {
//!                 Term::from(DYTerm::Application(
//!                     Signature::new_function(&fn_client_hello),
//!                     vec![
//!                         Term::from(DYTerm::Variable(Signature::new_var_with_type::<
//!                             ProtocolVersion,
//!                             _,
//!                         >(
//!                             Some(Source::Agent(client)),
//!                             Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ClientHello))),
//!                             0,
//!                         ))),
//!                         Term::from(DYTerm::Variable(
//!                             Signature::new_var_with_type::<Random, _>(
//!                                 Some(Source::Agent(client)),
//!                                 Some(TlsQueryMatcher::Handshake(Some(
//!                                     HandshakeType::ClientHello,
//!                                 ))),
//!                                 0,
//!                             ),
//!                         )),
//!                         Term::from(DYTerm::Variable(Signature::new_var_with_type::<
//!                             SessionID,
//!                             _,
//!                         >(
//!                             Some(Source::Agent(client)),
//!                             Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ClientHello))),
//!                             0,
//!                         ))),
//!                         Term::from(DYTerm::Variable(Signature::new_var_with_type::<
//!                             Vec<CipherSuite>,
//!                             _,
//!                         >(
//!                             Some(Source::Agent(client)),
//!                             Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ClientHello))),
//!                             0,
//!                         ))),
//!                         Term::from(DYTerm::Variable(Signature::new_var_with_type::<
//!                             Vec<Compression>,
//!                             _,
//!                         >(
//!                             Some(Source::Agent(client)),
//!                             Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ClientHello))),
//!                             0,
//!                         ))),
//!                         Term::from(DYTerm::Variable(Signature::new_var_with_type::<
//!                             Vec<ClientExtension>,
//!                             _,
//!                         >(
//!                             Some(Source::Agent(client)),
//!                             Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ClientHello))),
//!                             0,
//!                         ))),
//!                     ],
//!                 )),
//!             }),
//!         },
//!         // further steps here
//!     ],
//! };
//! ```
//!
//! # Example with `term!` macro
//! ```rust
//! use puffin::agent::AgentName;
//! use puffin::algebra::Term;
//! use puffin::term;
//! use puffin::trace::Source;
//! use tlspuffin::protocol::TLSProtocolTypes;
//! use tlspuffin::query::TlsQueryMatcher;
//! use tlspuffin::tls::fn_impl::fn_client_hello;
//! use tlspuffin::tls::rustls::msgs::enums::{
//!     CipherSuite, Compression, HandshakeType, ProtocolVersion,
//! };
//! use tlspuffin::tls::rustls::msgs::handshake::{ClientExtension, Random, SessionID};
//!
//! let client = AgentName::first();
//! let term: Term<TLSProtocolTypes> = term! {
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

#[cfg(feature = "boringssl-binding")]
pub mod boringssl;
#[cfg(feature = "libressl-binding")]
pub mod libressl;
#[cfg(feature = "openssl-binding")]
pub mod openssl;
#[cfg(feature = "wolfssl-binding")]
pub mod wolfssl;

#[cfg(feature = "rust-put")]
pub mod rand;

pub mod claims;
pub mod debug;
pub mod protocol;
pub mod put;
pub mod put_registry;
pub mod query;
pub mod static_certs;
pub mod tcp;
pub mod tls;

#[cfg(feature = "test-utils")]
pub mod test_utils;
