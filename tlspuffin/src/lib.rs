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
//! use puffin::agent::{AgentDescriptor, AgentName};
//! use puffin::algebra::signature::Signature;
//! use puffin::algebra::{DYTerm, Term};
//! use puffin::input_action;
//! use puffin::trace::{
//!     Action, InputAction, OutputAction, Query, Source, Step, Trace, TraceContext,
//! };
//! use tlspuffin::protocol::TLSVersion::*;
//! use tlspuffin::protocol::{TLSDescriptorConfig, TLSProtocolTypes};
//! use tlspuffin::query::TlsQueryMatcher;
//! use tlspuffin::tls::rustls::msgs::enums::{
//!     fn_handshaketype_clienthello, CipherSuite, Compression, HandshakeType, ProtocolVersion,
//! };
//! use tlspuffin::tls::rustls::msgs::handshake::{
//!     fn_clienthellopayload, fn_handshakemessagepayload, fn_handshakepayload_clienthello,
//!     CipherSuites, ClientExtension, ClientExtensions, Compressions, Random, SessionID,
//! };
//! use tlspuffin::tls::rustls::msgs::message::{fn_message, fn_messagepayload_handshake};
//!
//! let client: AgentName = AgentName::first();
//! let server: AgentName = client.next();
//!
//! // A variable reading one field out of the client's ClientHello.
//! fn var<T: 'static>(client: AgentName) -> Term<TLSProtocolTypes> {
//!     Term::from(DYTerm::Variable(Signature::new_var_with_type::<T, _>(
//!         Some(Source::Agent(client)),
//!         Some(TlsQueryMatcher::Handshake(Some(HandshakeType::ClientHello))),
//!         0,
//!     )))
//! }
//!
//! // A message is built from the constructors generated for the rustls types: the payload is
//! // wrapped into a handshake message, which is wrapped into a record. The `term!` macro below
//! // expands to exactly this shape.
//! let client_hello = Term::from(DYTerm::Application(
//!     Signature::new_function(&fn_message),
//!     vec![
//!         var::<ProtocolVersion>(client),
//!         Term::from(DYTerm::Application(
//!             Signature::new_function(&fn_messagepayload_handshake),
//!             vec![Term::from(DYTerm::Application(
//!                 Signature::new_function(&fn_handshakemessagepayload),
//!                 vec![
//!                     Term::from(DYTerm::Application(
//!                         Signature::new_function(&fn_handshaketype_clienthello),
//!                         vec![],
//!                     )),
//!                     Term::from(DYTerm::Application(
//!                         Signature::new_function(&fn_handshakepayload_clienthello),
//!                         vec![Term::from(DYTerm::Application(
//!                             Signature::new_function(&fn_clienthellopayload),
//!                             vec![
//!                                 var::<ProtocolVersion>(client),
//!                                 var::<Random>(client),
//!                                 var::<SessionID>(client),
//!                                 var::<CipherSuites>(client),
//!                                 var::<Compressions>(client),
//!                                 var::<ClientExtensions>(client),
//!                             ],
//!                         ))],
//!                     )),
//!                 ],
//!             ))],
//!         )),
//!     ],
//! ));
//!
//! let trace = Trace::<TLSProtocolTypes> {
//!     prior_traces: vec![],
//!     descriptors: vec![
//!         TLSDescriptorConfig::new_client(client, V1_3),
//!         TLSDescriptorConfig::new_server(server, V1_3),
//!     ],
//!     steps: vec![
//!         OutputAction::new_step(client),
//!         // Client: Hello Client -> Server
//!         Step {
//!             agent: server,
//!             action: Action::Input(input_action! { client_hello }),
//!         },
//!         // further steps here
//!     ],
//!     ..Default::default()
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
//! use tlspuffin::tls::rustls::msgs::enums::{
//!     fn_handshaketype_clienthello, CipherSuite, Compression, HandshakeType, ProtocolVersion,
//! };
//! use tlspuffin::tls::rustls::msgs::handshake::{
//!     fn_clienthellopayload, fn_handshakemessagepayload, fn_handshakepayload_clienthello,
//!     CipherSuites, ClientExtensions, Compressions, Random, SessionID,
//! };
//! use tlspuffin::tls::rustls::msgs::message::{fn_message, fn_messagepayload_handshake};
//!
//! let client = AgentName::first();
//! let term: Term<TLSProtocolTypes> = term! {
//!     fn_message(
//!         ((client, 0)/ProtocolVersion),
//!         fn_messagepayload_handshake(fn_handshakemessagepayload(
//!             fn_handshaketype_clienthello,
//!             fn_handshakepayload_clienthello(fn_clienthellopayload(
//!                 ((client, 0)/ProtocolVersion),
//!                 ((client, 0)/Random),
//!                 ((client, 0)/SessionID),
//!                 ((client, 0)/CipherSuites),
//!                 ((client, 0)/Compressions),
//!                 ((client, 0)/ClientExtensions)
//!             ))
//!         ))
//!     )
//! };
//! ```

#[cfg(feature = "rust-put")]
mod rust_put;

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
