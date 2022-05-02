//! TODO: Write intro: https://gitlab.inria.fr/mammann/tlspuffin/-/issues/64
//!
//! ### Used protocol and cryptographic libraries
//!
//! In order to easily implement concrete functions, we use several libraries which provide us with predefined encoders for TLS packets, cryptographic primitives, as well as higher level cryptographic operations specific for TLS.
//!
//! We forked the [rustls](https://github.com/ctz/rustls) library for cryptographic operations like deriving secrets. We also use it to encode and decode TLS messages.
//!
//! The cryptographic library [ring](https://github.com/briansmith/ring) allows us to use the derived secrets to encrypt and decrypt TLS messages.

#![allow(unused_doc_comments)]

#[macro_use]
extern crate log;

pub mod agent;
pub mod error;
pub mod fuzzer;
pub mod graphviz;
pub mod io;
pub mod term;
#[allow(clippy::ptr_arg)]
pub mod tls;
pub mod trace;
pub mod variable_data;

mod debug;
mod experiment;
pub mod openssl_binding;
pub mod wolfssl_binding;
pub mod concretize;
mod tests;