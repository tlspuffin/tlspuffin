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

extern crate core;
#[cfg(all(feature = "openssl-binding", feature = "wolfssl-binding"))]
compile_error!("`Only one binding at the same time is currently supported.");

pub mod agent;
pub mod algebra;
pub mod debug;
pub mod error;
pub mod experiment;
pub mod fuzzer;
pub mod graphviz;
pub mod io;
#[cfg(feature = "openssl-binding")]
pub mod openssl;
pub mod put;
pub mod put_registry;
pub mod static_certs;
#[allow(clippy::ptr_arg)]
pub mod tls;
pub mod trace;
pub mod variable_data;
#[cfg(feature = "wolfssl-binding")]
pub mod wolfssl;
