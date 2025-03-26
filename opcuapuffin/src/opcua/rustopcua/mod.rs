//! Extracted from lib `opcua`, the OPCUA Rust library, an "OPC UA client and server API".
//!
//! version = "0.13.0" # OPCUARustVersion
//! authors = ["Adam Lock <locka99@gmail.com>"]
//! license = "MPL-2.0"
//! documentation = "<https://docs.rs/opcua/>"
//!
//! See [opcua](https://github.com/locka99/opcua/commit/fcc89d8f8b93b5a0943ec8086706e883900faa3c) fork.
//! Upstreaming this fork is becoming unfeasible and there are no benefits in keeping up with the
//! latest version. If we want to support fuzzing new features of upcomping OPC UA versions
//! then we have to manually integrate them.
//! 
//! This module contains primitives required to perform OPC UA communications.

pub mod core;
pub mod types;