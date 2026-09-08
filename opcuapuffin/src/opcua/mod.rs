//! The OPC UA protocol module
//!
//! The module offers a variety of
//! [`DynamicFunction`](puffin::algebra::dynamic_function::DynamicFunction)s which can be used in
//! the fuzzing to represent OPC UA messages.

// The main part of the module has been transferred in crates/opcua-mapper/lib/src/puffin,
// that provides concrete implementations for the functions used in the term,
//! based on the rust OPC UA implementation.

pub mod seeds;
pub mod violations;
pub mod vulnerabilities;
