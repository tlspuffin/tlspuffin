//! The *opcua* module provides concrete implementations for the functions used in the term,
//! based on the rustopcua implementation.
//!
//! The module offers a variety of
//! [`DynamicFunction`](puffin::algebra::dynamic_function::DynamicFunction)s which can be used in
//! the fuzzing.

// The main part of the module has been transferred in crates/opcua-mapper/lib/src/puffin

pub mod seeds;
pub mod violations;
