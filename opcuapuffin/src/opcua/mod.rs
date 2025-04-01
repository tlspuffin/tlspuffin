//! The *opcua* module provides concrete implementations for the functions used in the term,
//! based on the rustopcua implementation.
//!
//! The module offers a variety of
//! [`DynamicFunction`](puffin::algebra::dynamic_function::DynamicFunction)s which can be used in
//! the fuzzing.

use puffin::protocol::{EvaluatedTerm, Extractable, ProtocolTypes};

pub mod seeds;

pub mod fn_constants;
pub use fn_constants::*;

// UA Secure Channel (Part 6)
pub mod channel;
pub use channel::*;

// Services (Part 4)
// pub mod services;
// pub use services::*;
