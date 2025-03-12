//! The *opcua* module provides concrete implementations for the functions used in the term.
//!
//! The module offers a variety of
//! [`DynamicFunction`](puffin::algebra::dynamic_function::DynamicFunction)s which can be used in
//! the fuzzing.

use puffin::algebra::dynamic_function::FunctionAttributes;
//use puffin::algebra::error::FnError;
use puffin::define_signature; //puffin/algebra/signature.rs
//use puffin::error::Error;

use crate::protocol::OPCProtocolTypes;

pub mod fn_constants;
pub use fn_constants::*;

define_signature!{
    OPCUA_SIGNATURE<OPCProtocolTypes>,
    // constants
    fn_true
    fn_false
}