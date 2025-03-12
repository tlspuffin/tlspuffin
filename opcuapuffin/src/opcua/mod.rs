//! The *opcua* module provides concrete implementations for the functions used in the term.
//!
//! The module offers a variety of
//! [`DynamicFunction`](puffin::algebra::dynamic_function::DynamicFunction)s which can be used in
//! the fuzzing.

use puffin::algebra::dynamic_function::FunctionAttributes;
//use puffin::algebra::error::FnError;
use puffin::define_signature; //puffin/algebra/signature.rs
//use puffin::error::Error;

use crate::protocol::OPCUAProtocolTypes;

pub mod fn_constants;
pub use fn_constants::*;

pub struct MSG_type {
    payload: Vec<u8>,
}

pub fn fn_open_channel_request() -> Result<MSG_type, FnError> {
    Ok(MSG)
}

define_signature!{
    OPCUA_SIGNATURE<OPCUAProtocolTypes>,
    // constants
    fn_true
    fn_false
    fn_open_channel_request
}