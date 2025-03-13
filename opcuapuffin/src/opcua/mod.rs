//! The *opcua* module provides concrete implementations for the functions used in the term.
//!
//! The module offers a variety of
//! [`DynamicFunction`](puffin::algebra::dynamic_function::DynamicFunction)s which can be used in
//! the fuzzing.

use puffin::protocol::EvaluatedTerm;
use puffin::codec;
use puffin::trace::Source;
use puffin::protocol::ProtocolTypes;
use puffin::trace::Knowledge;
use puffin::protocol::Extractable;
use puffin::dummy_codec;
use puffin::dummy_extract_knowledge;
use puffin::dummy_extract_knowledge_codec;
use puffin::algebra::dynamic_function::FunctionAttributes;
use puffin::algebra::error::FnError;
use puffin::define_signature; //puffin/algebra/signature.rs
use puffin::error::Error;

use crate::protocol::OpcuaProtocolTypes;

//pub mod claims;
pub mod rustopcua;
pub mod seeds;

pub mod fn_constants;
pub use fn_constants::*;

#[derive(Debug,Clone)]
pub struct OPN_channel_request {
    payload: Vec<u8>,
}

dummy_extract_knowledge_codec!(
    OpcuaProtocolTypes,
    OPN_channel_request
);

pub fn fn_open_channel_request() -> Result<OPN_channel_request, FnError> {
    Ok(OPN_channel_request {
        payload: vec![0x01, 0x02, 0x03, 0x04],
    })
}

define_signature!{
    OPCUA_SIGNATURE<OpcuaProtocolTypes>,
    // constants
    // fn_true
    // fn_false
    // fn_seq_0
    fn_open_channel_request
    //fn_open_channel_request
}