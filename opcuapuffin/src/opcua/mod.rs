//! The *opcua* module provides concrete implementations for the functions used in the term,
//! based on the rustopcua implementation.
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

use crate::types::OpcuaProtocolTypes;

pub mod seeds;

pub mod fn_constants;
pub use fn_constants::*;

// UA Secure Channel (Part 6)
pub mod channel;
pub use channel::*; 

// Services (Part 4)
// pub mod services;
// pub use services::*;

define_signature!{
    OPCUA_SIGNATURE<OpcuaProtocolTypes>,
    // constants
    // fn_true
    // fn_false
    // fn_seq_0
    //fn_open_channel_request
    fn_message_chunk
}