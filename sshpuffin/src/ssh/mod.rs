// FIXME stabilize sshpuffin and reactivate the dead_code lint
//
//     Currently sshpuffin contains many functions that are unused but will be
//     necessary for the full implementation. To avoid the many unhelpful
//     warning messages, we deactivate the dead_code lint globally in this
//     module.
//
//     Once the necessary features and API of sshpuffin are more stable, we
//     should reactivate the dead_code lint, as it provides valuable insights.
#![allow(dead_code)]

pub mod deframe;
pub mod message;
mod seeds;
#[path = "."]
pub mod fn_impl {
    pub mod fn_constants;
    pub mod fn_message;

    pub use fn_constants::*;
    pub use fn_message::*;
}

use fn_impl::*;
use puffin::algebra::dynamic_function::FunctionAttributes;
use puffin::define_signature;

use crate::protocol::SshProtocolTypes;

define_signature!(
    SSH_SIGNATURE<SshProtocolTypes>,
    fn_true
    fn_false
    fn_seq_0
    fn_seq_1
    fn_seq_2
    fn_seq_3
    fn_seq_4
    fn_seq_5
    fn_seq_6
    fn_seq_7
    fn_seq_8
    fn_seq_9
    fn_seq_10
    fn_seq_11
    fn_seq_12
    fn_seq_13
    fn_seq_14
    fn_seq_15
    fn_seq_16
    fn_empty_bytes_vec
);
