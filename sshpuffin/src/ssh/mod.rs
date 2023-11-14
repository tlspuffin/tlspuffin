pub mod deframe;
mod fn_message;
pub mod message;
mod seeds;

#[path = "."]
pub mod fn_impl {
    pub mod fn_constants;
    pub mod fn_message;

    pub use fn_constants::*;
    pub use fn_message::*;
}

use std::fmt::Debug;

use fn_impl::*;
use puffin::define_signature;

define_signature!(
    SSH_SIGNATURE,
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
