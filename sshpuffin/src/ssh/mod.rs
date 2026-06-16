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

use puffin::algebra::dynamic_function::FunctionAttributes;
pub mod deframe;
pub mod message;
pub(crate) mod seeds;
#[path = "."]
pub mod fn_impl {
    pub mod fn_constants;
    pub mod fn_message;

    pub use fn_constants::*;
    pub use fn_message::*;
}

use fn_impl::*;
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
    fn_raw_message
    fn_onwire_message
    fn_banner
    fn_disconnect
    fn_ignore
    fn_unimplemented
    fn_debug
    fn_service_request
    fn_service_accept
    fn_kex_init
    fn_kex_ecdh_init
    fn_kex_ecdh_reply
    fn_new_keys
    fn_user_auth_request
    fn_user_auth_failure
    fn_user_auth_success
    fn_user_auth_banner
    fn_global_request
    fn_request_success
    fn_request_failure
    fn_channel_open
    fn_channel_open_confirmation
    fn_channel_open_failure
    fn_channel_window_adjust
    fn_channel_data
    fn_channel_extended_data
    fn_channel_eof
    fn_channel_close
    fn_channel_request
    fn_channel_success
    fn_channel_failure
);
