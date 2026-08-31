//! The *tls* module provides concrete implementations for the functions used in the term.
//!
//! The module offers a variety of
//! [`DynamicFunction`](puffin::algebra::dynamic_function::DynamicFunction)s which can be used in
//! the fuzzing.

use fn_impl::*;
use puffin::algebra::error::FnError;
use puffin::error::Error;
use puffin::{declare_signature, define_readable_types, define_signature};

use crate::protocol::TLSProtocolTypes;

mod key_exchange;
mod key_schedule;
mod sign;

pub mod differential_rfc_violations;
pub mod rustls;
pub mod seeds;
pub mod violation;
pub mod vulnerabilities;

/// This module contains all the concrete implementations of function symbols.
#[path = "."]
pub mod fn_impl {
    pub mod fn_cert;
    pub mod fn_constants;
    pub mod fn_extensions;
    pub mod fn_fields;
    pub mod fn_messages;
    pub mod fn_transcript;
    pub mod fn_utils;

    pub use fn_cert::*;
    pub use fn_constants::*;
    pub use fn_extensions::*;
    pub use fn_fields::*;
    pub use fn_messages::*;
    pub use fn_transcript::*;
    pub use fn_utils::*;
}

impl From<rustls::error::Error> for Error {
    fn from(error: rustls::error::Error) -> Self {
        Error::Stream(error.to_string())
    }
}

/// Function symbol which can be used for debugging
#[allow(dead_code)]
fn fn_debug(
    message: &crate::tls::rustls::msgs::message::Message,
) -> Result<crate::tls::rustls::msgs::message::Message, FnError> {
    dbg!(message);
    Ok(message.clone())
}

#[macro_export]
macro_rules! nyi_fn {
    ($(#[$attr:meta])*) => {};
}

declare_signature!(TLS_SIGNATURE<TLSProtocolTypes>);

// `TLS_SIGNATURE` also carries the types a bitstring can be read back into, see
// `TLSProtocolBehavior::try_read_bytes`. Every type deriving `Constructor` registers itself, so
// what is left to register by hand is what the derive does not reach: the types below and the
// handful defined outside the term algebra (transcripts, `HandshakeHash`), each registered with
// `define_readable_types!` in the module defining it.
//
// A type is only readable if `encode` then `read` round-trips on its own; those that need context
// the bitstring does not carry (`MessagePayload`, `HandshakePayload`) or that drop fields on
// `read` (`ServerHelloPayload`) opt out with `#[constructor_no_try_read]`.
//
// The uni-test `term_zoo::test_term_read_encode` checks that this is exhaustive for the TLS
// signature at least.
define_readable_types!(
    TLS_SIGNATURE,
    TLSProtocolTypes;
    u64,
    u32,
    u16,
    u8,
    bool,
    Vec<u8>,
    Option<Vec<u8>>,
    Vec<Vec<u8>>,
);

define_signature!(
    TLS_SIGNATURE,
    TLSProtocolTypes;
    // The constructors that a `#[derive(Constructor)]` on the corresponding rustls message type
    // now generates have been removed from `fn_impl` entirely, along with the `fn_get_*` / `fn_find_*`
    // accessors that deconstructor terms replace. What stays hand-written and registered here is
    // what the derive cannot produce:
    //  - value corpora: a constant whose type takes data the term algebra cannot produce
    //    (`fn_random`, `fn_sessionid`, the certificates and keys, ...), a specific
    //    interesting value (`fn_invalid_signature_algorithm`), or a curated list
    //    (`fn_signature_algorithm_cert_extension`);
    //  - constructors whose type has a non-compositional encoding, i.e. a field that does not
    //    appear in the parent encoding as its own encoding: `fn_hello_retry_request`,
    //    `fn_certificate_request13`;
    //  - constructors whose type only has a dummy codec, so a term of that type has no
    //    meaningful encoding: `fn_unknown_*_extension`, `fn_session_ticket_*_extension`;
    //  - everything that computes rather than constructs (transcripts, key shares, signatures,
    //    en/decryption).
    // constants
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
    fn_large_length
    fn_empty_bytes_vec
    fn_large_bytes_vec [no_bit] // exclude MakeMessage and thus bit-level mutations
    // messages
    fn_certificate_request13
    fn_hello_retry_request [get] // because some compressions get lost
    fn_hello_retry_request_random
    // extensions
    fn_empty_vec_of_vec
    fn_append_vec [list]
    fn_session_ticket_request_extension
    fn_session_ticket_offer_extension
    fn_preshared_keys_extension_empty_binder [opaque]
    fn_certificate_authorities_extension
    fn_signature_algorithm_cert_extension
    fn_key_share_deterministic
    fn_unknown_client_extension
    fn_unknown_server_extension
    fn_unknown_hello_retry_extension
    fn_unknown_cert_request_extension
    fn_unknown_new_session_ticket_extension
    fn_unknown_certificate_extension
    // fields
    fn_empty_session_id
    fn_no_key_share
    fn_get_client_key_share [get]
    fn_verify_data [opaque]
    fn_verify_data_server [opaque]
    fn_client_sign_transcript [opaque]
    fn_server_sign_transcript [opaque]
    // The cipher suites are the `#[constructor_no_skip]` variants of `CipherSuite` itself, see
    // `msgs::enums`.
    // utils
    fn_coalesced_flight [opaque]
    fn_new_transcript
    fn_new_hrr_transcript [opaque]
    fn_append_transcript [opaque] // this one is opaque and not list since it returns the hash of all elements added to the list so far
    fn_decrypt_handshake_flight [opaque]
    fn_decrypt_multiple_handshake_messages [opaque] [no_gen]
    fn_decrypt_application_flight [opaque]
    fn_no_psk
    fn_psk
    fn_decrypt_application [opaque] [no_gen]
    fn_encrypt_handshake [opaque]
    fn_encrypt_handshake_opaque [opaque]
    fn_encrypt_application [opaque]
    fn_derive_psk [opaque]
    fn_derive_binder [opaque]
    fn_fill_binder [opaque]
    fn_new_transcript12
    fn_decode_server_ecdh_pubkey [opaque]
    fn_decode_client_ecdh_pubkey [opaque]
    fn_sign_rsa_ecdhe_server_key_exchange12 [opaque]
    fn_encode_ec_pubkey12
    fn_new_pubkey12 [opaque]
    fn_encrypt12 [opaque]
    fn_decrypt12 [no_gen]
    fn_new_certificate
    fn_u64_to_u32 [get]
    fn_u32_to_u16 [get]
    // transcript functions
    fn_server_hello_transcript [opaque] [no_gen]
    fn_client_finished_transcript [opaque] [no_gen]
    fn_server_finished_transcript [opaque] [no_gen]
    fn_certificate_transcript [opaque] [no_gen]
    // certificate functions
    fn_bob_cert
    fn_bob_key
    fn_alice_cert
    fn_alice_key
    fn_eve_cert
    fn_random_ec_cert
    fn_random_ec_key
    fn_eve_pkcs1_signature
    fn_rsa_sign_client [opaque]
    fn_rsa_sign_server [opaque]
    fn_ecdsa_sign_client [opaque] [no_det] // fn_ecdsa_sign_client has built-in randomness
    // TODO: replace this with explicit term
    fn_ecdsa_sign_server [opaque]
    fn_invalid_signature_algorithm
);
