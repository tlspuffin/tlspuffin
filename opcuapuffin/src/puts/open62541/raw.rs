// Disable several lints. The auto-generated bindings do not conform to them.
// TODO: Revisit and revise periodically, especially after changing the MSRV.
#![allow(unknown_lints, reason = "Rust versions")]
#![expect(clippy::allow_attributes)]
#![expect(clippy::allow_attributes_without_reason)]
#![expect(clippy::as_conversions)]
#![expect(clippy::cast_lossless)]
#![expect(clippy::cast_possible_truncation)]
#![expect(clippy::cast_possible_wrap)]
#![expect(clippy::default_trait_access)]
#![expect(clippy::indexing_slicing)]
#![expect(clippy::missing_assert_message)]
#![expect(clippy::missing_const_for_fn)]
#![expect(clippy::missing_safety_doc)]
#![expect(clippy::must_use_candidate)]
#![expect(clippy::ptr_as_ptr)]
#![expect(clippy::ptr_offset_with_cast)]
#![expect(clippy::pub_underscore_fields)]
#![expect(clippy::semicolon_if_nothing_returned)]
#![expect(clippy::transmute_int_to_bool)]
#![expect(clippy::transmute_ptr_to_ptr)]
#![expect(clippy::type_complexity)]
#![expect(clippy::unreadable_literal)]
#![expect(clippy::used_underscore_binding)]
#![expect(clippy::useless_transmute)]
#![expect(missing_debug_implementations)]
#![expect(non_camel_case_types)]
#![expect(non_snake_case)]
#![expect(unnecessary_transmutes)]
#![expect(unsafe_op_in_unsafe_fn)]
include!(concat!(env!("OUT_DIR"), "/open62541_bindings.rs"));


// This is the raw C interface to the PUT
use crate::puts::opcua_sys::OPCUA_PUT_INTERFACE;

extern "C" {
    pub fn open62541() -> OPCUA_PUT_INTERFACE;
}