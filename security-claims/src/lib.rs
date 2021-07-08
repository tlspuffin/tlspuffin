#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/claim-interface.rs"));

pub const CLAIM_INTERFACE_H: &'static str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/claim-interface.h"));
