#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(unused)]

pub use ffi::{Claim, ClaimType, TLSLike, CLAIM_INTERFACE_H};
pub use register::{register_claimer, deregister_claimer};

pub mod register;
mod ffi;
pub mod check;
