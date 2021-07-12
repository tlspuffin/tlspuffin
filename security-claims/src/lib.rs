#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

pub use ffi::{Claim, ClaimType, CLAIM_INTERFACE_H};
pub use register::{register_claimer, deregister_claimer};
use ffi::TLSLike;

pub mod register;
mod ffi;
pub mod check;
