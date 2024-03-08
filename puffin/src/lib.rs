#![allow(unused_doc_comments)]

pub mod agent;
pub mod algebra;
pub mod claims;
pub mod cli;
pub mod codec;
pub mod error;
pub mod experiment;
pub mod fuzzer;
pub mod graphviz;
pub mod log;
pub mod protocol;
pub mod put;
pub mod put_registry;
pub mod stream;
pub mod test_utils;
pub mod trace;
pub mod variable_data;

pub use libafl;

pub const GIT_REF: &str = match option_env!("GIT_REF") {
    Some(env) => env,
    None => "undefined",
};

pub const MAYBE_GIT_REF: Option<&str> = option_env!("GIT_REF");

pub const GIT_MSG: &str = match option_env!("GIT_MSG") {
    Some(env) => env,
    None => "undefined",
};
