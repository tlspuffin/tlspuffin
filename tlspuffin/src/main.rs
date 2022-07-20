use std::process::ExitCode;

use crate::put_registry::PUT_REGISTRY;

mod claims;
mod debug;
mod extraction;
#[cfg(feature = "openssl-binding")]
mod openssl;
mod put;
mod put_registry;
mod static_certs;
mod tcp;
mod tls;
#[cfg(feature = "wolfssl-binding")]
mod wolfssl;

pub fn main() -> ExitCode {
    puffin::cli::main(&PUT_REGISTRY)
}
