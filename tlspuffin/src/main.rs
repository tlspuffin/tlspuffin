use std::process::ExitCode;

mod claims;
mod debug;
mod extraction;
#[cfg(feature = "openssl-binding")]
mod openssl;
mod put_registry;
mod static_certs;
mod tcp;
mod tls;
#[cfg(feature = "wolfssl-binding")]
mod wolfssl;

pub fn main() -> ExitCode {
    puffin::main::main()
}
