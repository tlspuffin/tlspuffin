use std::process::ExitCode;

use tlspuffin::put_registry::TLS_PUT_REGISTRY;

pub fn main() -> ExitCode {
    puffin::cli::main(&TLS_PUT_REGISTRY)
}
