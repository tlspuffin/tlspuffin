mod claim;
mod libssh;
mod protocol;
mod put_registry;
mod ssh;
mod violation;

use std::process::ExitCode;

use crate::put_registry::SSH_PUT_REGISTRY;

pub fn main() -> ExitCode {
    puffin::cli::main(&SSH_PUT_REGISTRY)
}
