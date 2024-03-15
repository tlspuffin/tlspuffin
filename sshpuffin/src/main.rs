mod claim;
mod libssh;
mod protocol;
mod put_registry;
mod ssh;
mod violation;

use std::process::ExitCode;

use crate::put_registry::ssh_default_registry;

pub fn main() -> ExitCode {
    puffin::cli::main(ssh_default_registry())
}
