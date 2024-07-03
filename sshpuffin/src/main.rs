mod claim;
mod libssh;
mod protocol;
mod put_registry;
mod query;
mod ssh;
mod violation;

use std::process::ExitCode;

use crate::put_registry::ssh_registry;

pub fn main() -> ExitCode {
    puffin::cli::main(
        "Fuzzes the SSH protocol at the symbolic level",
        ssh_registry(),
    )
}
