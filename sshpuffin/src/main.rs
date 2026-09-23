use std::process::ExitCode;

use sshpuffin::put_registry::ssh_registry;

pub fn main() -> ExitCode {
    puffin::cli::main(
        "Fuzzes the SSH protocol at the symbolic level",
        ssh_registry(),
    )
}
