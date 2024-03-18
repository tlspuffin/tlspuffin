use std::process::ExitCode;

use tlspuffin::put_registry::tls_registry;

pub fn main() -> ExitCode {
    puffin::cli::main(tls_registry())
}
