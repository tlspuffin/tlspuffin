use std::process::ExitCode;

use tlspuffin::put_registry::tls_registry;

pub fn main() -> ExitCode {
    puffin::cli::main(
        "Fuzzes the TLS protocol at the symbolic level",
        tls_registry(),
    )
}
