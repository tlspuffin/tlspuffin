use std::process::ExitCode;

use tlspuffin::put_registry::tls_default_registry;

pub fn main() -> ExitCode {
    #[cfg(feature = "cputs")]
    tls_harness::init();

    puffin::cli::main(tls_default_registry())
}
