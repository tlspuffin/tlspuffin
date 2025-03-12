use std::process::ExitCode;

use crate::put_registry::opc_registry;

pub fn main() -> ExitCode {
    puffin::cli::main(
        "Fuzzes the OPC UA protocol at the symbolic level",
        opc_registry(),
    )
}