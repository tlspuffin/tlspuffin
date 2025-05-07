use std::process::ExitCode;

use opcuapuffin::put_registry::opcua_registry;

pub fn main() -> ExitCode {
    puffin::cli::main(
        "Fuzzes the OPC UA protocol at the symbolic level",
        opcua_registry(),
    )
}
