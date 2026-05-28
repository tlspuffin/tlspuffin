use std::process::ExitCode;

use opcuapuffin::put_registry::opcua_registry;

pub fn main() -> ExitCode {
    puffin::cli::main(
        "Fuzzes the OPC UA protocol at the symbolic level",
        opcua_registry(),
    )
}

#[no_mangle]
pub unsafe extern "C" fn atexit(_f: extern "C" fn()) -> libc::c_int {
    0
}
