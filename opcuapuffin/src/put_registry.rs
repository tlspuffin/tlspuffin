use puffin::put_registry::PutRegistry;

use crate::protocol::OpcuaProtocolBehavior;

pub const OPEN62541: &str = "open62541";
pub const OPC_TCP: &str = "opc.tcp";

pub fn opcua_registry() -> PutRegistry<OpcuaProtocolBehavior> {
    PutRegistry::new(
        [(OPEN62541, crate::puts::open62541::new_opcua_factory()),
               (OPC_TCP, crate::puts::tcp::new_opcua_factory()),
        ],
        OPC_TCP,
    )
}