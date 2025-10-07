use puffin::put_registry::PutRegistry;

use crate::protocol::OpcuaProtocolBehavior;

pub const OPEN62541: &str = "open62541";

pub fn opcua_registry() -> PutRegistry<OpcuaProtocolBehavior> {
    PutRegistry::new(
        [(OPEN62541, crate::harnesses::open62541::new_opcua_factory())],
        OPEN62541,
    )
}