use std::collections::HashMap;

use puffin::put_registry::{Factory, PutRegistry};

use crate::protocol::OpcuaProtocolBehavior;

pub fn opcua_registry() -> PutRegistry<OpcuaProtocolBehavior> {
    let puts: HashMap<String, Box<dyn Factory<OpcuaProtocolBehavior>>> = HashMap::new();
    let default = String::from("");
    PutRegistry::new(puts, default)
    //panic!("Not implemented yet for OPC UA");
}
