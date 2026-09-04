// #![allow(non_upper_case_globals)]
// #![allow(non_camel_case_types)]
// #![allow(non_snake_case)]
// include!(concat!(env!("OUT_DIR"), "/harness_bundle/put_bindings.rs"));

use puffin::put::{PutDescriptor, PutOptions};
use puffin::put_registry::{PutRegistry, TCP_PUT};

use crate::protocol::OpcuaProtocolBehavior;

pub const OPEN62541: &str = "open62541";

pub fn opcua_registry() -> PutRegistry<OpcuaProtocolBehavior> {
    PutRegistry::new(
        [
            (OPEN62541, crate::puts::open62541::new_opcua_factory()),
            (TCP_PUT, crate::puts::tcp::new_opcua_factory()),
        ],
        PutDescriptor::new(OPEN62541, PutOptions::empty()),
    )
}

#[allow(unused)]
macro_rules! registration_c {
    ($id:ident, $name:expr, $harness_version:expr, $library_version:expr, $capabilities:expr) => {
        mod $id {
            // use super::GlobalFactory;
            // use crate::put_registry::bindings::TLS_PUT_INTERFACE;

            // pub fn register() -> Option<GlobalFactory> {
            //     let interface_ptr = unsafe { $id() };
            //     if interface_ptr.is_null() {
            //         log::error!("PUT registration failed: {} interface is NULL", &$name);
            //         return None;
            //     }

            //     let interface = unsafe { *interface_ptr.clone() };

            //     Some(GlobalFactory::CFactory(crate::put::CPut::new(
            //         $name,
            //         $harness_version,
            //         $library_version,
            //         $capabilities,
            //         interface,
            //     )))
            // }

            extern "C" {
                fn $id() -> *const OPCUA_PUT_INTERFACE;
            }
        }
    };
}
