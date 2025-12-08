// This is the raw C interface to the PUT
use crate::puts::opcua_sys::OPCUA_PUT_INTERFACE;

extern "C" {
    pub fn open62541() -> OPCUA_PUT_INTERFACE;
}