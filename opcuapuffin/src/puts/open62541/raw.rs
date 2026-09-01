// This is the raw C interface to the PUT, i.e. put.h
use crate::puts::opcua_sys::OPCUA_PUT_INTERFACE;

extern "C" {
    #[cfg(not(feature = "gcov"))]
    pub fn open62541() -> OPCUA_PUT_INTERFACE;
    #[cfg(feature = "gcov")]
    #[link_name = "open62541_gcov"]
    pub fn open62541() -> OPCUA_PUT_INTERFACE;
}
