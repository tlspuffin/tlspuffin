// This is the raw C interface to the PUT, i.e. put.h
use crate::puts::opcua_sys::OPCUA_PUT_INTERFACE;

extern "C" {
    #[cfg(not(feature = "gcov"))]
    pub fn s2opc() -> OPCUA_PUT_INTERFACE;
    #[cfg(feature = "gcov")]
    #[link_name = "s2opc_gcov"]
    pub fn s2opc() -> OPCUA_PUT_INTERFACE;
}