// This is the raw C interface to the PUT, described in harness/open62541/include/put.h
use crate::puts::opcua_sys::OPCUA_PUT_INTERFACE;

extern "C" {
    pub fn open62541() -> OPCUA_PUT_INTERFACE;
}