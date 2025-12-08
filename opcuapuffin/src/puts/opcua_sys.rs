// This is the raw C interface to the PUT, described in include/puffin/opcua.h
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]
include!(env!("RUST_BINDINGS_FILE"));

use std::ptr::null;
use opcua::puffin::static_certs;
use opcua::puffin::types::OpcuaVersion;

pub fn version_of(version: OpcuaVersion) -> OPCUA_VERSION {
    match version {
        OpcuaVersion::V1_4 => OPCUA_VERSION::V1_4,
        OpcuaVersion::V1_5 => OPCUA_VERSION::V1_5
    }
}


// Certificates:
macro_rules! pem {
    ($pemder: ident) => {
        pub const $pemder: PEM = PEM {
            length: static_certs::$pemder.0.len(),
            bytes: static_certs::$pemder.0.as_ptr(),
        };
    }
}

pem!(ALICE_CERTIFICATE);
pem!(ALICE_PRIVATE_KEY);
pem!(BOB_CERTIFICATE);
pem!(BOB_PRIVATE_KEY);

pub const VOID_STORE: *const PEM = null();
