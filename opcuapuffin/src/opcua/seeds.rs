//! Implementation of special traces, used to start the fuzzing.
//! Each may represent a special execution of OPC UA, like a full handshake
//! or the execution of a known attack.
#![allow(dead_code)]

use opcua::puffin::types::OpcuaProtocolTypes;
use puffin::trace::Trace;

use crate::protocol::OpcuaProtocolBehavior;

// This macro, copied from TLSPuffin, should be in Puffin??
macro_rules! corpus {
    () => {
        vec![]
    };

    ( $( $func:ident : $cond:expr ),* $(,)? ) => {
        {
            use puffin::trace_helper::TraceHelper;
            let mut corpus = vec![];

            $(
                if $cond {
                    corpus.push(($func.build_trace(), $func.fn_name()));
                }
            )*

            corpus
        }
    };
}

pub fn create_corpus(
    _put: &dyn puffin::put_registry::Factory<OpcuaProtocolBehavior>,
) -> Vec<(Trace<OpcuaProtocolTypes>, &'static str)> {
    corpus!(
        // Full Handshakes

        // Client Attacks

        // Server Attacks

    )
}
