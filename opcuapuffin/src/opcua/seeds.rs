//! Implementation of special traces, used to start the fuzzing.
//! Each may represent a special execution of OPC UA, like a full handshake
//! or the execution of a known attack.
#![allow(dead_code)]

//use opcua::puffin::query::OpcuaQueryMatcher;
use opcua::puffin::signature::fn_client_hello;
use opcua::puffin::signature::fn_impl::{fn_bob_endpoint, fn_default_size};
use opcua::puffin::types::{OpcuaDescriptorConfig, OpcuaProtocolTypes};

use puffin::agent::AgentName;
use puffin::{input_action, term};
use puffin::trace::{Action, InputAction, Step, Trace};

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
    put: &dyn puffin::put_registry::Factory<OpcuaProtocolBehavior>,
) -> Vec<(Trace<OpcuaProtocolTypes>, &'static str)> {
    corpus!(
        // Hello Bob!
        seed_a_hello_bob: put.supports("v1.3")

        // Full Handshakes

        // Client Attacks

        // Server Attacks

    )
}

pub fn seed_A_hello_bob (
    server: AgentName,
) -> Trace<OpcuaProtocolTypes> {
    Trace {
    prior_traces: vec![],
        descriptors: vec![
            OpcuaDescriptorConfig::new_server(server)
        ],
        steps: vec![
            Step {
                agent: server,
                action: Action::Input(input_action! { term! {
                        fn_client_hello (
                            fn_bob_endpoint,
                            fn_default_size,
                            fn_default_size
                        )
                    }
                }),
            },


        ]
        }
}