//! Simple seeds for sppuffin protocol.
//! Minimal trace with one agent and basic actions.

use puffin::agent::{AgentDescriptor, AgentName};
use puffin::trace::{Action, InputAction, Step, Trace};
use puffin::{input_action, term};

use crate::fn_impl::*;

use crate::fn_impl::SwissProtocolTypes;

/// Simple seed: one agent with 3 steps
pub fn seed_simple_three_terms() -> Trace<SwissProtocolTypes> {
    let agent = AgentName::first();

    Trace {
        prior_traces: vec![],
        descriptors: vec![AgentDescriptor::from_name(agent)],
        steps: vec![Step {
            agent,
            action: Action::Input(input_action! { term! {
               // fn_immutable_byte_array_length(
                   fn_new_immutable_byte_array
               // )
                }
            }),
        }],
        metadata_trace: Default::default(),
    }
}
