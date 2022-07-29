use puffin::{
    agent::{AgentDescriptor, AgentName, AgentType, TLSVersion},
    algebra::AnyMatcher,
    term,
    trace::{InputAction, Trace},
};

use crate::ssh::fn_impl::fn_seq_0;

pub fn seed_successful(server: AgentName) -> Trace<AnyMatcher> {
    Trace {
        prior_traces: vec![],
        descriptors: vec![AgentDescriptor {
            name: server,
            tls_version: TLSVersion::V1_3,
            typ: AgentType::Server,
            try_reuse: false,
            client_authentication: false,
            server_authentication: false,
        }],
        steps: vec![InputAction::new_step(
            server,
            term! {
                fn_seq_0
            },
        )],
    }
}

#[cfg(test)]
mod tests {
    use puffin::agent::AgentName;

    use crate::{ssh::seeds::seed_successful, SSH_PUT_REGISTRY};

    #[test]
    fn test_seed_successful() {
        let trace = seed_successful(AgentName::first());
        trace.execute_default(&SSH_PUT_REGISTRY);
    }
}
