use puffin::{
    agent::{AgentDescriptor, AgentName, AgentType, TLSVersion},
    algebra::AnyMatcher,
    term,
    trace::{InputAction, OutputAction, Trace},
};

use crate::ssh::fn_impl::*;

pub fn seed_successful(client: AgentName, server: AgentName) -> Trace<AnyMatcher> {
    Trace {
        prior_traces: vec![],
        descriptors: vec![
            AgentDescriptor {
                name: client,
                tls_version: TLSVersion::V1_3, // FIXME: Remove?
                typ: AgentType::Client,
                try_reuse: false,             // FIXME: Remove?
                client_authentication: false, // FIXME: Remove?
                server_authentication: false, // FIXME: Remove?
            },
            AgentDescriptor {
                name: server,
                tls_version: TLSVersion::V1_3, // FIXME: Remove?
                typ: AgentType::Server,
                try_reuse: false,             // FIXME: Remove?
                client_authentication: false, // FIXME: Remove?
                server_authentication: false, // FIXME: Remove?
            },
        ],
        steps: vec![
            OutputAction::new_step(client),
            InputAction::new_step(
                server,
                term! {
                    fn_banner(
                        ((client, 0))
                    )
                },
            ),
            InputAction::new_step(
                client,
                term! {
                    fn_banner(
                        ((server, 0))
                    )
                },
            ),
        ],
    }
}

#[cfg(test)]
mod tests {
    use puffin::agent::AgentName;
    use test_log::test;

    use crate::{libssh::ssh::set_log_level, ssh, ssh::seeds::seed_successful, SSH_PUT_REGISTRY};

    #[test]
    fn test_seed_successful() {
        set_log_level(100);
        let client = AgentName::first();
        let trace = seed_successful(client, client.next());
        trace.execute_default(&SSH_PUT_REGISTRY);
    }
}
