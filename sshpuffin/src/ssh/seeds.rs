use puffin::agent::{AgentDescriptor, AgentName};
use puffin::term;
use puffin::trace::{InputAction, OutputAction, Trace};

use crate::protocol::{AgentType, SshDescriptorConfig, SshProtocolTypes};
use crate::ssh::fn_impl::*;
use crate::ssh::message::*;

pub fn seed_successful(client: AgentName, server: AgentName) -> Trace<SshProtocolTypes> {
    Trace {
        prior_traces: vec![],
        descriptors: vec![
            AgentDescriptor::from_config(
                client,
                SshDescriptorConfig {
                    typ: AgentType::Client,
                    try_reuse: false, // FIXME: Remove?
                },
            ),
            AgentDescriptor::from_config(
                server,
                SshDescriptorConfig {
                    typ: AgentType::Server,
                    try_reuse: false, // FIXME: Remove?
                },
            ),
        ],
        steps: vec![
            // after each input, the receiving agent's output (progress, then read): libssh writes
            // what it sends on its next progress, and the output puffin reads after an
            // input does not progress the agent (since dff9692b4): without it, the
            // server's banner was never read
            OutputAction::new_step(client),
            // Client -> Server: Banner
            InputAction::new_step(
                server,
                term! {
                    fn_banner(
                        ((client, 0))
                    )
                },
            ),
            OutputAction::new_step(server),
            // Server -> Client: Banner
            InputAction::new_step(
                client,
                term! {
                    fn_banner(
                        ((server, 0))
                    )
                },
            ),
            OutputAction::new_step(client),
            // Client -> Server: KexInit
            InputAction::new_step(
                server,
                term! {
                    fn_kex_init(
                        ((client, 0)[None]/[u8; 16]),
                        ((client, 0)[None]/KexAlgorithms),
                        ((client, 0)[None]/SignatureSchemes),
                        ((client, 0)[None]/EncryptionAlgorithms),
                        ((client, 1)[None]/EncryptionAlgorithms),
                        ((client, 0)[None]/MacAlgorithms),
                        ((client, 1)[None]/MacAlgorithms),
                        ((client, 0)[None]/CompressionAlgorithms),
                        ((client, 1)[None]/CompressionAlgorithms)
                    )
                },
            ),
            OutputAction::new_step(server),
            // Server -> Client: KexInit
            InputAction::new_step(
                client,
                term! {
                    fn_kex_init(
                        ((server, 0)[None]/[u8; 16]),
                        ((server, 0)[None]/KexAlgorithms),
                        ((server, 0)[None]/SignatureSchemes),
                        ((server, 0)[None]/EncryptionAlgorithms),
                        ((server, 1)[None]/EncryptionAlgorithms),
                        ((server, 0)[None]/MacAlgorithms),
                        ((server, 1)[None]/MacAlgorithms),
                        ((server, 0)[None]/CompressionAlgorithms),
                        ((server, 1)[None]/CompressionAlgorithms)
                    )
                },
            ),
            OutputAction::new_step(client),
            // Client -> Server: ECDH Init
            InputAction::new_step(
                server,
                term! {
                    fn_raw_message(
                        ((client, 2)[None]/RawSshMessage)  // ECDH Init
                    )
                },
            ),
            OutputAction::new_step(server),
            // Server -> Client: ECDH Reply
            InputAction::new_step(
                client,
                term! {
                    fn_kex_ecdh_reply(
                        ((server, 0)[None]/Vec<u8>),
                        ((server, 1)[None]/Vec<u8>),
                        ((server, 2)[None]/Vec<u8>)
                    )
                },
            ),
            OutputAction::new_step(client),
            InputAction::new_step(
                server,
                term! {
                    fn_raw_message(
                        ((client, 3)[None]/RawSshMessage)  // SSH_MSG_NEWKEYS??
                    )
                },
            ),
            OutputAction::new_step(server),
            // auth finished in this input step
            // in auto-output step the client auth is called
            InputAction::new_step(
                client,
                term! {
                    fn_raw_message(
                        ((server, 3)[None]/RawSshMessage)  // SSH_MSG_NEWKEYS??
                    )
                },
            ),
            OutputAction::new_step(client),
            InputAction::new_step(
                client,
                term! {
                    fn_onwire_message(
                        ((server, 0)[None]/OnWireData)  // option data??
                    )
                },
            ),
            OutputAction::new_step(client),
            InputAction::new_step(
                server,
                term! {
                    fn_onwire_message(
                        ((client, 0)[None]/OnWireData)  // Auth request??
                    )
                },
            ),
            OutputAction::new_step(server),
            InputAction::new_step(
                client,
                term! {
                    fn_onwire_message(
                        ((server, 1)[None]/OnWireData)  // Auth response??
                    )
                },
            ),
            OutputAction::new_step(client),
            InputAction::new_step(
                server,
                term! {
                    fn_onwire_message(
                        ((client, 1)[None]/OnWireData)  // ?
                    )
                },
            ),
            OutputAction::new_step(server),
            InputAction::new_step(
                client,
                term! {
                    fn_onwire_message(
                        ((server, 2)[None]/OnWireData)  // ??
                    )
                },
            ),
            OutputAction::new_step(client),
        ],
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use puffin::execution::{Runner, TraceRunner};
    use puffin::trace::Spawner;

    use crate::libssh::ssh::set_log_level;
    use crate::ssh::seeds::seed_successful;
    use crate::ssh_registry;

    #[test_log::test]
    fn test_seed_successful() {
        set_log_level(100);

        let registry = ssh_registry();
        let runner = Runner::new(registry.clone(), Spawner::new(registry));
        let client = puffin::agent::AgentName::first();
        let trace = seed_successful(client, client.next());

        let context = runner.execute(trace, &mut 0).unwrap();

        assert!(context.find_agent(client).unwrap().is_state_successful())
    }
}
