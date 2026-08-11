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
            OutputAction::new_step(client),
            // Client -> Server: Banner
            InputAction::new_step(
                server,
                term! {
                    fn_banner(
                        K((client, 0))
                    )
                },
            ),
            // Server -> Client: Banner
            InputAction::new_step(
                client,
                term! {
                    fn_banner(
                        K((server, 0))
                    )
                },
            ),
            // Client -> Server: KexInit
            InputAction::new_step(
                server,
                term! {
                    fn_kex_init(
                        K((client, 0)[None]/[u8; 16]),
                        K((client, 0)[None]/KexAlgorithms),
                        K((client, 0)[None]/SignatureSchemes),
                        K((client, 0)[None]/EncryptionAlgorithms),
                        K((client, 1)[None]/EncryptionAlgorithms),
                        K((client, 0)[None]/MacAlgorithms),
                        K((client, 1)[None]/MacAlgorithms),
                        K((client, 0)[None]/CompressionAlgorithms),
                        K((client, 1)[None]/CompressionAlgorithms)
                    )
                },
            ),
            // Server -> Client: KexInit
            InputAction::new_step(
                client,
                term! {
                    fn_kex_init(
                        K((server, 0)[None]/[u8; 16]),
                        K((server, 0)[None]/KexAlgorithms),
                        K((server, 0)[None]/SignatureSchemes),
                        K((server, 0)[None]/EncryptionAlgorithms),
                        K((server, 1)[None]/EncryptionAlgorithms),
                        K((server, 0)[None]/MacAlgorithms),
                        K((server, 1)[None]/MacAlgorithms),
                        K((server, 0)[None]/CompressionAlgorithms),
                        K((server, 1)[None]/CompressionAlgorithms)
                    )
                },
            ),
            // Client -> Server: ECDH Init
            InputAction::new_step(
                server,
                term! {
                    fn_raw_message(
                        K((client, 2)[None]/RawSshMessage)  // ECDH Init
                    )
                },
            ),
            // Server -> Client: ECDH Reply
            InputAction::new_step(
                client,
                term! {
                    fn_kex_ecdh_reply(
                        K((server, 0)[None]/Vec<u8>),
                        K((server, 1)[None]/Vec<u8>),
                        K((server, 2)[None]/Vec<u8>)
                    )
                },
            ),
            InputAction::new_step(
                server,
                term! {
                    fn_raw_message(
                        K((client, 3)[None]/RawSshMessage)  // SSH_MSG_NEWKEYS??
                    )
                },
            ),
            // auth finished in this input step
            // in auto-output step the client auth is called
            InputAction::new_step(
                client,
                term! {
                    fn_raw_message(
                        K((server, 3)[None]/RawSshMessage)  // SSH_MSG_NEWKEYS??
                    )
                },
            ),
            InputAction::new_step(
                client,
                term! {
                    fn_onwire_message(
                        K((server, 0)[None]/OnWireData)  // option data??
                    )
                },
            ),
            InputAction::new_step(
                server,
                term! {
                    fn_onwire_message(
                        K((client, 0)[None]/OnWireData)  // Auth request??
                    )
                },
            ),
            InputAction::new_step(
                client,
                term! {
                    fn_onwire_message(
                        K((server, 1)[None]/OnWireData)  // Auth response??
                    )
                },
            ),
            InputAction::new_step(
                server,
                term! {
                    fn_onwire_message(
                        K((client, 1)[None]/OnWireData)  // ?
                    )
                },
            ),
            InputAction::new_step(
                client,
                term! {
                    fn_onwire_message(
                        K((server, 2)[None]/OnWireData)  // ??
                    )
                },
            ),
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
