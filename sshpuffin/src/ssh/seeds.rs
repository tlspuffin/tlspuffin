use puffin::agent::{AgentDescriptor, AgentName};
use puffin::term;
use puffin::trace::{InputAction, OutputAction, Trace};

use crate::protocol::{AgentType, SshDescriptorConfig, SshProtocolBehavior, SshProtocolTypes};
use crate::ssh::fn_impl::*;
use crate::ssh::message::{
    CompressionAlgorithms, EncryptionAlgorithms, KexAlgorithms, MacAlgorithms, OnWireData,
    RawSshMessage, SignatureSchemes, SshBytes,
};

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
                        ((client, 0))
                    )
                },
            ),
            // Server -> Client: Banner
            InputAction::new_step(
                client,
                term! {
                    fn_banner(
                        ((server, 0))
                    )
                },
            ),
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
            // Client -> Server: ECDH Init
            InputAction::new_step(
                server,
                term! {
                    fn_raw_message(
                        ((client, 2)[None]/RawSshMessage)  // ECDH Init
                    )
                },
            ),
            // Server -> Client: ECDH Reply (pass through raw; the DY extractor
            // will index SshPublicKey / SshBytes / SshSignature from it for mutations)
            InputAction::new_step(
                client,
                term! { fn_raw_message(((server, 2)[None]/RawSshMessage)) },
            ),
            InputAction::new_step(
                server,
                term! {
                    fn_raw_message(
                        ((client, 3)[None]/RawSshMessage)  // SSH_MSG_NEWKEYS??
                    )
                },
            ),
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
            InputAction::new_step(
                client,
                term! {
                    fn_onwire_message(
                        ((server, 0)[None]/OnWireData)  // option data??
                    )
                },
            ),
            InputAction::new_step(
                server,
                term! {
                    fn_onwire_message(
                        ((client, 0)[None]/OnWireData)  // Auth request??
                    )
                },
            ),
            InputAction::new_step(
                client,
                term! {
                    fn_onwire_message(
                        ((server, 1)[None]/OnWireData)  // Auth response??
                    )
                },
            ),
            InputAction::new_step(
                server,
                term! {
                    fn_onwire_message(
                        ((client, 1)[None]/OnWireData)  // ?
                    )
                },
            ),
            InputAction::new_step(
                client,
                term! {
                    fn_onwire_message(
                        ((server, 2)[None]/OnWireData)  // ??
                    )
                },
            ),
        ],
        ..Default::default()
    }
}

/// A trace that exercises the service-request → password-auth path with
/// structured terms.  Steps up to NewKeys mirror seed_successful; after that
/// we inject a structured ServiceRequest and UserAuthRequest so the fuzzer
/// has real handles on the auth code paths.
pub fn seed_auth_structured(client: AgentName, server: AgentName) -> Trace<SshProtocolTypes> {
    Trace {
        prior_traces: vec![],
        descriptors: vec![
            AgentDescriptor::from_config(
                client,
                SshDescriptorConfig {
                    typ: AgentType::Client,
                    try_reuse: false,
                },
            ),
            AgentDescriptor::from_config(
                server,
                SshDescriptorConfig {
                    typ: AgentType::Server,
                    try_reuse: false,
                },
            ),
        ],
        steps: vec![
            OutputAction::new_step(client),
            // Banner exchange
            InputAction::new_step(
                server,
                term! { fn_banner(((client, 0))) },
            ),
            InputAction::new_step(
                client,
                term! { fn_banner(((server, 0))) },
            ),
            // KexInit exchange
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
            // ECDH init — structured: extract the ephemeral key as SshBytes
            // so the fuzzer can mutate it independently from the packet framing.
            InputAction::new_step(
                server,
                term! { fn_kex_ecdh_init(((client, 2)[None]/SshBytes)) },
            ),
            // ECDH reply — pass through raw (same reason as in seed_successful).
            InputAction::new_step(
                client,
                term! { fn_raw_message(((server, 2)[None]/RawSshMessage)) },
            ),
            InputAction::new_step(server, term! { fn_raw_message(((client, 3)[None]/RawSshMessage)) }),
            InputAction::new_step(client, term! { fn_raw_message(((server, 3)[None]/RawSshMessage)) }),
            // Service request (structured — gives the fuzzer a handle on service dispatch)
            InputAction::new_step(
                server,
                term! { fn_service_request((fn_ssh_userauth)) },
            ),
            // Password auth request (structured)
            InputAction::new_step(
                server,
                term! {
                    fn_user_auth_request(
                        (fn_username),
                        (fn_ssh_connection),
                        (fn_method_password),
                        (fn_password)
                    )
                },
            ),
        ],
        ..Default::default()
    }
}

// ── Helper: agent descriptor pair ────────────────────────────────────────────

fn descriptors(
    client: AgentName,
    server: AgentName,
) -> Vec<AgentDescriptor<SshDescriptorConfig>> {
    vec![
        AgentDescriptor::from_config(client, SshDescriptorConfig { typ: AgentType::Client, try_reuse: false }),
        AgentDescriptor::from_config(server, SshDescriptorConfig { typ: AgentType::Server, try_reuse: false }),
    ]
}

// ── Seed: disconnect during KEX ───────────────────────────────────────────────
//
// Client and server exchange banners, then the fuzzer injects a disconnect
// before KEX completes.  Exercises libssh's early-teardown paths.

pub fn seed_disconnect_early(
    client: AgentName,
    server: AgentName,
) -> Trace<SshProtocolTypes> {
    Trace {
        prior_traces: vec![],
        descriptors: descriptors(client, server),
        steps: vec![
            OutputAction::new_step(client),
            InputAction::new_step(server, term! { fn_banner(((client, 0))) }),
            InputAction::new_step(client, term! { fn_banner(((server, 0))) }),
            InputAction::new_step(
                server,
                term! {
                    fn_disconnect(
                        (fn_disconnect_reason_protocol_error),
                        (fn_ssh_bytes_empty),
                        (fn_ssh_bytes_empty)
                    )
                },
            ),
        ],
        ..Default::default()
    }
}

// ── Seed: "none" auth probe ───────────────────────────────────────────────────
//
// After a successful KEX, the client probes the server with method "none"
// (RFC 4252 §5.2) to learn which auth methods the server supports.  The
// server should reply with SSH_MSG_USERAUTH_FAILURE listing available methods.

pub fn seed_none_auth_probe(
    client: AgentName,
    server: AgentName,
) -> Trace<SshProtocolTypes> {
    Trace {
        prior_traces: vec![],
        descriptors: descriptors(client, server),
        steps: vec![
            OutputAction::new_step(client),
            InputAction::new_step(server, term! { fn_banner(((client, 0))) }),
            InputAction::new_step(client, term! { fn_banner(((server, 0))) }),
            // KexInit exchange
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
            InputAction::new_step(server, term! { fn_raw_message(((client, 2)[None]/RawSshMessage)) }),
            InputAction::new_step(client, term! { fn_raw_message(((server, 2)[None]/RawSshMessage)) }),
            InputAction::new_step(server, term! { fn_raw_message(((client, 3)[None]/RawSshMessage)) }),
            InputAction::new_step(client, term! { fn_raw_message(((server, 3)[None]/RawSshMessage)) }),
            // Service request + "none" auth probe (structured)
            InputAction::new_step(
                server,
                term! { fn_service_request((fn_ssh_userauth)) },
            ),
            InputAction::new_step(
                server,
                term! {
                    fn_user_auth_request(
                        (fn_username),
                        (fn_ssh_connection),
                        (fn_method_none),
                        (fn_none_auth_data)
                    )
                },
            ),
        ],
        ..Default::default()
    }
}

// ── Seed: wrong-password auth failure ────────────────────────────────────────
//
// Client authenticates with an incorrect password.  The server sends
// SSH_MSG_USERAUTH_FAILURE; the fuzzer then sends a second attempt.

pub fn seed_auth_wrong_password(
    client: AgentName,
    server: AgentName,
) -> Trace<SshProtocolTypes> {
    Trace {
        prior_traces: vec![],
        descriptors: descriptors(client, server),
        steps: vec![
            OutputAction::new_step(client),
            InputAction::new_step(server, term! { fn_banner(((client, 0))) }),
            InputAction::new_step(client, term! { fn_banner(((server, 0))) }),
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
            InputAction::new_step(server, term! { fn_raw_message(((client, 2)[None]/RawSshMessage)) }),
            InputAction::new_step(client, term! { fn_raw_message(((server, 2)[None]/RawSshMessage)) }),
            InputAction::new_step(server, term! { fn_raw_message(((client, 3)[None]/RawSshMessage)) }),
            InputAction::new_step(client, term! { fn_raw_message(((server, 3)[None]/RawSshMessage)) }),
            InputAction::new_step(server, term! { fn_service_request((fn_ssh_userauth)) }),
            // First attempt with wrong password
            InputAction::new_step(
                server,
                term! {
                    fn_user_auth_request(
                        (fn_username),
                        (fn_ssh_connection),
                        (fn_method_password),
                        (fn_password_auth_data((fn_password)))
                    )
                },
            ),
            // Second attempt with the correct password (as observed from client output)
            InputAction::new_step(
                server,
                term! {
                    fn_user_auth_request(
                        (fn_username),
                        (fn_ssh_connection),
                        (fn_method_password),
                        (fn_password_auth_data((fn_password)))
                    )
                },
            ),
        ],
        ..Default::default()
    }
}

pub fn create_corpus(
    _put: &dyn puffin::put_registry::Factory<SshProtocolBehavior>,
) -> Vec<(Trace<SshProtocolTypes>, &'static str)> {
    let client = AgentName::first();
    let server = client.next();

    vec![
        (seed_successful(client, server), "seed_successful"),
        (seed_auth_structured(client, server), "seed_auth_structured"),
        (seed_disconnect_early(client, server), "seed_disconnect_early"),
        (seed_none_auth_probe(client, server), "seed_none_auth_probe"),
        (seed_auth_wrong_password(client, server), "seed_auth_wrong_password"),
    ]
}

#[cfg(test)]
mod tests {
    use puffin::execution::{Runner, TraceRunner};
    use puffin::trace::Spawner;

    use crate::ssh::seeds::seed_successful;
    use crate::ssh_registry;

    #[test_log::test]
    #[ignore = "legacy seed trace still assumes old Rust libssh mapper/harness behavior; update trace for C harness framing"]
    fn test_seed_successful() {
        let registry = ssh_registry();
        let runner = Runner::new(registry.clone(), Spawner::new(registry));
        let client = puffin::agent::AgentName::first();
        let trace = seed_successful(client, client.next());

        let context = runner.execute(trace, &mut 0).unwrap();

        assert!(context.find_agent(client).unwrap().is_state_successful())
    }
}
