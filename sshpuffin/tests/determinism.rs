//! PUT determinism, the precondition of differential fuzzing (TLS: `tests/determinism.rs`).

#![cfg(any(has_put = "libssh0114", has_put = "wolfssh150"))]

use puffin::agent::AgentName;
use puffin::trace::Trace;
use sshpuffin::protocol::SshProtocolTypes;
use sshpuffin::put_registry::ssh_registry;
use sshpuffin::ssh::seeds::*;

/// Serialises the tests that EXECUTE PUTs. Each PUT's deterministic RNG is
/// process-global (libssh: OpenSSL RAND_METHOD + one static seed in
/// harness/libssh/src/rng.c; wolfSSH: one seed stream), and `cargo test` runs
/// tests on parallel threads: two PUT executions interleaving their draws make
/// each other nondeterministic. (This, not the PUT, is why libssh once looked
/// nondeterministic "by attempt 4".) Hold it for the whole execution.
static PUT_EXEC_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn put_exec_lock() -> std::sync::MutexGuard<'static, ()> {
    PUT_EXEC_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// PUT determinism (mirrors TLS `test_attacker_full_det_recreate`): the same
/// trace, replayed against the same PUT in the same process, must produce
/// byte-identical contexts across runs even with a wall-clock gap between them.
/// Determinism is the precondition the whole differential method rests on: a
/// nondeterministic PUT would manufacture spurious cross-stack "differences" run
/// to run.
///
/// Both PUTs and both roles are covered. wolfSSL draws from the harness's
/// CUSTOM_RAND_GENERATE_SEED stream, rewound at every agent create. libssh draws
/// from OpenSSL through the harness's custom RAND_METHOD (harness/libssh/src/rng.c),
/// reset to its default seed by `determinism_reseed_all_factories` before every
/// execution. (An earlier note here said libssh was nondeterministic in-process;
/// re-measured 2026-09-23 it is deterministic in both roles. The single-PUT vs
/// differential mismatch seen in triage was a CONFIG difference, the missing
/// uniformisation, not randomness; see `display-execute --uniformise`.)
#[cfg(any(has_put = "wolfssh150", has_put = "libssh0114"))]
fn assert_put_deterministic(put: &str, trace: Trace<SshProtocolTypes>) {
    use std::thread;
    use std::time::Duration;

    use puffin::execution::{Runner, TraceRunner};
    use puffin::trace::Spawner;

    let mut registry = ssh_registry();
    registry
        .set_default_factory(put)
        .unwrap_or_else(|e| panic!("PUT {put} not registered: {e}"));
    let spawner = Spawner::new(registry.clone());
    let runner = Runner::new(registry, spawner);

    let _exec = put_exec_lock();
    let ctx_1 = (&runner).execute(&trace, &mut 0);
    // A wall-clock gap between executions surfaces any hidden time dependence.
    thread::sleep(Duration::from_secs(1));
    for i in 0..20 {
        let ctx_2 = (&runner).execute(&trace, &mut 0);
        assert!(
            ctx_1 == ctx_2,
            "PUT {put} executed nondeterministically at attempt {i}"
        );
    }
}

#[cfg(has_put = "wolfssh150")]
#[test]
fn wolfssh_put_is_deterministic() {
    let a = AgentName::first();
    assert_put_deterministic("wolfssh150", seed_client_attacker_full_aesgcm(a)); // server role
    assert_put_deterministic("wolfssh150", seed_server_attacker_full_aesgcm(a)); // client role
}

#[cfg(has_put = "libssh0114")]
#[test]
fn libssh_put_is_deterministic() {
    let a = AgentName::first();
    assert_put_deterministic("libssh0114", seed_client_attacker_full_aesgcm(a)); // server role
    assert_put_deterministic("libssh0114", seed_server_attacker_full_aesgcm(a)); // client role
}
