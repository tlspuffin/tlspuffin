//! Seeds executed on the SSH PUTs: each must reach its verdict.

#![cfg(all(has_put = "libssh0114", has_put = "wolfssh150"))]

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

/// Every two-party / Terrapin relay seed must reach ITS verdict on each built
/// PUT — not die on an unresolvable relay query first (they all used to):
///   * the honest relays (flight and packet granularity) complete, both agents DONE;
///   * on libssh, every Terrapin variant is stopped by strict-kex (the injected IGNORE during KEX
///     is rejected);
///   * on wolfSSH (no strict-kex), the c2s variants run to the end but stall (no later c2s packet
///     to realign on), and the s2c variant fails the client's AES-GCM tag check (`AES_GCM_AUTH_E` =
///     -180: GCM nonces do not follow the sequence number, so the truncation cannot be hidden).
#[cfg(all(has_put = "libssh0114", has_put = "wolfssh150"))]
#[test]
fn two_party_seeds_reach_their_verdict() {
    use puffin::put::{PutDescriptor, PutOptions};
    use puffin::trace::{Spawner, TraceContext};

    #[derive(Debug)]
    enum Verdict {
        BothDone,
        StrictKexReject,
        Stall,
        GcmTagFailure,
    }
    use Verdict::*;

    let client = AgentName::first();
    let server = client.next();
    type Seed = fn(AgentName, AgentName) -> Trace<SshProtocolTypes>;
    let cases: [(&str, Seed, Verdict, Verdict); 5] = [
        ("two_party", seed_handshake_two_party, BothDone, BothDone),
        (
            "two_party_packet_complete",
            seed_handshake_two_party_packet_complete,
            BothDone,
            BothDone,
        ),
        (
            "terrapin_attempt",
            seed_terrapin_attempt,
            StrictKexReject,
            Stall,
        ),
        (
            "terrapin_packet",
            seed_terrapin_packet,
            StrictKexReject,
            Stall,
        ),
        (
            "terrapin_s2c",
            seed_terrapin_s2c,
            StrictKexReject,
            GcmTagFailure,
        ),
    ];
    let _exec = put_exec_lock();
    let mut failures = Vec::new();
    for (name, seed, on_libssh, on_wolfssh) in &cases {
        for (put, want) in [("libssh0114", on_libssh), ("wolfssh150", on_wolfssh)] {
            let desc = PutDescriptor::new(put, PutOptions::default());
            let spawner = Spawner::new(ssh_registry())
                .with_mapping(&[(client, desc.clone()), (server, desc)]);
            let mut ctx = TraceContext::new(spawner);
            let res = seed(client, server).execute(&mut ctx, &mut 0, false);
            let states = format!(
                "{:?} / {:?}",
                ctx.find_agent(client),
                ctx.find_agent(server)
            );
            let ok = match (want, &res) {
                (BothDone, Ok(())) => ctx.agents_successful(),
                (Stall, Ok(())) => !ctx.agents_successful(),
                (StrictKexReject, Err(e)) => e.to_string().contains("strict KEX"),
                (GcmTagFailure, Err(_)) => states.contains("gerr=-180"),
                _ => false,
            };
            if !ok {
                failures.push(format!(
                    "{name} on {put}: want {want:?}, got {res:?}; {states}"
                ));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "two-party verdicts:\n{}",
        failures.join("\n")
    );
}

/// The data-dependent server-attacker session must take BOTH client PUTs all the
/// way to DONE (channel confirmed on the channel number each client chose, shell
/// request answered) — i.e. the attacker really read the client's CHANNEL_OPEN
/// from its encrypted stream and replied on the right channel.
#[cfg(all(has_put = "libssh0114", has_put = "wolfssh150"))]
#[test]
fn server_session_clients_reach_done() {
    use puffin::put::{PutDescriptor, PutOptions};
    use puffin::trace::{Spawner, TraceContext};

    let client = AgentName::first();
    let _exec = put_exec_lock();
    for put in ["libssh0114", "wolfssh150"] {
        let desc = PutDescriptor::new(put, PutOptions::default());
        let spawner = Spawner::new(ssh_registry()).with_mapping(&[(client, desc)]);
        let mut ctx = TraceContext::new(spawner);
        seed_server_attacker_session_aesgcm(client)
            .execute(&mut ctx, &mut 0, false)
            .unwrap_or_else(|e| panic!("{put}: server-attacker session failed: {e}"));
        assert!(
            ctx.agents_successful(),
            "{put}: client did not reach DONE: {:?}",
            ctx.find_agent(client)
        );
    }
}
