//! Seeds executed on the SSH PUTs: each must reach its verdict, on every PUT of the binary.

#![cfg(any(has_libssh, has_wolfssh))]

use puffin::agent::AgentName;
use puffin::algebra::dynamic_function::TypeShape;
use puffin::put::{PutDescriptor, PutOptions};
use puffin::trace::{Spawner, Trace, TraceContext};
use sshpuffin::claim::SshClaimInner;
use sshpuffin::protocol::{SshProtocolBehavior, SshProtocolTypes};
use sshpuffin::put_registry::{put_names, ssh_registry};
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

/// Every PUT of the binary, libssh then wolfSSH: those of each vendor the build found
/// (`has_libssh`, `has_wolfssh`), so that a test cannot pass on no PUT.
fn all_puts() -> Vec<String> {
    let libssh = put_names("libssh");
    let wolfssh = put_names("wolfssh");
    assert_eq!(
        !libssh.is_empty(),
        cfg!(has_libssh),
        "libssh PUTs: {libssh:?}"
    );
    assert_eq!(
        !wolfssh.is_empty(),
        cfg!(has_wolfssh),
        "wolfSSH PUTs: {wolfssh:?}"
    );
    [libssh, wolfssh].concat()
}

/// Executes `trace` with every agent on `put`.
fn execute_on(
    put: &str,
    agents: &[AgentName],
    trace: &Trace<SshProtocolTypes>,
) -> (
    Result<(), puffin::error::Error>,
    TraceContext<SshProtocolBehavior>,
) {
    let desc = PutDescriptor::new(put, PutOptions::default());
    let mapping: Vec<_> = agents.iter().map(|a| (*a, desc.clone())).collect();
    let mut ctx = TraceContext::new(Spawner::new(ssh_registry()).with_mapping(&mapping));
    let res = trace.execute(&mut ctx, &mut 0, false);
    (res, ctx)
}

/// Whether `put` runs strict KEX (the Terrapin countermeasure, `kex-strict-*-v00@openssh.com`):
/// every libssh, and wolfSSH from 1.6.0 on, where it is on by default (wolfSSH PR 1271).
fn has_strict_kex(put: &str) -> bool {
    if put_names("libssh").iter().any(|p| p == put) {
        return true;
    }
    let version = ssh_registry()
        .puts()
        .find(|(name, _)| *name == put)
        .and_then(|(_, factory)| {
            factory
                .versions()
                .into_iter()
                .find(|(component, _)| component == "library")
        })
        .map(|(_, version)| version)
        .unwrap_or_else(|| panic!("PUT {put} has no library version"));
    // "wolfssh 1.6.0"
    let numbers: Vec<u32> = version
        .split(' ')
        .nth(1)
        .unwrap_or_default()
        .split('.')
        .map(|n| n.parse().unwrap_or(0))
        .collect();
    numbers >= vec![1, 6]
}

/// Every two-party / Terrapin relay seed must reach ITS verdict on each built
/// PUT — not die on an unresolvable relay query first (they all used to):
///   * the honest relays (flight and packet granularity) complete, both agents DONE;
///   * on a PUT with strict KEX (every libssh, wolfSSH from 1.6.0), every Terrapin variant is
///     stopped by it: the IGNORE injected during the initial KEX is rejected (libssh: "strict KEX";
///     wolfSSH: `WS_MSGID_NOT_ALLOWED_E` = -1094);
///   * on wolfSSH 1.5.0 (no strict KEX), the c2s variants run to the end but stall (no later c2s
///     packet to realign on), and the s2c variant fails the client's AES-GCM tag check
///     (`AES_GCM_AUTH_E` = -180: GCM nonces do not follow the sequence number, so the truncation
///     cannot be hidden).
#[test]
fn two_party_seeds_reach_their_verdict() {
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
    // (seed, verdict with strict KEX, verdict without)
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
    for put in all_puts() {
        let strict = has_strict_kex(&put);
        for (name, seed, with_strict, without_strict) in &cases {
            let want = if strict { with_strict } else { without_strict };
            let (res, ctx) = execute_on(&put, &[client, server], &seed(client, server));
            let states = format!(
                "{:?} / {:?}",
                ctx.find_agent(client),
                ctx.find_agent(server)
            );
            let ok = match (want, &res) {
                (BothDone, Ok(())) => ctx.agents_successful(),
                (Stall, Ok(())) => !ctx.agents_successful(),
                (StrictKexReject, Err(e)) => {
                    e.to_string().contains("strict KEX") || states.contains("gerr=-1094")
                }
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

/// The data-dependent server-attacker session must take every client PUT all the
/// way to DONE (channel confirmed on the channel number each client chose, shell
/// request answered) — i.e. the attacker really read the client's CHANNEL_OPEN
/// from its encrypted stream and replied on the right channel.
#[test]
fn server_session_clients_reach_done() {
    let client = AgentName::first();
    let _exec = put_exec_lock();
    for put in all_puts() {
        let (res, ctx) = execute_on(
            &put,
            &[client],
            &seed_server_attacker_session_aesgcm(client),
        );
        res.unwrap_or_else(|e| panic!("{put}: server-attacker session failed: {e}"));
        assert!(
            ctx.agents_successful(),
            "{put}: client did not reach DONE: {:?}",
            ctx.find_agent(client)
        );
    }
}

/// The seeds of the `default` and `with-divergent` corpora are valid starting points on every PUT:
///   * each `default` seed runs to its last step;
///   * each `with-divergent` seed runs to its last step or stops at an error of the PUT, never at
///     one of the trace itself (an unresolvable query, a term that does not evaluate): the PUT may
///     reject what diverges (wolfSSH 1.6.0 rejects the KEXINIT of `kexinit_injection`);
///   * every agent completed the first key exchange: it emitted its claim with the session id (the
///     exchange hash H, 32 bytes), which the s2c decryption recipe reads.
#[test]
fn corpus_seeds_run_on_every_put() {
    let client = AgentName::first();
    let server = client.next();
    let default = build_corpus();
    let n_default = default.len();
    let registry = ssh_registry();
    let (_, factory) = registry.puts().next().expect("no PUT");
    let seeds = create_with_divergent_corpus(factory);
    assert!(seeds.len() > n_default, "with-divergent adds no seed");
    let _exec = put_exec_lock();
    let mut failures = Vec::new();
    for put in all_puts() {
        for (i, (trace, name)) in seeds.iter().enumerate() {
            let (res, ctx) = execute_on(&put, &[client, server], trace);
            match &res {
                Ok(()) => {}
                Err(puffin::error::Error::Put(_)) if i >= n_default => {}
                Err(e) => failures.push(format!("{name} on {put}: {e}")),
            }
            for agent in [client, server] {
                if ctx.find_agent(agent).is_err() {
                    continue; // a single-agent seed
                }
                let session_id = ctx
                    .find_claim(agent, TypeShape::of::<Box<SshClaimInner>>())
                    .and_then(|claim| {
                        claim
                            .as_any()
                            .downcast_ref::<Box<SshClaimInner>>()
                            .map(|inner| inner.session_id.len())
                    });
                if session_id != Some(32) {
                    failures.push(format!(
                        "{name} on {put}: {agent} has no session-id claim ({session_id:?})"
                    ));
                }
            }
        }
    }
    assert!(
        failures.is_empty(),
        "corpus seeds:\n{}",
        failures.join("\n")
    );
}
