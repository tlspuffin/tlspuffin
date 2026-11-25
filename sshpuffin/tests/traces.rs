//! Seeds executed on the SSH PUTs: each must reach its verdict, on every PUT of the binary.

#![cfg(any(has_libssh, has_wolfssh))]

use puffin::agent::AgentName;
use puffin::algebra::dynamic_function::TypeShape;
use puffin::algebra::error::FnError;
use puffin::algebra::{DYTerm, Term, TermType};
use puffin::codec::Codec;
use puffin::execution::{DifferentialRunner, TraceRunner};
use puffin::fuzzer::bit_mutations::make_message_term;
use puffin::protocol::ProtocolTypes;
use puffin::put::{PutDescriptor, PutOptions};
use puffin::term;
use puffin::trace::{
    Action, ExecutionResult, InputAction, OutputAction, Source, Spawner, Trace, TraceContext,
};
use sshpuffin::claim::SshClaimInner;
use sshpuffin::protocol::{RawSshMessageFlight, SshProtocolBehavior, SshProtocolTypes};
use sshpuffin::put_registry::{put_names, ssh_registry};
use sshpuffin::ssh::fn_impl::*;
use sshpuffin::ssh::message::{OnWireData, RawSshMessage, SshBytes, SshMessage, Username};
use sshpuffin::ssh::seeds::*;
use sshpuffin::ssh::transcript::AlignedTranscript;

/// Serialises the tests that EXECUTE PUTs, which `cargo test` runs on parallel threads. The
/// harnesses keep their RNG state per thread, but the libraries share process-wide state
/// (libssh draws through OpenSSL's global RAND method). Hold it for the whole execution.
static PUT_EXEC_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn put_exec_lock() -> std::sync::MutexGuard<'static, ()> {
    PUT_EXEC_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// Every PUT of the binary that can run the seeds, libssh then wolfSSH: those of each vendor the
/// build found (`has_libssh`, `has_wolfssh`), so that a test cannot pass on no PUT. The attacker
/// seeds encrypt with AES-GCM, which libssh only has from 0.9.0 on: an older libssh (`libssh083`)
/// stops at their key exchange and is skipped, and a binary whose only libssh is one fails here.
fn all_puts() -> Vec<String> {
    let (libssh, without_aes_gcm): (Vec<_>, Vec<_>) = put_names("libssh")
        .into_iter()
        .partition(|put| library_version(put) >= vec![0, 9]);
    if !without_aes_gcm.is_empty() {
        eprintln!("skipped, no AES-GCM before libssh 0.9.0: {without_aes_gcm:?}");
    }
    let wolfssh = put_names("wolfssh");
    assert_eq!(
        !libssh.is_empty(),
        cfg!(has_libssh),
        "libssh PUTs with AES-GCM: {libssh:?}"
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
/// libssh from 0.10.6 on (0.9.8 in the 0.9 series, CVE-2023-48795), and wolfSSH from 1.6.0 on,
/// where it is on by default (wolfSSH PR 1271).
fn has_strict_kex(put: &str) -> bool {
    let version = library_version(put);
    if put_names("libssh").iter().any(|p| p == put) {
        return version >= vec![0, 10, 6] || (vec![0, 9, 8]..vec![0, 10]).contains(&version);
    }
    version >= vec![1, 6]
}

/// The version of the library of `put`, e.g. `[1, 6, 0]` for wolfSSH 1.6.0.
fn library_version(put: &str) -> Vec<u32> {
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
    version
        .split(' ')
        .nth(1)
        .unwrap_or_default()
        .split('.')
        .map(|n| n.parse().unwrap_or(0))
        .collect()
}

/// Every two-party / Terrapin relay seed must reach ITS verdict on each built
/// PUT — not die on an unresolvable relay query first (they all used to):
///   * the honest relays (flight and packet granularity) complete, both agents DONE;
///   * on a PUT with strict KEX (libssh from 0.10.6, wolfSSH from 1.6.0), every Terrapin variant is
///     stopped by it: the IGNORE injected during the initial KEX is rejected (libssh: "strict KEX";
///     wolfSSH: `WS_MSGID_NOT_ALLOWED_E` = -1094);
///   * on wolfSSH 1.5.0 (no strict KEX), the c2s variants run to the end but stall (no later c2s
///     packet to realign on), and the s2c variant fails the client's AES-GCM tag check
///     (`AES_GCM_AUTH_E` = -180: GCM nonces do not follow the sequence number, so the truncation
///     cannot be hidden);
///   * on libssh without strict KEX (0.10.4), the c2s variants stall too, but the s2c variant
///     SUCCEEDS, which is Terrapin (CVE-2023-48795): the two libssh peers negotiate
///     chacha20-poly1305, keyed by the sequence number, so the injected IGNORE and the dropped
///     EXT_INFO cancel out and the client completes without having seen EXT_INFO.
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
    // (seed, verdict with strict KEX, without it on wolfSSH, without it on libssh)
    let cases: [(&str, Seed, Verdict, Verdict, Verdict); 5] = [
        (
            "two_party",
            seed_handshake_two_party,
            BothDone,
            BothDone,
            BothDone,
        ),
        (
            "two_party_packet_complete",
            seed_handshake_two_party_packet_complete,
            BothDone,
            BothDone,
            BothDone,
        ),
        (
            "terrapin_attempt",
            seed_terrapin_attempt,
            StrictKexReject,
            Stall,
            Stall,
        ),
        (
            "terrapin_packet",
            seed_terrapin_packet,
            StrictKexReject,
            Stall,
            Stall,
        ),
        (
            "terrapin_s2c",
            seed_terrapin_s2c,
            StrictKexReject,
            GcmTagFailure,
            BothDone,
        ),
    ];
    let _exec = put_exec_lock();
    let mut failures = Vec::new();
    for put in all_puts() {
        let strict = has_strict_kex(&put);
        let libssh = put_names("libssh").contains(&put);
        for (name, seed, with_strict, wolfssh_without, libssh_without) in &cases {
            let want = match (strict, libssh) {
                (true, _) => with_strict,
                (false, true) => libssh_without,
                (false, false) => wolfssh_without,
            };
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

/// Whether `agent` answered the input step `step`: an input step's reply is the flight read right
/// after it.
fn answered(ctx: &TraceContext<SshProtocolBehavior>, agent: AgentName, step: usize) -> bool {
    ctx.knowledge_store.knowledges().iter().any(|k| {
        k.source == Source::Agent(agent)
            && k.step.as_ref().is_some_and(|s| s.step == step)
            && k.data.as_any().is::<RawSshMessageFlight>()
    })
}

/// The last two input steps of `seed_client_attacker_rekey_complete`: the packets sealed under the
/// keys of its rekey, which the server answers with CHANNEL_OPEN_CONFIRMATION and REQUEST_FAILURE.
fn post_rekey_inputs(trace: &Trace<SshProtocolTypes>) -> Vec<usize> {
    let inputs: Vec<usize> = (0..trace.steps.len())
        .filter(|&i| matches!(trace.steps[i].action, Action::Input(_)))
        .collect();
    inputs[inputs.len() - 2..].to_vec()
}

/// `seed_client_attacker_rekey_complete` sends its last two packets under the keys of its rekey.
/// `corpus_seeds_run_on_every_put` does not see whether those keys are right: the libssh harness
/// drops a packet whose GCM tag fails without reporting an error, so the trace still ends `Ok`.
/// Each PUT must answer both packets (and the differential decrypts the answers:
/// `the_differential_decrypts_the_server_after_its_rekey`).
#[test]
fn rekey_complete_is_answered_after_the_rekey() {
    let server = AgentName::first();
    let trace = seed_client_attacker_rekey_complete(server);
    let after_rekey = post_rekey_inputs(&trace);
    let _exec = put_exec_lock();
    for put in all_puts() {
        let (res, ctx) = execute_on(&put, &[server], &trace);
        assert!(res.is_ok(), "rekey_complete on {put}: {res:?}");
        for &step in &after_rekey {
            assert!(
                answered(&ctx, server, step),
                "rekey_complete on {put}: no reply to the post-rekey step {step}"
            );
        }
    }
}

/// The messages of the transcript the differential decrypts from the server's output: the one
/// transcript its decryption recipes yield (with a vendor's current instrumentation, the epochs
/// fold; with an older one, the first-epoch fold).
fn decrypted_transcript(
    ctx: &TraceContext<SshProtocolBehavior>,
    server: AgentName,
    put: &str,
) -> Vec<SshMessage> {
    transcript_of(&server_decryption_recipes_aesgcm(server), ctx, put)
}

/// The messages of the transcript `recipes` give in `ctx`, the recipes of one agent's output in
/// the differential: exactly one of them gives it.
fn transcript_of(
    recipes: &[SshTerm],
    ctx: &TraceContext<SshProtocolBehavior>,
    put: &str,
) -> Vec<SshMessage> {
    let transcripts: Vec<AlignedTranscript> = recipes
        .iter()
        .filter_map(|recipe| recipe.evaluate_dy(ctx).ok())
        .filter_map(|t| t.as_any().downcast_ref::<AlignedTranscript>().cloned())
        .collect();
    assert_eq!(
        transcripts.len(),
        1,
        "{put}: one decryption recipe yields the transcript"
    );
    let t = &transcripts[0];
    t.order.iter().map(|key| t.by_key[key].clone()).collect()
}

/// The last claim of `agent`: the one the decryption recipes read (`((agent, 0))` resolves to it).
fn last_claim(
    ctx: &TraceContext<SshProtocolBehavior>,
    agent: AgentName,
    put: &str,
) -> SshClaimInner {
    ctx.find_claim(agent, TypeShape::of::<Box<SshClaimInner>>())
        .and_then(|claim| {
            claim
                .as_any()
                .downcast_ref::<Box<SshClaimInner>>()
                .map(|inner| (**inner).clone())
        })
        .unwrap_or_else(|| panic!("{put}: no claim of {agent}"))
}

/// `claim` carries the secrets of `count` key exchanges, all curve25519-sha256 in the seeds: a
/// 32-byte exchange hash and a shared secret each. Only the first one's exchange hash is the
/// session id: a rekey's is its own (RFC 4253 §7.2).
fn assert_kex_secrets(claim: &SshClaimInner, count: usize, put: &str) {
    let secrets = &claim.kex_secrets;
    assert_eq!(
        secrets.len(),
        count,
        "{put}: the last claim carries the secrets of {} key exchanges",
        secrets.len()
    );
    for (i, kex) in secrets.iter().enumerate() {
        assert_eq!(kex.exchange_hash.len(), 32, "{put}: H of key exchange {i}");
        assert!(
            !kex.shared_secret.is_empty(),
            "{put}: K of key exchange {i}"
        );
        assert_eq!(
            kex.exchange_hash == claim.session_id,
            i == 0,
            "{put}: H of key exchange {i}, against the session id"
        );
    }
}

/// The messages after the second NEWKEYS of `messages`: those sealed under the keys of the rekey.
fn after_rekey_newkeys<'a>(messages: &'a [SshMessage], put: &str) -> &'a [SshMessage] {
    let rekey_newkeys = messages
        .iter()
        .enumerate()
        .filter(|(_, m)| matches!(m, SshMessage::NewKeys))
        .nth(1)
        .map(|(i, _)| i)
        .unwrap_or_else(|| panic!("{put}: the rekey's NEWKEYS is not decrypted: {messages:?}"));
    &messages[rekey_newkeys + 1..]
}

/// The differential decrypts the server's output after its rekey too, from the secrets of both key
/// exchanges its last claim carries: on every PUT, `rekey_complete`'s transcript goes on past the
/// rekey's NEWKEYS (the second in the server's output) to the replies to the two packets sealed
/// under the rekey's keys, CHANNEL_OPEN_CONFIRMATION and REQUEST_FAILURE. The differential of
/// every libssh and wolfSSH pair finds no difference. (The claim of the rekey repeats the auth
/// belief of the claim before it: the claim comparison, which merges adjacent equal claims, does
/// not see it.)
#[test]
fn the_differential_decrypts_the_server_after_its_rekey() {
    let server = AgentName::first();
    let trace = seed_client_attacker_rekey_complete(server);
    let _exec = put_exec_lock();
    for put in all_puts() {
        let (res, ctx) = execute_on(&put, &[server], &trace);
        assert!(res.is_ok(), "rekey_complete on {put}: {res:?}");
        assert_kex_secrets(&last_claim(&ctx, server, &put), 2, &put);
        let messages = decrypted_transcript(&ctx, server, &put);
        let after_rekey = after_rekey_newkeys(&messages, &put);
        assert!(
            after_rekey
                .iter()
                .any(|m| matches!(m, SshMessage::ChannelOpenConfirmation(_))),
            "{put}: no CHANNEL_OPEN_CONFIRMATION decrypted after the rekey: {messages:?}"
        );
        assert!(
            after_rekey
                .iter()
                .any(|m| matches!(m, SshMessage::RequestFailure)),
            "{put}: no REQUEST_FAILURE decrypted after the rekey: {messages:?}"
        );
    }
    let (libssh, wolfssh) = libssh_and_wolfssh_puts();
    for first in &libssh {
        for second in &wolfssh {
            differential(first, second, server, &trace)
                .unwrap_or_else(|d| panic!("rekey_complete on {first} x {second}: {d}"));
        }
    }
}

thread_local! {
    /// What `fn_batched_packets` sends: set before the trace that sends it executes.
    static BATCHED_PACKETS: std::cell::RefCell<Vec<u8>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// The packets of several steps, in one write: `BATCHED_PACKETS`.
fn fn_batched_packets() -> Result<RawSshMessage, FnError> {
    Ok(RawSshMessage::OnWire(OnWireData(
        BATCHED_PACKETS.with(|packets| packets.borrow().clone()),
    )))
}

/// The bytes the input step `step` of `trace` sends to `agent` on `put`, in an execution after a
/// reseed, as `MakeMessage` computes them (`make_message_term`): an execution after another reseed
/// derives the same session keys, so a packet sealed under them stays valid there.
fn sent_bytes(trace: &SshTrace, step: usize, agent: AgentName, put: &str) -> Vec<u8> {
    let trace = SshProtocolTypes::preprocess_trace(trace).unwrap_or_else(|| trace.clone());
    let desc = PutDescriptor::new(put, PutOptions::default());
    let mut ctx: TraceContext<SshProtocolBehavior> =
        TraceContext::new(Spawner::new(ssh_registry()).with_mapping(&[(agent, desc)]));
    ctx.determinism_reseed();
    trace
        .execute_until_step(&mut ctx, step, &mut 0, true)
        .unwrap_or_else(|e| panic!("{put}: the steps before {step}: {e}"));
    let Action::Input(input) = &trace.steps[step].action else {
        panic!("step {step} is not an input");
    };
    input
        .execute_precomputations(&mut ctx)
        .unwrap_or_else(|e| panic!("{put}: the precomputations of step {step}: {e}"));
    input
        .recipe
        .evaluate_symbolic(&ctx)
        .unwrap_or_else(|e| panic!("{put}: the recipe of step {step}: {e}"))
}

/// A client may send the end of its key exchange and its authentication in one write: here
/// KEX_ECDH_INIT, NEWKEYS, SERVICE_REQUEST and USERAUTH_REQUEST, in one step. The server's claims
/// then both come from inside that step, from its authentication. They carry the secrets of the
/// key exchange all the same, and the differential decrypts the server's answers from them. (The
/// harnesses used to record the secrets around a step only: these claims had none, and the
/// differential fell back to the keys from the wire.)
///
/// Except on libssh before 0.11, whose `ssh_handle_key_exchange` does not end once the client has
/// authenticated in the key exchange's write: its `ssh_server_kex_termination` misses
/// `SSH_SESSION_STATE_AUTHENTICATED` (0.11 added it). The harness then stays in its key exchange
/// and emits no completion claim; its last claim is the post-KEX claim of the end of the step.
#[test]
fn a_key_exchange_batched_with_the_authentication_gives_its_secrets_to_the_claims() {
    let server = AgentName::first();
    let seed = seed_client_attacker_full_aesgcm(server);
    let batched = [
        input_with_symbol(&seed, "fn_kex_ecdh_init"),
        input_with_symbol(&seed, "fn_new_keys"),
        input_with_symbol(&seed, "fn_service_request"),
        input_with_symbol(&seed, "fn_user_auth_request"),
    ];
    let mut trace = seed.clone();
    trace.steps.truncate(batched[0]);
    trace
        .steps
        .push(InputAction::new_step(server, term! { fn_batched_packets }));
    trace.steps.push(OutputAction::new_step(server));

    let libssh = put_names("libssh");
    let _exec = put_exec_lock();
    for put in all_puts() {
        let packets: Vec<u8> = batched
            .iter()
            .flat_map(|&step| sent_bytes(&seed, step, server, &put))
            .collect();
        BATCHED_PACKETS.with(|batch| *batch.borrow_mut() = packets);
        ssh_registry().determinism_reseed_all_factories();
        let (res, ctx) = execute_on(&put, &[server], &trace);
        assert!(res.is_ok(), "{put}: {res:?}");
        let claim = last_claim(&ctx, server, &put);
        let kex_ends = !libssh.contains(&put) || library_version(&put) >= vec![0, 11];
        assert_eq!(
            claim.auth_method,
            if kex_ends { "password" } else { "" },
            "{put}: the auth belief of the last claim"
        );
        assert_kex_secrets(&claim, 1, &put);
        let messages = decrypted_transcript(&ctx, server, &put);
        assert!(
            messages
                .iter()
                .any(|m| matches!(m, SshMessage::ServiceAccept(_))),
            "{put}: no SERVICE_ACCEPT decrypted: {messages:?}"
        );
        assert!(
            messages
                .iter()
                .any(|m| matches!(m, SshMessage::UserAuthSuccess)),
            "{put}: no USERAUTH_SUCCESS decrypted: {messages:?}"
        );
    }
}

/// A rekey that never completes: the attacker sends the KEXINIT and KEX_ECDH_INIT of its rekey,
/// not its NEWKEYS, then opens a channel under the first keys. The server's outbound keys switch
/// at its own NEWKEYS all the same, and its last claim carries the secrets of both key exchanges
/// from then on. wolfSSH answers the channel open in that window (the RFC 4253 §7.1 divergence of
/// `seed_client_attacker_rekey_channel_auto`): the differential decrypts its
/// CHANNEL_OPEN_CONFIRMATION, after the server's second NEWKEYS, with the keys of the rekey.
/// libssh refuses it, and ends the session there ("Packet filter: rejected packet").
#[test]
fn the_differential_decrypts_the_server_in_a_rekey_that_never_completes() {
    let server = AgentName::first();
    let seed = seed_client_attacker_rekey_channel_auto(server);
    let open = input_with_symbol(&seed, "fn_channel_open");
    let mut trace = seed.clone();
    let newkeys = trace.steps.pop().expect("the seed has steps");
    assert!(
        matches!(&newkeys.action, Action::Input(input) if has_symbol(&input.recipe, "fn_new_keys")),
        "the seed ends with the NEWKEYS of its rekey"
    );
    // The channel open and the output after it, moved past the server's NEWKEYS.
    let channel_open: Vec<_> = trace.steps.drain(open..open + 2).collect();
    trace.steps.extend(channel_open);
    let moved_open = trace.steps.len() - 2;

    let wolfssh = put_names("wolfssh");
    let _exec = put_exec_lock();
    for put in all_puts() {
        let (res, ctx) = execute_on(&put, &[server], &trace);
        if wolfssh.contains(&put) {
            assert!(res.is_ok(), "{put}: {res:?}");
        } else {
            assert!(
                matches!(&res, Err(puffin::error::Error::Put(e)) if e.contains("Packet filter")),
                "{put}: {res:?}"
            );
            assert_eq!(ctx.executed_until, moved_open, "{put}");
        }
        assert_kex_secrets(&last_claim(&ctx, server, &put), 2, &put);
        let messages = decrypted_transcript(&ctx, server, &put);
        let after_rekey = after_rekey_newkeys(&messages, &put);
        if wolfssh.contains(&put) {
            assert!(
                after_rekey
                    .iter()
                    .any(|m| matches!(m, SshMessage::ChannelOpenConfirmation(_))),
                "{put}: no CHANNEL_OPEN_CONFIRMATION decrypted after the rekey: {messages:?}"
            );
        }
    }
}

/// The differential decrypts a client PUT's output after its rekey too, with the c2s epochs fold,
/// from the secrets of both key exchanges in the client's last claim: in
/// `seed_server_attacker_rekey_complete`, the attacker sends a global request under the keys of a
/// rekey it started, and the client's REQUEST_FAILURE comes after its second NEWKEYS.
#[test]
fn the_differential_decrypts_the_client_after_its_rekey() {
    let client = AgentName::first();
    let trace = seed_server_attacker_rekey_complete(client);
    let _exec = put_exec_lock();
    for put in all_puts() {
        let (res, ctx) = execute_on(&put, &[client], &trace);
        assert!(res.is_ok(), "{put}: {res:?}");
        assert_kex_secrets(&last_claim(&ctx, client, &put), 2, &put);
        let messages = transcript_of(&client_decryption_recipes_aesgcm(client), &ctx, &put);
        let after_rekey = after_rekey_newkeys(&messages, &put);
        assert!(
            after_rekey
                .iter()
                .any(|m| matches!(m, SshMessage::RequestFailure)),
            "{put}: no REQUEST_FAILURE decrypted after the rekey: {messages:?}"
        );
    }
}

/// The claims carry no secrets of a key exchange whose K the key derivation does not take as an
/// mpint: the hybrids of libssh 0.12, sntrup761x25519 (K a 64-byte string in `shared_secret`) and
/// ML-KEM (K in `hybrid_shared_secret`). As an mpint, a K starting with 0 or 0x80 and more would
/// derive wrong keys; without secrets, the differential decrypts the first epoch from the wire. In
/// the same trace, curve25519-sha256 gives its secrets to both claims, and the differential
/// decrypts what each peer sends from them.
#[test]
fn a_hybrid_key_exchange_gives_no_secrets_to_the_claims() {
    let client = AgentName::first();
    let server = client.next();
    let libssh_hybrid: Vec<String> = put_names("libssh")
        .into_iter()
        .filter(|put| library_version(put) >= vec![0, 12])
        .collect();
    if libssh_hybrid.is_empty() {
        eprintln!("skipped: no libssh PUT from 0.12 on");
        return;
    }
    let _exec = put_exec_lock();
    for put in &libssh_hybrid {
        for (kex, secrets) in [
            ("sntrup761x25519-sha512", 0),
            ("sntrup761x25519-sha512@openssh.com", 0),
            ("mlkem768x25519-sha256", 0),
            ("curve25519-sha256", 1),
        ] {
            let mut trace = seed_handshake_two_party_packet_complete(client, server);
            for agent in &mut trace.descriptors {
                agent.protocol_config.kex = Some(kex.into());
                agent.protocol_config.ciphers = Some("aes256-gcm@openssh.com".into());
            }
            let (res, ctx) = execute_on(put, &[client, server], &trace);
            assert!(res.is_ok(), "{put}, {kex}: {res:?}");
            for agent in [client, server] {
                assert_eq!(
                    last_claim(&ctx, agent, put).kex_secrets.len(),
                    secrets,
                    "{put}, {kex}: the secrets in the last claim of {agent}"
                );
            }
            if secrets == 0 {
                continue;
            }
            let server_messages = decrypted_transcript(&ctx, server, put);
            assert!(
                server_messages
                    .iter()
                    .any(|m| matches!(m, SshMessage::UserAuthSuccess)),
                "{put}, {kex}: no USERAUTH_SUCCESS decrypted: {server_messages:?}"
            );
            let client_messages =
                transcript_of(&client_decryption_recipes_aesgcm(client), &ctx, put);
            assert!(
                client_messages
                    .iter()
                    .any(|m| matches!(m, SshMessage::UserAuthRequest(_))),
                "{put}, {kex}: no USERAUTH_REQUEST decrypted: {client_messages:?}"
            );
        }
    }
}

/// `MakeMessage` on the root of a sealed step replaces the recipe by its encoding. An unmodified
/// payload must be the packet the step would have sent: same keys (the step's precomputations)
/// and same counter (numbered by `preprocess_trace`), so the PUT still answers after the rekey.
#[test]
fn make_message_on_sealed_steps_keeps_the_rekey_answered() {
    let server = AgentName::first();
    let seed = seed_client_attacker_rekey_complete(server);
    let after_rekey = post_rekey_inputs(&seed);
    let sealed: Vec<usize> = (0..seed.steps.len())
        .filter(|&i| {
            matches!(&seed.steps[i].action, Action::Input(input) if !input.precomputations.is_empty())
        })
        .collect();
    assert!(sealed.len() >= 6, "sealed steps of the seed: {sealed:?}");

    let _exec = put_exec_lock();
    for put in all_puts() {
        let desc = PutDescriptor::new(&put, PutOptions::default());
        for &step in &sealed {
            let mut trace = seed.clone();
            let mut make_ctx: TraceContext<SshProtocolBehavior> = TraceContext::new(
                Spawner::new(ssh_registry()).with_mapping(&[(server, desc.clone())]),
            );
            make_message_term(&mut trace, &(step, vec![]), &mut make_ctx)
                .unwrap_or_else(|e| panic!("MakeMessage on step {step} on {put}: {e}"));

            // Reseeded like the partial execution of `MakeMessage`: the payload holds a packet
            // sealed under the session keys of that execution.
            ssh_registry().determinism_reseed_all_factories();
            let (res, ctx) = execute_on(&put, &[server], &trace);
            assert!(res.is_ok(), "payload at step {step} on {put}: {res:?}");
            for &answer in &after_rekey {
                assert!(
                    answered(&ctx, server, answer),
                    "payload at step {step} on {put}: no reply to step {answer}"
                );
            }
        }
    }
}

// ── The policies of the two harnesses ───────────────────────────────────────

type SshTerm = Term<SshProtocolTypes>;
type SshTrace = Trace<SshProtocolTypes>;

fn wire_string(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u32).to_be_bytes());
    out.extend_from_slice(value);
}

fn fn_pty_request_data() -> Result<Vec<u8>, FnError> {
    let mut data = vec![];
    wire_string(&mut data, b"xterm");
    for dimension in [80u32, 24, 0, 0] {
        data.extend_from_slice(&dimension.to_be_bytes());
    }
    wire_string(&mut data, b"");
    Ok(data)
}

fn fn_env_request() -> Result<SshBytes, FnError> {
    Ok(SshBytes::new(b"env".to_vec()))
}

fn fn_env_request_data() -> Result<Vec<u8>, FnError> {
    let mut data = vec![];
    wire_string(&mut data, b"LANG");
    wire_string(&mut data, b"C");
    Ok(data)
}

fn fn_subsystem_request() -> Result<SshBytes, FnError> {
    Ok(SshBytes::new(b"subsystem".to_vec()))
}

fn fn_subsystem_request_data() -> Result<Vec<u8>, FnError> {
    let mut data = vec![];
    wire_string(&mut data, b"sftp");
    Ok(data)
}

/// Bytes announcing a packet longer than any PUT accepts.
fn fn_oversized_packet() -> Result<RawSshMessage, FnError> {
    Ok(RawSshMessage::OnWire(OnWireData(vec![0xff; 64])))
}

fn replace_term(term: &mut SshTerm, from: &SshTerm, to: &SshTerm) {
    if &*term == from {
        *term = to.clone();
    } else if let DYTerm::Application(_, args) = &mut term.term {
        for arg in args {
            replace_term(arg, from, to);
        }
    }
}

/// `trace` with each `(from, to)` applied to every recipe.
fn with_replaced(trace: &SshTrace, replacements: &[(SshTerm, SshTerm)]) -> SshTrace {
    let mut trace = trace.clone();
    for step in &mut trace.steps {
        if let Action::Input(input) = &mut step.action {
            for (from, to) in replacements {
                replace_term(&mut input.recipe, from, to);
                for precomputation in &mut input.precomputations {
                    replace_term(&mut precomputation.recipe, from, to);
                }
            }
        }
    }
    trace
}

/// Whether `term` holds a function symbol called `name`.
fn has_symbol(term: &SshTerm, name: &str) -> bool {
    match &term.term {
        DYTerm::Application(function, args) => {
            function.name().ends_with(name) || args.iter().any(|arg| has_symbol(arg, name))
        }
        DYTerm::Variable(_) => false,
    }
}

/// The index of the first input step whose recipe holds the function symbol `name`.
fn input_with_symbol(trace: &SshTrace, name: &str) -> usize {
    trace
        .steps
        .iter()
        .position(|step| matches!(&step.action, Action::Input(i) if has_symbol(&i.recipe, name)))
        .unwrap_or_else(|| panic!("no input step with {name}"))
}

/// `term` with the service name inside its userauth signature changed: the signature no longer
/// verifies, while the request around it is the same.
fn break_signature(term: &mut SshTerm) {
    if let DYTerm::Application(function, args) = &mut term.term {
        if function.name().ends_with("fn_sign_userauth") {
            let (signed, other): (SshTerm, SshTerm) =
                (term! { fn_ssh_connection }, term! { fn_ssh_userauth });
            replace_term(&mut args[3], &signed, &other);
        } else {
            args.iter_mut().for_each(break_signature);
        }
    }
}

/// The libssh and wolfSSH PUTs that can run the attacker seeds.
fn libssh_and_wolfssh_puts() -> (Vec<String>, Vec<String>) {
    let wolfssh = put_names("wolfssh");
    all_puts()
        .into_iter()
        .partition(|put| !wolfssh.contains(put))
}

/// The differences `differential-execute first second` reports on `trace`, if any.
fn differential(
    first: &str,
    second: &str,
    agent: AgentName,
    trace: &SshTrace,
) -> Result<(), String> {
    let trace = SshProtocolTypes::differential_fuzzing_uniformise_put_config(trace.clone());
    let spawner = |put: &str| {
        Spawner::new(ssh_registry())
            .with_mapping(&[(agent, PutDescriptor::new(put, PutOptions::default()))])
    };
    let runner = DifferentialRunner::new(ssh_registry(), spawner(first), spawner(second));
    (&runner)
        .execute(&trace, &mut 0)
        .map(|_| ())
        .map_err(|e| e.to_string())
}

/// `display-execute`: `-t` shows the recipe as stored, with its `fn_u32_auto` counter, and `-r`
/// the bytes the PUT received, with the packet's real counter.
#[test]
fn display_execute_shows_the_stored_recipe_and_the_sent_bytes() {
    let server = AgentName::first();
    let trace = seed_client_attacker_full_aesgcm(server);
    let preprocessed = SshProtocolTypes::preprocess_trace(&trace).expect("the seed is renumbered");
    // The second sealed packet: its counter is 1, not the sentinel's value.
    let step = (0..trace.steps.len())
        .filter(|&i| matches!(&trace.steps[i].action, Action::Input(i) if has_symbol(&i.recipe, "fn_u32_auto")))
        .nth(1)
        .expect("two sealed packets");
    let hex = |bytes: Vec<u8>| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let _exec = put_exec_lock();
    for put in all_puts() {
        let (res, ctx) = execute_on(&put, &[server], &trace);
        assert!(res.is_ok(), "{put}: {res:?}");
        let (Action::Input(stored), Action::Input(sent)) =
            (&trace.steps[step].action, &preprocessed.steps[step].action)
        else {
            unreachable!()
        };
        let stored_bytes = hex(stored.recipe.evaluate(&ctx).expect("the stored recipe"));
        let sent_bytes = hex(sent.recipe.evaluate(&ctx).expect("the sent recipe"));
        assert_ne!(stored_bytes, sent_bytes, "{put}");

        let shown = ExecutionResult::from(put.clone(), None, &trace, ctx, true, false, false, true);
        let shown = serde_json::to_value(&shown).unwrap();
        let input = &shown["execution"]["steps"][step]["action"]["Input"];
        assert!(
            input["recipe"].as_str().unwrap().contains("fn_u32_auto"),
            "{put}: {input}"
        );
        assert_eq!(input["raw"].as_str(), Some(sent_bytes.as_str()), "{put}");
    }
}

/// A PUT against itself in a differential: its second execution starts from the same seed as the
/// first, so it draws the same randomness (same ephemeral keys, hence the same session id).
#[test]
fn a_differential_runs_both_executions_from_the_same_seed() {
    let server = AgentName::first();
    let trace = seed_client_attacker_full_aesgcm(server);
    let session_id = |ctx: &TraceContext<SshProtocolBehavior>| {
        ctx.find_claim(server, TypeShape::of::<Box<SshClaimInner>>())
            .and_then(|claim| {
                claim
                    .as_any()
                    .downcast_ref::<Box<SshClaimInner>>()
                    .map(|inner| inner.session_id.clone())
            })
            .expect("a session-id claim")
    };
    let _exec = put_exec_lock();
    for put in all_puts() {
        let spawner = Spawner::new(ssh_registry())
            .with_mapping(&[(server, PutDescriptor::new(&put, PutOptions::default()))]);
        let runner = DifferentialRunner::new(ssh_registry(), spawner.clone(), spawner);
        let (first, second) = (&runner)
            .execute(&trace, &mut 0)
            .unwrap_or_else(|e| panic!("{put} against itself: {e}"));
        assert_eq!(session_id(&first), session_id(&second), "{put}");
    }
}

/// Requests whose answer is the harness's decision: both harnesses decide the same. Each case is
/// a default seed with one request changed, and must show no difference between any libssh and
/// any wolfSSH.
#[test]
fn harnesses_decide_the_same() {
    let server = AgentName::first();
    let forwarding = seed_client_attacker_forwarding(server);
    let session = seed_client_attacker_session_requests(server);
    let (forward, cancel): (SshTerm, SshTerm) = (
        term! { fn_request_tcpip_forward },
        term! { fn_request_cancel_tcpip_forward },
    );
    let (allowed, refused): (SshTerm, SshTerm) = (
        term! { fn_tcpip_forward_data((fn_addr_localhost), (fn_port_ssh)) },
        term! { fn_tcpip_forward_data((fn_addr_localhost), (fn_u32_5)) },
    );
    let (exec, exec_data): (SshTerm, SshTerm) = (
        term! { fn_channel_exec },
        term! { fn_exec_payload((fn_exec_command_userauth)) },
    );
    let mut bad_signature = seed_client_attacker_pubkey_aesgcm(server);
    let signed_request = input_with_symbol(&bad_signature, "fn_sign_userauth");
    bad_signature.steps.truncate(signed_request + 2);
    if let Action::Input(input) = &mut bad_signature.steps[signed_request].action {
        break_signature(&mut input.recipe);
    }

    let cases = [
        (
            "cancel-tcpip-forward of an allowed port",
            with_replaced(&forwarding, &[(forward.clone(), cancel.clone())]),
        ),
        (
            "cancel-tcpip-forward of another port",
            with_replaced(
                &forwarding,
                &[
                    (forward.clone(), cancel),
                    (allowed.clone(), refused.clone()),
                ],
            ),
        ),
        (
            "tcpip-forward of another port",
            with_replaced(&forwarding, &[(allowed, refused)]),
        ),
        (
            "pty-req",
            with_replaced(
                &session,
                &[
                    (exec.clone(), term! { fn_channel_pty_req }),
                    (exec_data.clone(), term! { fn_pty_request_data }),
                ],
            ),
        ),
        (
            "env",
            with_replaced(
                &session,
                &[
                    (exec.clone(), term! { fn_env_request }),
                    (exec_data.clone(), term! { fn_env_request_data }),
                ],
            ),
        ),
        (
            "subsystem",
            with_replaced(
                &session,
                &[
                    (exec, term! { fn_subsystem_request }),
                    (exec_data, term! { fn_subsystem_request_data }),
                ],
            ),
        ),
        (
            "publickey query about an unauthorized key",
            with_replaced(
                &seed_client_attacker_pubkey_query(server),
                &[(
                    term! { fn_client_a_pubkey_blob },
                    term! { fn_client_c_pubkey_blob },
                )],
            ),
        ),
        (
            "publickey request whose signature does not verify",
            bad_signature,
        ),
    ];

    let (libssh, wolfssh) = libssh_and_wolfssh_puts();
    let _exec = put_exec_lock();
    let mut failures = Vec::new();
    for first in &libssh {
        for second in &wolfssh {
            for (name, trace) in &cases {
                if let Err(difference) = differential(first, second, server, trace) {
                    failures.push(format!("{name} on {first} x {second}: {difference}"));
                }
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// A SERVICE_REQUEST other than `ssh-userauth` ends the session, on every PUT at that step.
#[test]
fn a_refused_service_ends_the_session() {
    let server = AgentName::first();
    let seed = seed_client_attacker_full_aesgcm(server);
    let request = input_with_symbol(&seed, "fn_service_request");
    let trace = with_replaced(
        &seed,
        &[(term! { fn_ssh_userauth }, term! { fn_ssh_connection })],
    );
    let _exec = put_exec_lock();
    for put in all_puts() {
        let (res, ctx) = execute_on(&put, &[server], &trace);
        assert!(
            matches!(res, Err(puffin::error::Error::Put(_))),
            "{put}: {res:?}"
        );
        assert_eq!(ctx.executed_until, request, "{put}");
    }
}

/// A fatal error after the handshake reaches the trace: the harnesses used to return `Ok` from
/// the DONE state whatever happened.
#[test]
fn an_error_after_the_handshake_ends_the_session() {
    let server = AgentName::first();
    let mut trace = seed_client_attacker_session_requests(server);
    trace
        .steps
        .truncate(input_with_symbol(&trace, "fn_channel_exec") + 2);
    let oversized = trace.steps.len();
    trace
        .steps
        .push(InputAction::new_step(server, term! { fn_oversized_packet }));
    trace.steps.push(OutputAction::new_step(server));
    let _exec = put_exec_lock();
    for put in all_puts() {
        let (res, ctx) = execute_on(&put, &[server], &trace);
        assert!(
            matches!(res, Err(puffin::error::Error::Put(_))),
            "{put}: {res:?}; {:?}",
            ctx.find_agent(server)
        );
        assert_eq!(ctx.executed_until, oversized, "{put}");
    }
}

/// The client side of the test above: once its shell runs, the client still reads what the
/// server sends, and an oversized packet ends the session at its step on every PUT. (The libssh
/// client harness used to read nothing more once done, where the wolfSSH client goes on in
/// `wolfSSH_worker()`.)
#[test]
fn an_error_after_the_client_handshake_ends_the_session() {
    let client = AgentName::first();
    let mut trace = seed_server_attacker_session_aesgcm(client);
    let oversized = trace.steps.len();
    trace
        .steps
        .push(InputAction::new_step(client, term! { fn_oversized_packet }));
    let _exec = put_exec_lock();
    for put in all_puts() {
        let (res, ctx) = execute_on(&put, &[client], &trace);
        assert!(
            matches!(res, Err(puffin::error::Error::Put(_))),
            "{put}: {res:?}; {:?}",
            ctx.find_agent(client)
        );
        assert_eq!(ctx.executed_until, oversized, "{put}");
    }
}

/// The bytes of `first`, then those of `second`, in one write: the PUT reads both in one step.
fn fn_back_to_back(
    first: &RawSshMessage,
    second: &RawSshMessage,
) -> Result<RawSshMessage, FnError> {
    let mut bytes = first.get_encoding();
    second.encode(&mut bytes);
    Ok(RawSshMessage::OnWire(OnWireData(bytes)))
}

/// A channel the client closes before any request on it: wolfSSH reports the close from inside
/// `accept()`, which then refuses to run again. The session must go on, on every PUT: a second
/// channel open is answered, and an oversized packet ends the session at its step. (The wolfSSH
/// harness used to stay in its handshake state, where every later step was `Ok` without a read.)
#[test]
fn a_channel_closed_before_any_request_leaves_the_session_running() {
    let server = AgentName::first();
    let seed = seed_client_attacker_session_requests(server);
    let open = input_with_symbol(&seed, "fn_channel_open");
    let mut closed = seed.clone();
    closed.steps.drain(
        input_with_symbol(&seed, "fn_channel_exec")..input_with_symbol(&seed, "fn_channel_close"),
    );

    let mut reopened = closed.clone();
    let second_open = reopened.steps.len();
    reopened
        .steps
        .extend(seed.steps[open..open + 2].iter().cloned());

    let mut oversized = closed;
    let oversized_step = oversized.steps.len();
    oversized
        .steps
        .push(InputAction::new_step(server, term! { fn_oversized_packet }));

    let _exec = put_exec_lock();
    for put in all_puts() {
        let (res, ctx) = execute_on(&put, &[server], &reopened);
        assert!(res.is_ok(), "{put}: {res:?}");
        assert!(
            answered(&ctx, server, second_open),
            "{put}: the second CHANNEL_OPEN is not answered"
        );
        let (res, ctx) = execute_on(&put, &[server], &oversized);
        assert!(
            matches!(res, Err(puffin::error::Error::Put(_))),
            "{put}: {res:?}; {:?}",
            ctx.find_agent(server)
        );
        assert_eq!(ctx.executed_until, oversized_step, "{put}");
    }
}

/// A packet sent right behind channel data, in the same write, while the server is still in its
/// handshake (no request on the channel yet): every PUT handles it in that step. (The wolfSSH
/// harness used to return once the data was read, leaving the packet behind it for later.)
#[test]
fn a_packet_behind_channel_data_is_handled_in_the_same_step() {
    let server = AgentName::first();
    let mut trace = seed_client_attacker_channel_data(server);
    let data = input_with_symbol(&trace, "fn_channel_data");
    trace.steps.truncate(data + 1);
    if let Action::Input(input) = &mut trace.steps[data].action {
        let packet = input.recipe.clone();
        input.recipe = term! { fn_back_to_back((@packet), (fn_oversized_packet)) };
    }
    let _exec = put_exec_lock();
    for put in all_puts() {
        let (res, ctx) = execute_on(&put, &[server], &trace);
        assert!(
            matches!(res, Err(puffin::error::Error::Put(_))),
            "{put}: {res:?}; {:?}",
            ctx.find_agent(server)
        );
        assert_eq!(ctx.executed_until, data, "{put}");
    }
}

fn fn_username_with_nul() -> Result<Username, FnError> {
    Ok(Username::new(b"user\0x".to_vec()))
}

fn fn_username_too_long() -> Result<Username, FnError> {
    Ok(Username::new([b"user".as_slice(), &[b'x'; 200]].concat()))
}

/// The user an agent's last claim says it authenticated, `""` for none.
fn authenticated_user(ctx: &TraceContext<SshProtocolBehavior>, agent: AgentName) -> String {
    ctx.find_claim(agent, TypeShape::of::<Box<SshClaimInner>>())
        .and_then(|claim| {
            claim
                .as_any()
                .downcast_ref::<Box<SshClaimInner>>()
                .map(|inner| inner.auth_user.clone())
        })
        .unwrap_or_default()
}

/// The harnesses authorize a user name only if it is exactly an allowed one, here with the right
/// password: a name longer than a claim holds is refused on every PUT, and so is a name with an
/// embedded NUL on wolfSSH. libssh hands its harness the name as a C string, cut at the NUL, so a
/// libssh PUT that accepts "user\0x" can only claim "user": that is libssh's decision (an open
/// divergence), never a name the client did not send.
#[test]
fn a_user_name_that_is_not_an_allowed_one_is_refused() {
    let server = AgentName::first();
    let seed = seed_client_attacker_full_aesgcm(server);
    let (_, wolfssh) = libssh_and_wolfssh_puts();
    let user: SshTerm = term! { fn_username };
    let with_nul = with_replaced(&seed, &[(user.clone(), term! { fn_username_with_nul })]);
    let too_long = with_replaced(&seed, &[(user, term! { fn_username_too_long })]);
    let _exec = put_exec_lock();
    for put in all_puts() {
        let (_, ctx) = execute_on(&put, &[server], &seed);
        assert_eq!(authenticated_user(&ctx, server), "user", "{put}: the seed");
        let (_, ctx) = execute_on(&put, &[server], &too_long);
        assert_eq!(authenticated_user(&ctx, server), "", "{put}: a long name");
        let (_, ctx) = execute_on(&put, &[server], &with_nul);
        let claimed = authenticated_user(&ctx, server);
        if wolfssh.contains(&put) {
            assert_eq!(claimed, "", "{put}: a name with a NUL");
        } else {
            assert!(
                claimed.is_empty() || claimed == "user",
                "{put}: a name with a NUL claimed as {claimed:?}"
            );
        }
    }
}

/// A DISCONNECT from the peer after the handshake ends the session on every PUT, at that step.
#[test]
fn a_disconnect_after_the_handshake_ends_the_session() {
    let server = AgentName::first();
    let seed = seed_client_attacker_session_requests(server);
    let eof = input_with_symbol(&seed, "fn_channel_eof");
    let mut trace = seed.clone();
    trace.steps.truncate(eof + 2);
    if let Action::Input(input) = &mut trace.steps[eof].action {
        let disconnect: SshTerm =
            term! { fn_disconnect((fn_u32_2), (fn_ssh_bytes_empty), (fn_ssh_bytes_empty)) };
        let DYTerm::Application(_, args) = &mut input.recipe.term else {
            unreachable!()
        };
        args[0] = disconnect;
    }
    let _exec = put_exec_lock();
    for put in all_puts() {
        let (res, ctx) = execute_on(&put, &[server], &trace);
        assert!(
            matches!(res, Err(puffin::error::Error::Put(_))),
            "{put}: {res:?}; {:?}",
            ctx.find_agent(server)
        );
        assert_eq!(ctx.executed_until, eof, "{put}");
    }
}

/// The claim with the session id comes at the peer's NEWKEYS on every PUT, server and client: not
/// before it, and also when that NEWKEYS is the last thing the PUT processes.
#[test]
fn the_session_id_claim_comes_at_the_peer_newkeys() {
    let put_agent = AgentName::first();
    let _exec = put_exec_lock();
    for (role, seed) in [
        ("server", seed_client_attacker_full_aesgcm(put_agent)),
        ("client", seed_server_attacker_full_aesgcm(put_agent)),
    ] {
        let newkeys = input_with_symbol(&seed, "fn_new_keys");
        let until = |steps: usize| {
            let mut trace = seed.clone();
            trace.steps.truncate(steps);
            trace
        };
        let session_id = |ctx: &TraceContext<SshProtocolBehavior>| {
            ctx.find_claim(put_agent, TypeShape::of::<Box<SshClaimInner>>())
                .is_some()
        };
        for put in all_puts() {
            let (res, ctx) = execute_on(&put, &[put_agent], &until(newkeys));
            assert!(res.is_ok(), "{put} {role}: {res:?}");
            assert!(
                !session_id(&ctx),
                "{put} {role}: a claim before the NEWKEYS"
            );
            let (res, ctx) = execute_on(&put, &[put_agent], &until(newkeys + 1));
            assert!(res.is_ok(), "{put} {role}: {res:?}");
            assert!(session_id(&ctx), "{put} {role}: no claim at the NEWKEYS");
        }
    }
}
