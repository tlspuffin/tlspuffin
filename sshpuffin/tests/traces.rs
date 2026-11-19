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
use sshpuffin::ssh::message::{OnWireData, RawSshMessage, SshBytes, Username};
use sshpuffin::ssh::seeds::*;

/// Serialises the tests that EXECUTE PUTs, which `cargo test` runs on parallel threads. The
/// harnesses keep their RNG state per thread, but the libraries share process-wide state
/// (libssh draws through OpenSSL's global RAND method). Hold it for the whole execution.
static PUT_EXEC_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn put_exec_lock() -> std::sync::MutexGuard<'static, ()> {
    PUT_EXEC_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// Every PUT of the binary that can run the seeds, libssh then wolfSSH: those of each vendor the
/// build found (`has_libssh`, `has_wolfssh`), so that a test cannot pass on no PUT. The seeds all
/// encrypt with AES-GCM, which libssh only has from 0.9.0 on: an older libssh (`libssh083`) stops
/// at their key exchange and is skipped, and a binary whose only libssh is one fails here.
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
/// every libssh, and wolfSSH from 1.6.0 on, where it is on by default (wolfSSH PR 1271).
fn has_strict_kex(put: &str) -> bool {
    if put_names("libssh").iter().any(|p| p == put) {
        return true;
    }
    library_version(put) >= vec![1, 6]
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
/// Neither the differential nor `corpus_seeds_run_on_every_put` sees whether those keys are right:
/// the decrypted transcript stops at the rekey's NEWKEYS, and the libssh harness drops a packet
/// whose GCM tag fails without reporting an error, so the trace still ends `Ok`. Each PUT must
/// answer both packets.
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
