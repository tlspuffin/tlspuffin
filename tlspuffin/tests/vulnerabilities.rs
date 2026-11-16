use puffin::execution::{ExecutionStatus, ForkedRunner, Runner, TraceRunner};
use puffin::fuzzer::bit_mutations::{havoc_mutations_dy, MakeMessage, ReadMessage};
use puffin::fuzzer::mutations::MutationConfig;
use puffin::fuzzer::stages::FocusScheduledMutator;
use puffin::fuzzer::utils::{find_term, find_term_mut};
use puffin::libafl::corpus::InMemoryCorpus;
use puffin::libafl::mutators::{MutationResult, MutatorsTuple};
use puffin::libafl::prelude::{HasRand, StdState};
use puffin::libafl_bolts::bolts_prelude::{tuple_list, Rand, RomuDuoJrRand};
use puffin::libafl_bolts::tuples::NamedTuple;
use puffin::libafl_bolts::HasLen;
use puffin::put::PutDescriptor;
use puffin::put_registry::TCP_PUT;
use puffin::trace::{ConfigTrace, Spawner, Trace};
use tlspuffin::protocol::{TLSProtocolTypes, TLSVersion};
use tlspuffin::test_utils::{create_state, test_mutations};
#[allow(unused_imports)]
use tlspuffin::{test_utils::prelude::*, tls::seeds::*, tls::vulnerabilities::*};

// Vulnerable up until OpenSSL 1.0.1j
#[apply(test_puts,
    attrs = [ignore], // We cannot check for this vulnerability right now
    filter = all(CVE_2015_0204, tls12, asan)
)]
fn test_seed_freak(put: &str) {
    expect_trace_crash(
        seed_freak.build_trace(),
        default_runner_for(put),
        std::time::Duration::from_secs(20),
        Some(20),
    );
}

// #[apply(test_puts, filter = all(CVE_2014_0160, tls12, asan))]
// fn test_seed_heartbleed(put: &str) {
//     expect_trace_crash(
//         seed_heartbleed.build_trace(),
//         default_runner_for(put),
//         std::time::Duration::from_secs(20),
//         Some(20),
//     );
// }

#[apply(test_puts, filter = all(CVE_2021_3449, tls12))]
fn test_seed_cve_2021_3449(put: &str) {
    expect_trace_crash(
        seed_cve_2021_3449.build_trace(),
        default_runner_for(put),
        std::time::Duration::from_secs(20),
        Some(20),
    );
}

#[apply(test_puts,
    attrs = [should_panic(expected = "Authentication bypass")],
    filter = all(
        CVE_2022_25640,
        tls13,
        client_authentication_transcript_extraction
    )
)]
fn test_seed_cve_2022_25640(put: &str) {
    let runner = default_runner_for(put);
    let trace = seed_cve_2022_25640.build_trace();

    let ctx = runner.execute(trace, &mut 0).unwrap();

    assert!(ctx.agents_successful());
}

#[apply(test_puts,
    attrs = [should_panic(expected = "Authentication bypass")],
    filter = all(
        CVE_2022_25640,
        tls13,
        client_authentication_transcript_extraction
    )
)]
fn test_seed_cve_2022_25640_simple(put: &str) {
    let runner = default_runner_for(put);
    let trace = seed_cve_2022_25640_simple.build_trace();

    let ctx = runner.execute(trace, &mut 0).unwrap();

    assert!(ctx.agents_successful());
}

#[apply(test_puts,
    attrs = [should_panic(expected = "Authentication bypass")],
    filter = all(
        CVE_2022_25638,
        tls13,
        client_authentication_transcript_extraction
    )
)]
fn test_seed_cve_2022_25638(put: &str) {
    let runner = default_runner_for(put);
    let trace = seed_cve_2022_25638.build_trace();

    let ctx = runner.execute(trace, &mut 0).unwrap();

    assert!(ctx.agents_successful());
}

#[apply(test_puts,
    filter = all(
        CVE_2022_38152,
        tls12,
    )
)]
fn test_seed_cve_2022_38152(put: &str) {
    expect_trace_crash(
        seed_session_resumption_dhe_full.build_trace(),
        default_runner_for_desc(puffin::put::PutDescriptor::new(
            put,
            vec![("use_clear", "true")],
        )),
        std::time::Duration::from_secs(20),
        Some(20),
    );
}

#[apply(test_puts,
    filter = all(
        CVE_2022_38153,
        tls12,
        tls12_session_resumption,
    )
)]
fn test_seed_cve_2022_38153(put: &str) {
    let runner = default_runner_for(put);
    let trace = seed_successful12_with_tickets.build_trace();

    let _ = runner.execute(trace.clone(), &mut 0).unwrap();
    /*
    Originally, puffin found this bug because wolfssl was not made deterministic at all. The bug requires that the
    shared (across sessions) ticket map gets filled until a collision happen (a key refers to two tickets). For this to
    happen, we need to create several **different** tickets. This won't happen, now that wolfssl is made
    deterministic (the same ticket will be created at the end of a single handshake). We mimick the old behavior
    here, using `.execute_config`.

    Theoretically, this attack can still be found with a deterministic WolfSSL: mutations could repeat a full
    handshake multiple times (hence yielding different tickets) and then appending the malicious handshake.
    This is extremely unlikely to happen though; or even impossible given the bounds on the trace lengths. In
    the future, we might want to reconsider whether we **always** want to reseed prior to executing a trace.
    */
    for _ in 1..50 {
        let _ = runner
            .execute_config(
                trace.clone(),
                ConfigTrace {
                    with_reseed: false,
                    ..ConfigTrace::default()
                },
                &mut 0,
            )
            .unwrap();
    }

    expect_trace_crash(
        seed_cve_2022_38153.build_trace(),
        runner,
        std::time::Duration::from_secs(20),
        Some(20),
    );
}

// Test whether we can refind cve_2022_38153 through bit-level mutations by first:
// 1. Mutating with MakeMessage the sub-term of interest
// 2. Applying HAVOC mutations randomly
// 3. For each batch of HAVOC mutations, then apply ReadMessage and execute

#[apply(test_puts,
    filter = all(
        CVE_2022_38153,
        tls12,
        tls12_session_resumption,
    )
)]
#[ignore]
fn test_seed_bitmut_cve_2022_38153(put: &str) {
    let timeout_secs = 60 * 10 as u64;
    let max_muts = 10; // 10 (*10 buckets)
    let max_all_tries = 1_000_000; // 1M
    let mut all_tries = 0;
    let mut mutant_tries = 0;
    let trace = seed_successful12_with_tickets.build_trace();
    let runner = default_runner_for(put);
    let path_make_message = (9, vec![1, 0]);
    for _ in 0..50 {
        let _ = runner.execute(trace.clone(), &mut 0).unwrap();
    }

    let timeout = std::time::Duration::from_secs(timeout_secs);
    let registry = tls_registry();
    let mut state = create_state();
    let mut mutations = test_mutations(&registry, true, true);
    let max_mut_idx = mutations.len();
    let min_mut_idx = 9; // Hence all HAVOC mutations, excluding MakeMessage and ReadMessage

    // Different overall tries, should work for at least one
    while all_tries < max_all_tries && mutant_tries < 10_000 {
        log::error!("While all_tries {all_tries} < max_all_tries {max_all_tries} and mutant_tries {mutant_tries} < 1000");
        // 1000
        mutant_tries += 1;
        let mut mutant = seed_cve_simple_2022_38153.build_trace();

        // MakeMessage mutant
        let ctx = runner
            .execute(seed_cve_simple_2022_38153.build_trace(), &mut 0)
            .unwrap();
        let term_to_mutate = find_term_mut(&mut mutant, &path_make_message).unwrap();
        term_to_mutate.make_payload(&ctx).unwrap();
        // let long_vec: BytesInput = vec![42; 700].into(); -- Now reproduced with the following
        // mutations

        let forked_runner = ForkedRunner::new(&runner).with_timeout(timeout);

        // Succession of mutations
        log::error!("[START] Try mutant_tries: {mutant_tries} / all_tries: {all_tries}");

        let mut skip = false;

        'outer: for j_mut in 0..max_muts {
            // log::error!("outer for: j_mut = {j_mut}");
            if all_tries < max_all_tries {
                // excluding MakeMessage because of min_mut_idx = 9
                for _j_mut_bucket in 0..10 {
                    // do 10 mutations at once
                    all_tries += 1;
                    // let min_mut_idx = 23;
                    // let max_mut_idx = 30;
                    let mut_idx = state.rand_mut().between(min_mut_idx, max_mut_idx - 1);
                    if mut_idx != 1000 {
                        match mutations
                            .get_and_mutate(mut_idx.into(), &mut state, &mut mutant)
                            .unwrap()
                        {
                            MutationResult::Mutated => {
                                log::info!(
                                    "[{j_mut}] Success mutation nb{mut_idx}: {}",
                                    mutations.names()[mut_idx]
                                );

                                if mut_idx == 27 {
                                    if let Some(payload) = &find_term(&mutant, &path_make_message)
                                        .as_ref()
                                        .unwrap()
                                        .payloads
                                    {
                                        log::error!(
                                            "[{all_tries}] [{j_mut}] ExpandLarge [{}] YESS: {}",
                                            mutations.names()[mut_idx],
                                            payload.payload.len()
                                        );
                                    }
                                }
                            }
                            MutationResult::Skipped => {
                                log::info!(
                                    "[{j_mut}] Fail mutation nb{mut_idx}: {}",
                                    mutations.names()[mut_idx]
                                );
                            }
                        };
                    }
                }
                // Check length is long enough
                if let Some(payload) = &find_term(&mutant, &path_make_message)
                    .as_ref()
                    .unwrap()
                    .payloads
                {
                    // We mutate the payloads, so we need to make sure that the payload is readable
                    if payload.payload.len() > 250 {
                        log::error!(
                            "[{all_tries}] [{j_mut}] =========> Payload is sufficiently long: {} bytes",
                            payload.payload.len()
                        );
                    } else {
                        log::warn!(
                            "[{all_tries}] [{j_mut}] ==> Length: {}",
                            payload.payload.len()
                        );
                        // log::error!("{mutant}");
                    }
                } else {
                    log::error!(
                        "[{all_tries}] [{j_mut}] No payload at position {path_make_message:?}!"
                    );
                }
                // We applied a number of HAVOC mutations, we now copy the mutant and shotgun
                // ReadMessage on the right location and see if we can trigger the bug
                let mut trace_to_execute = mutant.clone();

                let read_message_idx = 8; // ReadMessage mutation
                match mutations
                    .get_and_mutate(read_message_idx.into(), &mut state, &mut trace_to_execute)
                    .unwrap()
                {
                    MutationResult::Mutated => {
                        log::warn!("[RM] Success [{}]", mutations.names()[read_message_idx]);
                    }
                    MutationResult::Skipped => {
                        log::error!("[RM] Failed [{}]", mutations.names()[read_message_idx]);
                    }
                }
                log::warn!("[EXECUTE] Try mutant_tries: {mutant_tries} / all_tries: {all_tries}");
                let mut success = false;
                forked_runner
                    .execute(&trace_to_execute, &mut 0)
                    .inspect(|status| {
                        use ExecutionStatus as S;
                        match &status {
                            S::Crashed => {
                                log::warn!("{mutant_tries}/{all_tries} trace execution crashed");
                                success = true;
                            }
                            S::Failure(_) => {
                                log::warn!("{mutant_tries}/{all_tries} invalid trace... skipping");
                                skip = true;
                            }

                            S::Timeout => log::warn!(
                                "{mutant_tries}/{all_tries} trace execution
                timed out"
                            ),
                            S::Interrupted => {
                                log::warn!(
                                    "{mutant_tries}/{all_tries} trace execution interrupted,
                skipping..."
                                );
                                skip = true;
                            }
                            S::Success => {
                                log::warn!("{mutant_tries}/{all_tries} success")
                            }
                        };
                    })
                    .expect("Could not fork_runner {mutant_tries}/{all_tries}");
                if success {
                    log::error!("SUCCESS (crashed) after mutant_tries: {mutant_tries} / all_tries: {all_tries}. ");
                    return ();
                }
                if skip {
                    break 'outer;
                }
            }
        }
    }
    panic!("No crash after {max_all_tries} tries");
}
/* Note on excluding HAVOC mutations:
Excluding mut_idx != 23 && mut_idx != 24 && mut_idx != 25 :
    [2025-06-03T14:49:23Z ERROR vulnerabilities] SUCCESS (crashed) after mutant_tries: 11 / all_tries: 1060.
    With ReadMessage "random":
        [2025-06-05T12:16:19Z ERROR vulnerabilities] SUCCESS (crashed) after mutant_tries: 21 / all_tries: 2060.
Excluding mut_idx != 23 && mut_idx != 24:
    [2025-06-03T14:49:54Z ERROR vulnerabilities] SUCCESS (crashed) after mutant_tries: 69 / all_tries: 6860
Excluding mut_idx != 24:
    [2025-06-03T14:52:53Z ERROR vulnerabilities] SUCCESS (crashed) after mutant_tries: 128 / all_tries: 12730.
    With ReadMessage "random":
        [2025-06-05T12:23:16Z ERROR vulnerabilities] SUCCESS (crashed) after mutant_tries: 14 / all_tries: 1360.  ???
W Fail to read a readable term (originated from ReadMessage), should never happen!ithout excluding:
    No crash after 1000000 tries!!
 */

/* Note on previous test:
The ReadMessage mutation yields the same modification as the following ones, all at once:

let path_make_message = (9, vec![]);
let term_to_mutate = find_term_mut(&mut mutant, &path_make_message).unwrap();
term_to_mutate.make_payload(&ctx);
// Reproduce correct record layer length
term_to_mutate
    .payloads
    .as_mut()
    .unwrap()
    .payload
    .bytes_mut()[3] = 2;
term_to_mutate[...]
    .bytes_mut()[4] = 198;

// Reproduce correct handshake layer length
term_to_mutate[...]
    .bytes_mut()[7] = 2;
term_to_mutate[...]
    .bytes_mut()[8] = 194;

// Reproduce correct Payloadu16 layer length (just before the actual payload (42
// times `700`) Note that for other cases like heartbleed, we
// specifically want to be able to lie about the length!
term_to_mutate[...]
    .bytes_mut()[13] = 2;
term_to_mutate[...]
    .bytes_mut()[14] = 188;
*/

// Test whether we can refind cve_2022_38153 through bit-level mutations by only applying HAVOC,
// MakeMessage, and ReadMessage mutations randomly
#[apply(test_puts,
    filter = all(
        CVE_2022_38153,
        tls12,
        tls12_session_resumption,
    )
)]
fn test_seed_only_mut_bitmut_cve_2022_38153(put: &str) {
    let timeout_secs = 60 * 10 as u64;
    let max_muts = 10; // 10 (*10 buckets)
    let max_all_tries = 1_000_000; // 1M
    let mut all_tries = 0;
    let mut mutant_tries = 0;
    let trace = seed_successful12_with_tickets.build_trace();
    let runner = default_runner_for(put);
    // let path_make_message = (9, vec![1, 0]);
    for _ in 0..50 {
        let _ = runner.execute(trace.clone(), &mut 0).unwrap();
    }

    let timeout = std::time::Duration::from_secs(timeout_secs);
    let registry = tls_registry();
    let mut state = create_state();
    // let mut mutations = test_mutations(&registry, true, true);
    // let max_mut_idx = mutations.len();
    // let min_mut_idx = 7; // Hence all HAVOC mutations, including MakeMessage and ReadMessage

    let _ = runner
        .execute(seed_cve_simple_2022_38153.build_trace(), &mut 0)
        .unwrap();

    // Different overall tries, should work for at least one
    while all_tries < max_all_tries && mutant_tries < 100_000 {
        log::error!("While all_tries {all_tries} < max_all_tries {max_all_tries} and mutant_tries {mutant_tries} < 1000");
        // 1000
        mutant_tries += 1;
        let forked_runner = ForkedRunner::new(&runner).with_timeout(timeout);
        let mut mutant = seed_cve_simple_2022_38153.build_trace();

        // Succession of mutations
        log::error!("[START] Try mutant_tries: {mutant_tries} / all_tries: {all_tries}");

        let mut skip = false;

        'outer: for _j_mut in 0..max_muts {
            // log::error!("outer for: j_mut = {j_mut}");
            if all_tries < max_all_tries {
                let config = MutationConfig {
                    with_focus: true,
                    ..MutationConfig::default_with_bit()
                };
                let mut mutator_bit_focus = FocusScheduledMutator::new(
                    tuple_list!(MakeMessage::new(config, &registry)),
                    havoc_mutations_dy::<
                        StdState<
                            InMemoryCorpus<Trace<TLSProtocolTypes>>,
                            Trace<TLSProtocolTypes>,
                            RomuDuoJrRand,
                            InMemoryCorpus<Trace<TLSProtocolTypes>>,
                        >,
                        TLSProtocolTypes,
                    >(config),
                    tuple_list!(ReadMessage::new(config, &registry)),
                );
                all_tries += 1;
                match mutator_bit_focus.mutate(&mut state, &mut mutant) {
                    Ok(r) => match r {
                        MutationResult::Mutated => {
                            log::info!("[Focus] Success");
                        }
                        MutationResult::Skipped => {
                            log::error!("[Focus] Failure");
                        }
                    },
                    Err(_) => {
                        log::error!("[Focus] Error <===================");
                    }
                }

                // // excluding MakeMessage because of min_mut_idx = 9
                // for _j_mut_bucket in 0..10 {
                //     all_tries += 1;
                //     let mut_idx = state
                //         .rand_mut()
                //         .between(min_mut_idx, max_mut_idx as u64 - 1)
                //         as usize;
                //     let _ = mutations
                //         .get_and_mutate(mut_idx.into(), &mut state, &mut mutant, 0)
                //         .unwrap();
                // }

                // // Check length is long enough
                // if let Some(payload) = &find_term(&mutant, &path_make_message)
                //     .as_ref()
                //     .unwrap()
                //     .payloads
                // {
                //     // We mutate the payloads, so we need to make sure that the payload is
                // readable     if payload.payload.bytes().len() > 250 {
                //         log::error!(
                //             "[{all_tries}] [{j_mut}]
                // ========================================> Payload is sufficiently long: {}
                // bytes",             payload.payload.bytes().len()
                //         );
                //     } else {
                //         log::warn!(
                //             "[{all_tries}] [{j_mut}]                                         ==>
                // Length: {}",             payload.payload.bytes().len()
                //         );
                //         // log::error!("{mutant}");
                //     }
                // } else {
                //     log::error!(
                //         "[{all_tries}] [{j_mut}] No payload at position {path_make_message:?}!"
                //     );
                // }
                // // With: [2025-06-06T14:14:28Z ERROR vulnerabilities] SUCCESS (crashed) after
                // mutant_tries: 154 / all_tries: 6060. // Without:
                // let read_message_idx = 8; // ReadMessage mutation
                // match mutations
                //     .get_and_mutate(read_message_idx.into(), &mut state, &mut mutant, 0)
                //     .unwrap()
                // {
                //     MutationResult::Mutated => {
                //         log::warn!("[RM] Success [{}]", mutations.names()[read_message_idx]);
                //     }
                //     MutationResult::Skipped => {
                //         log::error!("[RM] Failed [{}]", mutations.names()[read_message_idx]);
                //     }
                // }
                log::warn!("[EXECUTE] Try mutant_tries: {mutant_tries} / all_tries: {all_tries}");
                let mut success = false;
                forked_runner
                    .execute(&mutant, &mut 0)
                    .inspect(|status| {
                        use ExecutionStatus as S;
                        match &status {
                            S::Crashed => {
                                log::error!("{mutant_tries}/{all_tries} trace execution crashed");
                                success = true;
                            }
                            S::Failure(_) => {
                                log::warn!("{mutant_tries}/{all_tries} invalid trace... skipping");
                                skip = true;
                            }

                            S::Timeout => log::warn!(
                                "{mutant_tries}/{all_tries} trace execution
                timed out"
                            ),
                            S::Interrupted => {
                                log::warn!(
                                    "{mutant_tries}/{all_tries} trace execution interrupted,
                skipping..."
                                );
                                skip = true;
                            }
                            S::Success => {
                                log::warn!("{mutant_tries}/{all_tries} success")
                            }
                        };
                    })
                    .expect("Could not fork_runner {mutant_tries}/{all_tries}");
                if success {
                    log::error!("SUCCESS (crashed) after mutant_tries: {mutant_tries} / all_tries: {all_tries}. ");
                    return ();
                }
                if skip {
                    break 'outer;
                }
            }
        }
    }
    panic!("No crash after {max_all_tries} tries");
}

#[apply(test_puts,
    filter = all(
        CVE_2022_39173,
        tls13,
        tls13_session_resumption,
        asan,
    )
)]
fn test_seed_cve_2022_39173(put: &str) {
    expect_trace_crash(
        seed_cve_2022_39173.build_trace(),
        default_runner_for(put),
        std::time::Duration::from_secs(20),
        Some(20),
    );
}

#[apply(test_puts,
    filter = all(
        CVE_2022_39173,
        tls13,
        tls13_session_resumption,
        asan,
    )
)]
fn test_seed_cve_2022_39173_full(put: &str) {
    expect_trace_crash(
        seed_cve_2022_39173_full.build_trace(),
        default_runner_for(put),
        std::time::Duration::from_secs(20),
        Some(20),
    );
}

#[apply(test_puts,
    filter = all(
        CVE_2022_39173,
        tls13,
        tls13_session_resumption,
        asan,
    )
)]
fn test_seed_cve_2022_39173_minimized(put: &str) {
    expect_trace_crash(
        seed_cve_2022_39173_minimized.build_trace(),
        default_runner_for(put),
        std::time::Duration::from_secs(20),
        Some(20),
    );
}

#[test_log::test]
#[ignore] // wolfssl example server and client are not available in CI
fn tcp_wolfssl_openssl_test_seed_cve_2022_38153() {
    let trace = seed_cve_2022_38153.build_trace();

    let server_port = 44336;
    let server_agent = trace.descriptors[1].name;
    let server_guard = openssl_server(server_port, TLSVersion::V1_2);
    let server = PutDescriptor::new(TCP_PUT, server_guard.build_options());

    let client_port = 44337;
    let client_agent = trace.descriptors[0].name;
    let client_guard = wolfssl_client(client_port, TLSVersion::V1_2, Some(50));
    let client = PutDescriptor::new(TCP_PUT, client_guard.build_options());

    let put_registry = tls_registry();
    let runner = Runner::new(
        put_registry.clone(),
        Spawner::new(put_registry).with_mapping(&[(client_agent, client), (server_agent, server)]),
    );

    let mut context = runner.execute(trace, &mut 0).unwrap();

    let shutdown = context.find_agent_mut(client_agent).unwrap().shutdown();
    log::info!("{}", shutdown);
    assert!(shutdown.contains("free(): invalid pointer"));
}

#[test_log::test]
#[ignore] // wolfssl example server and client are not available in CI
fn tcp_wolfssl_cve_2022_39173() {
    let port = 44338;
    let guard = wolfssl_server(port, TLSVersion::V1_3);
    let trace = seed_cve_2022_39173_full.build_trace();
    let runner = default_runner_for_desc(PutDescriptor::new(TCP_PUT, guard.build_options()));
    let server = trace.descriptors[0].name;

    let mut context = runner.execute(trace, &mut 0).unwrap();

    let shutdown = context.find_agent_mut(server).unwrap().shutdown();
    log::info!("{}", shutdown);
}

#[apply(test_puts,
     attrs = [should_panic(expected = "Negotiated cipher is not in agent's configured ciphers list")],
     filter = all(CVE_2024_5814, tls12, tls13)
)]
fn test_seed_cve_2024_5814(put: &str) {
    let runner = default_runner_for(put);
    let trace = seed_cve_2024_5814.build_trace();
    let ctx = runner.execute(trace, &mut 0).unwrap();
    assert!(ctx.agents_successful());
}

/// <https://nvd.nist.gov/vuln/detail/CVE-2025-11934>
///
/// The client under test offers only RSA-PSS+SHA256 in its `signature_algorithms` extension
/// (see `seed_cve_2025_11934`'s `sigalgs` PUT config). The attacker-crafted `CertificateVerify`
/// is genuinely signed with an EC private key under ECDSA_NISTP256_SHA256 (wire value 0x0403) -
/// an algorithm the client never offered. On vulnerable wolfSSL 5.8.2/5.8.3,
/// `DoTls13CertificateVerify` only checks that the client holds *some* ECC key (it does, since
/// the attacker also supplied the matching EC certificate), never that 0x0403 is actually a
/// member of the offered list, so the handshake completes and the downgrade succeeds.
///
/// Detection goes through `TlsSecurityViolationPolicy::check_violation` (`tls/violation.rs`),
/// which compares the client's `Finished` claim's `peer_signature_algorithm` against its own
/// `available_signature_algorithms` (populated straight from `ssl->suites->hashSigAlgo`, the
/// exact list the official patch validates against). `runner.execute(..).unwrap()` panics with
/// that violation's message when the mismatch is detected, hence `should_panic` below, mirroring
/// `test_seed_cve_2024_5814`'s cipher-downgrade check rather than asserting on the claim directly.
#[apply(test_puts,
     attrs = [should_panic(expected = "Negotiated signature algorithm is not in agent's configured signature algorithms list")],
     filter = all(CVE_2025_11934, tls13)
)]
fn test_seed_cve_2025_11934(put: &str) {
    let runner = default_runner_for(put);
    let trace = seed_cve_2025_11934.build_trace();
    let ctx = runner.execute(trace, &mut 0).unwrap();
    assert!(ctx.agents_successful());
}

/// Retries `mutator` on a fresh clone of `base` until `accept` holds on the result, then returns
/// that mutated trace. All in-memory term operations (no PUT involved), so even a few tens of
/// thousands of attempts - the worst individually-estimated case below - run in well under a
/// second; only the single final `runner.execute` below touches a real PUT.
fn force_mutation_until<M>(
    base: &Trace<TLSProtocolTypes>,
    mutator: &mut M,
    state: &mut tlspuffin::test_utils::TLSState,
    accept: impl Fn(&Trace<TLSProtocolTypes>) -> bool,
) -> Trace<TLSProtocolTypes>
where
    M: puffin::libafl::mutators::Mutator<Trace<TLSProtocolTypes>, tlspuffin::test_utils::TLSState>,
{
    loop {
        let mut candidate = base.clone();
        mutator.mutate(state, &mut candidate).unwrap();
        if accept(&candidate) {
            return candidate;
        }
    }
}

/// Does NOT fuzz anything: it forces, one at a time, the exact four mutations identified by the
/// statistical analysis as the only way to reach CVE-2025-11934 from a *default*-corpus seed
/// (`seed_server_attacker_full`, whose `sigalgs` is restricted to `"RSA-PSS+SHA256"`), then checks
/// that the resulting trace is a genuine, detected attack - not just that the four mutations
/// individually type-check.
///
/// Each step is driven to completion by `force_mutation_until` rather than left to chance: blindly
/// hoping all four land together in one real campaign has been estimated at roughly 1e-17 (the
/// corpus-selection dilution alone, ignored here since we start directly from the right seed, was
/// already ~1/1000; each mutation step on its own is comparatively reachable - which is why
/// forcing them one at a time, rather than all at once, is computationally trivial). This test
/// exists to confirm two things the written analysis could not, on its own, be fully sure of: that
/// `ReplaceFunctionReshapeMutator` produces a correct result on this real, deep TLS construction
/// (not just the synthetic test in `puffin::fuzzer::mutations::tests`), and that no fifth
/// requirement was missed - if the oracle does not fire at the end, the reachability analysis
/// itself is wrong.
///
/// Steps 1-3 require *every* occurrence of the old function to flip, not just one: each of
/// `fn_alice_cert`/`fn_alice_key`/`fn_rsa_pss_signature_algorithm` is duplicated across the trace
/// (the `CertificateVerify` term is embedded both in the message actually sent and in the
/// dependency chain used to compute `server_finished`). `ReplaceMatchMutator`'s scope mechanism
/// (Global/Step) only replicates a replacement to occurrences that are still structurally *equal*
/// to the one chosen as representative - so accepting a partial flip (satisfied by the more likely
/// Individual scope) leaves the two copies of the signing call looking different from each other,
/// which silently makes step 4's required Global-scope flip impossible to ever satisfy afterwards
/// (confirmed empirically while writing this test: 0 full flips in 300,000 tries once the earlier
/// steps were left partial, versus a steady, non-zero rate once they require a full flip too).
///
/// 1. Certificate: `fn_alice_cert` -> `fn_alice_ec_cert` (`ReplaceMatchMutator`). Alice's EC
///    certificate, not the untrusted `fn_random_ec_cert`: the client's trust store only accepts
///    Alice's (or Eve's) identity, in either of its RSA/EC forms - any other self-signed
///    certificate fails chain validation before `CertificateVerify` is ever reached, regardless
///    of how the rest of the message is built (confirmed empirically: swapping in
///    `fn_random_ec_cert` here makes wolfSSL reject with "ASN self-signed certificate error" at
///    `DoTls13Certificate`, before `DoTls13CertificateVerify` ever runs).
/// 2. Signing key: `fn_alice_key` -> `fn_alice_ec_key` (`ReplaceMatchMutator`) - the private key
///    matching the certificate from step 1.
/// 3. Declared *and* signed-with scheme: `fn_rsa_pss_signature_algorithm` ->
///    `fn_ecdsa_signature_algorithm`, both occurrences at once via the Global/Step scope
///    mechanism (`ReplaceMatchMutator`).
/// 4. Signing call shape: `fn_rsa_sign_server(transcript, key, scheme)` ->
///    `fn_ecdsa_sign_server(transcript, key)`, dropping `scheme` and keeping `transcript`/`key` by
///    positional type match (`ReplaceFunctionReshapeMutator`).
#[apply(test_puts,
    attrs = [should_panic(expected = "Negotiated signature algorithm is not in agent's configured signature algorithms list")],
    filter = all(CVE_2025_11934, tls13)
)]
fn test_mutators_can_reach_cve_2025_11934(put: &str) {
    use puffin::algebra::dynamic_function::DescribableFunction;
    use puffin::fuzzer::mutations::{
        MutationConfig, ReplaceFunctionReshapeMutator, ReplaceMatchMutator,
    };
    use puffin::protocol::ProtocolTypes;
    use tlspuffin::test_utils::create_state;
    use tlspuffin::tls::fn_impl::*;

    let mut state = create_state();
    let signature = TLSProtocolTypes::signature();
    let config = MutationConfig::default_with_bit();

    let mut replace_match = ReplaceMatchMutator::new(config, signature);
    let mut reshape = ReplaceFunctionReshapeMutator::new(config, signature);

    let mut trace = seed_server_attacker_full.build_trace();

    // 1. Certificate (every occurrence - the term is duplicated across the trace, e.g. once for
    //    the direct wire send and once more inside the dependency chain used to compute
    //    `server_finished`; a partial flip would leave the two copies structurally different from
    //    each other, which would silently block step 4's Global-scope replication later, since it
    //    relies on both copies of the signing call still being equal to one another).
    trace = force_mutation_until(&trace, &mut replace_match, &mut state, |t| {
        t.count_functions_by_name(fn_alice_cert.name()) == 0
            && t.count_functions_by_name(fn_alice_ec_cert.name()) > 0
    });

    // 2. Signing key (every occurrence, same reasoning as above).
    trace = force_mutation_until(&trace, &mut replace_match, &mut state, |t| {
        t.count_functions_by_name(fn_alice_key.name()) == 0
            && t.count_functions_by_name(fn_alice_ec_key.name()) > 0
    });

    // 3. Declared + signed scheme (both occurrences, via Global scope).
    trace = force_mutation_until(&trace, &mut replace_match, &mut state, |t| {
        t.count_functions_by_name(fn_rsa_pss_signature_algorithm.name()) == 0
            && t.count_functions_by_name(fn_ecdsa_signature_algorithm.name()) > 0
    });

    // 4. Signing call shape.
    trace = force_mutation_until(&trace, &mut reshape, &mut state, |t| {
        t.count_functions_by_name(fn_rsa_sign_server.name()) == 0
            && t.count_functions_by_name(fn_ecdsa_sign_server.name()) > 0
    });

    let runner = default_runner_for(put);
    let ctx = runner.execute(trace, &mut 0).unwrap();
    assert!(ctx.agents_successful());
}
