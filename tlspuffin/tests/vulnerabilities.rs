use puffin::execution::{ExecutionStatus, ForkedRunner, Runner, TraceRunner};
use puffin::fuzzer::utils::{find_term, find_term_mut};
use puffin::libafl::inputs::{BytesInput, HasBytesVec};
use puffin::libafl::mutators::{MutationResult, MutatorsTuple};
use puffin::libafl::prelude::HasRand;
use puffin::libafl_bolts::bolts_prelude::Rand;
use puffin::libafl_bolts::tuples::HasConstLen;
use puffin::put::PutDescriptor;
use puffin::put_registry::TCP_PUT;
use puffin::trace::Spawner;
use tlspuffin::protocol::TLSVersion;
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

    let ctx = runner.execute(trace).unwrap();

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

    let ctx = runner.execute(trace).unwrap();

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

    let ctx = runner.execute(trace).unwrap();

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
        default_runner_for(puffin::put::PutDescriptor::new(
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

    for _ in 0..50 {
        let _ = runner.execute(trace.clone()).unwrap();
    }

    expect_trace_crash(
        seed_cve_2022_38153.build_trace(),
        runner,
        std::time::Duration::from_secs(20),
        Some(20),
    );
}
// Test whether we can refind cve_2022_38153 through bit-level mutations
#[apply(test_puts,
    filter = all(
        CVE_2022_38153,
        tls12,
        tls12_session_resumption,
    )
)]
fn test_seed_through_bit_mutations_cve_2022_38153(put: &str) {
    let timeout_secs = 60 * 10 as u64;
    let max_muts = 1; // 1K
    let max_all_tries = 1_000; // 1M
    let mut all_tries = 0;
    let mut mutant_tries = 0;
    let trace = seed_successful12_with_tickets.build_trace();
    let runner = default_runner_for(put);
    let path_make_message = (9, vec![1, 0]);
    for _ in 0..50 {
        let _ = runner.execute(trace.clone()).unwrap();
    }

    let timeout = std::time::Duration::from_secs(timeout_secs);
    let registry = tls_registry();
    let mut state = create_state();
    let mut mutations = test_mutations(&registry, true, false);
    let max_mut_idx = mutations.len();
    let min_mut_idx = 8; // Hence excluding MakeMessage

    // Different overall tries, should work for at least one
    while all_tries < max_all_tries && mutant_tries < 1 {
        // 1000
        mutant_tries += 1;
        let mut mutant = seed_cve_simple_2022_38153.build_trace();

        // MakeMessage mutant
        let ctx = runner
            .execute(seed_cve_simple_2022_38153.build_trace())
            .unwrap();
        let term_to_mutate = find_term_mut(&mut mutant, &path_make_message).unwrap();
        term_to_mutate.make_payload(&ctx);
        let long_vec: BytesInput = vec![42; 700].into();
        term_to_mutate.payloads.as_mut().unwrap().payload = long_vec;

        log::error!("Trace to mutate: {}", mutant);
        log::error!("Payloads: {:?}", mutant.all_payloads());

        let forked_runner = ForkedRunner::new(&runner).with_timeout(timeout);

        // Succession of mutations
        log::error!("[START] Try mutant_tries: {mutant_tries} / all_tries: {all_tries}");
        'outer: for j_mut in 0..max_muts {
            if all_tries < max_all_tries {
                // excluding MakeMessage because of with_dy: false
                for _j_mut_bucket in 0..0 {
                    // 100
                    // do 10 mutations at once
                    all_tries += 1;
                    let mut_idx = state
                        .rand_mut()
                        .between(min_mut_idx, max_mut_idx as u64 - 1)
                        as usize;
                    match mutations
                        .get_and_mutate(mut_idx.into(), &mut state, &mut mutant, 0)
                        .unwrap()
                    {
                        MutationResult::Mutated => {
                            log::debug!(
                                "[{j_mut}] Success mutation nb{mut_idx}: {}",
                                mutations.names()[mut_idx]
                            );
                        }
                        MutationResult::Skipped => {
                            log::debug!(
                                "[{j_mut}] Fail mutation nb{mut_idx}: {}",
                                mutations.names()[mut_idx]
                            );
                        }
                    };
                }
                let mut skip = false;
                log::warn!("Payloads are: {:?}", mutant.all_payloads());
                let term_to_mutate = find_term(&mutant, &path_make_message).unwrap();
                log::error!("term_to_mutate: {:?}", term_to_mutate);

                // let mut mutant = seed_cve_simple_2022_38153.build_trace();
                // let mut mutant = seed_cve_2022_38153.build_trace();
                // // MakeMessage mutant
                // ---------- Test to reproduce the bug by cheating with the record layer length
                // information ----------- //
                let ctx = runner
                    .execute(seed_cve_simple_2022_38153.build_trace())
                    .unwrap();
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
                term_to_mutate
                    .payloads
                    .as_mut()
                    .unwrap()
                    .payload
                    .bytes_mut()[4] = 198;

                // Reproduce correct handshake layer length
                term_to_mutate
                    .payloads
                    .as_mut()
                    .unwrap()
                    .payload
                    .bytes_mut()[7] = 2;
                term_to_mutate
                    .payloads
                    .as_mut()
                    .unwrap()
                    .payload
                    .bytes_mut()[8] = 194;

                // Reproduce correct Payloadu16 layer length (just before the actual payload (42
                // times `700`) Note that for other cases like heartbleed, we
                // specifically want to be able to lie about the length!
                term_to_mutate
                    .payloads
                    .as_mut()
                    .unwrap()
                    .payload
                    .bytes_mut()[13] = 2;
                term_to_mutate
                    .payloads
                    .as_mut()
                    .unwrap()
                    .payload
                    .bytes_mut()[14] = 188;
                // term_to_mutate.payloads.as_mut().unwrap().payload.bytes_mut()[2] = 1;
                // term_to_mutate.payloads.as_mut().unwrap().payload.bytes_mut()[4] = 189;
                // term_to_mutate.payloads.as_mut().unwrap().payload.bytes_mut().append(&mut vec![1,

                // Conclusion: RUST_LOG=debug cargo test -p tlspuffin --features=wolfssl530
                // test_seed_through_bit_mutations_cve_2022_38153 will crash.
                // Note that the trace gets rejected without the correct length since wolfssl Checks
                // the length consistency with the size of the remaining buffer.
                // 1, 1, 1, 1, 1]);
                // ---------- END Test to reproduce the bug by
                // cheating with the record layer length information ----------- //

                // Removed the ForkedRunner to get the logging messages!
                // Execute and expect a crash at some point
                log::warn!("[EXECUTE] Try mutant_tries: {mutant_tries} / all_tries: {all_tries}");
                // let mut mutant = seed_cve_2022_38153.build_trace();
                runner
                    .execute(&mutant)
                    // .inspect(|status| {
                    //     use ExecutionStatus as S;
                    //     match &status {
                    //         S::Crashed => {
                    //             log::warn!("{mutant_tries}/{all_tries} trace execution crashed");
                    //             log::error!("expected trace execution to crash (retried {mutant_tries}/{all_tries} times)");
                    //             log::error!("Payloads are: {:?}", mutant.all_payloads());
                    //             panic!("SUCCESS");
                    //             return ();
                    //         }
                    //         S::Failure(_) => {
                    //             log::warn!("{mutant_tries}/{all_tries} invalid trace... skipping");
                    //             skip = true;
                    //         },
                    //
                    //         S::Timeout => log::warn!("{mutant_tries}/{all_tries} trace execution timed out"),
                    //         S::Interrupted => {
                    //             log::warn!("{mutant_tries}/{all_tries} trace execution interrupted, skipping...");
                    //             skip = true;
                    //         },
                    //         S::Success => {
                    //             log::warn!("{mutant_tries}/{all_tries} success")
                    //         }
                    //     };
                    // })
                    .expect("Could not fork_runner {mutant_tries}/{all_tries}");
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
fn test_seed_cve_2022_38153tcp_wolfssl_openssl_test_seed_cve_2022_38153() {
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

    let mut context = runner.execute(trace).unwrap();

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
    let runner = default_runner_for(PutDescriptor::new(TCP_PUT, guard.build_options()));
    let server = trace.descriptors[0].name;

    let mut context = runner.execute(trace).unwrap();

    let shutdown = context.find_agent_mut(server).unwrap().shutdown();
    log::info!("{}", shutdown);
}
