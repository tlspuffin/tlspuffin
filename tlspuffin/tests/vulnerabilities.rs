use puffin::execution::Runner;
use puffin::put::PutDescriptor;
use puffin::put_registry::TCP_PUT;
use puffin::trace::Spawner;
use tlspuffin::protocol::TLSVersion;
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

#[apply(test_puts, filter = all(CVE_2014_0160, tls12, asan))]
fn test_seed_heartbleed(put: &str) {
    expect_trace_crash(
        seed_heartbleed.build_trace(),
        default_runner_for(put),
        std::time::Duration::from_secs(20),
        Some(20),
    );
}

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

    let _ = runner.execute_config(trace.clone(), true, &mut 0).unwrap();
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
        let _ = runner.execute_config(trace.clone(), false, &mut 0).unwrap();
    }

    expect_trace_crash(
        seed_cve_2022_38153.build_trace(),
        runner,
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
    let runner = default_runner_for(PutDescriptor::new(TCP_PUT, guard.build_options()));
    let server = trace.descriptors[0].name;

    let mut context = runner.execute(trace, &mut 0).unwrap();

    let shutdown = context.find_agent_mut(server).unwrap().shutdown();
    log::info!("{}", shutdown);
}
