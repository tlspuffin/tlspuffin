use puffin::agent::TLSVersion;
use puffin::execution::Runner;
use puffin::put::PutDescriptor;
use puffin::put_registry::TCP_PUT;
use puffin::trace::Spawner;
#[allow(unused_imports)]
use tlspuffin::{test_utils::prelude::*, tls::seeds::*, tls::vulnerabilities::*};

// Vulnerable up until OpenSSL 1.0.1j
#[cfg(all(feature = "openssl101-binding", feature = "asan"))]
#[cfg(feature = "tls12")]
#[test_log::test]
#[ignore] // We cannot check for this vulnerability right now
fn test_seed_freak() {
    expect_trace_crash(
        seed_freak.build_trace(),
        default_runner_for(tls_registry().default().name()),
        std::time::Duration::from_secs(20),
        Some(20),
    );
}

#[cfg(all(feature = "openssl101-binding", feature = "asan"))]
#[cfg(feature = "tls12")]
#[test_log::test]
fn test_seed_heartbleed() {
    expect_trace_crash(
        seed_heartbleed.build_trace(),
        default_runner_for(tls_registry().default().name()),
        std::time::Duration::from_secs(20),
        Some(20),
    );
}

#[test_log::test]
#[cfg(feature = "openssl111j")]
#[cfg(feature = "tls12")]
fn test_seed_cve_2021_3449() {
    expect_trace_crash(
        seed_cve_2021_3449.build_trace(),
        default_runner_for(tls_registry().default().name()),
        std::time::Duration::from_secs(20),
        Some(20),
    );
}

#[test_log::test]
#[cfg(feature = "wolfssl510")]
#[cfg(feature = "tls13")] // require version which supports TLS 1.3
#[cfg(feature = "client-authentication-transcript-extraction")]
#[cfg(not(feature = "fix-CVE-2022-25640"))]
#[should_panic(expected = "Authentication bypass")]
fn test_seed_cve_2022_25640() {
    let runner = default_runner_for(tls_registry().default().name());
    let trace = seed_cve_2022_25640.build_trace();

    let ctx = runner.execute(trace).unwrap();

    assert!(ctx.agents_successful());
}

#[test_log::test]
#[cfg(feature = "wolfssl510")]
#[cfg(feature = "tls13")] // require version which supports TLS 1.3
#[cfg(feature = "client-authentication-transcript-extraction")]
#[cfg(not(feature = "fix-CVE-2022-25640"))]
#[should_panic(expected = "Authentication bypass")]
fn test_seed_cve_2022_25640_simple() {
    let runner = default_runner_for(tls_registry().default().name());
    let trace = seed_cve_2022_25640_simple.build_trace();

    let ctx = runner.execute(trace).unwrap();

    assert!(ctx.agents_successful());
}

#[test_log::test]
#[cfg(feature = "wolfssl510")]
#[cfg(feature = "tls13")] // require version which supports TLS 1.3
#[cfg(feature = "client-authentication-transcript-extraction")]
#[cfg(not(feature = "fix-CVE-2022-25638"))]
#[should_panic(expected = "Authentication bypass")]
fn test_seed_cve_2022_25638() {
    let runner = default_runner_for(tls_registry().default().name());
    let trace = seed_cve_2022_25638.build_trace();

    let ctx = runner.execute(trace).unwrap();

    assert!(ctx.agents_successful());
}

#[test_log::test]
#[cfg(feature = "tls12")]
#[cfg(feature = "wolfssl540")]
#[cfg(feature = "wolfssl-disable-postauth")]
fn test_seed_cve_2022_38152() {
    expect_trace_crash(
        seed_session_resumption_dhe_full.build_trace(),
        default_runner_for(puffin::put::PutDescriptor::new(
            tls_registry().default().name(),
            vec![("use_clear", "true")],
        )),
        std::time::Duration::from_secs(20),
        Some(20),
    );
}

#[test_log::test]
#[cfg(feature = "tls12")]
#[cfg(feature = "tls12-session-resumption")]
#[cfg(feature = "wolfssl530")]
fn test_seed_cve_2022_38153() {
    let runner = default_runner_for(tls_registry().default().name());
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

#[cfg(all(feature = "tls13", feature = "tls13-session-resumption"))]
#[cfg(all(
    any(feature = "wolfssl540", feature = "wolfssl530", feature = "wolfssl510"),
    feature = "asan"
))]
#[cfg(not(feature = "fix-CVE-2022-39173"))]
#[test_log::test]
fn test_seed_cve_2022_39173() {
    expect_trace_crash(
        seed_cve_2022_39173.build_trace(),
        default_runner_for(tls_registry().default().name()),
        std::time::Duration::from_secs(20),
        Some(20),
    );
}

#[cfg(all(feature = "tls13", feature = "tls13-session-resumption"))]
#[cfg(all(
    any(feature = "wolfssl540", feature = "wolfssl530", feature = "wolfssl510"),
    feature = "asan"
))]
#[cfg(not(feature = "fix-CVE-2022-39173"))]
#[test_log::test]
fn test_seed_cve_2022_39173_full() {
    expect_trace_crash(
        seed_cve_2022_39173_full.build_trace(),
        default_runner_for(tls_registry().default().name()),
        std::time::Duration::from_secs(20),
        Some(20),
    );
}

#[cfg(all(feature = "tls13", feature = "tls13-session-resumption"))]
#[cfg(all(
    any(feature = "wolfssl540", feature = "wolfssl530", feature = "wolfssl510"),
    feature = "asan"
))]
#[cfg(not(feature = "fix-CVE-2022-39173"))]
#[test_log::test]
fn test_seed_cve_2022_39173_minimized() {
    expect_trace_crash(
        seed_cve_2022_39173_minimized.build_trace(),
        default_runner_for(tls_registry().default().name()),
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
