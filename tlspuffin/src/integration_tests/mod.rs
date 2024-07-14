#[cfg(feature = "deterministic")]
mod determinism;
mod mutations;
mod term_zoo;

use test_log::test;

#[test]
fn version_test() {
    let registry = crate::put_registry::tls_registry();
    let put = registry.default().name();
    let versions = registry.find_by_id(&put).unwrap().versions();

    println!("TLS PUT components:");
    for (component, version) in versions.iter() {
        println!("    {}: {}", component, version);
    }

    let version = versions
        .iter()
        .find(|(c, _)| c == "library")
        .map(|(_, v)| v)
        .expect("missing version string");

    match put.as_str() {
        "openssl101f" => assert!(version.contains("1.0.1f")),
        "openssl102u" => assert!(version.contains("1.0.2u")),
        "openssl111j" => assert!(version.contains("1.1.1j")),
        "openssl111k" => assert!(version.contains("1.1.1k")),
        "openssl111u" => assert!(version.contains("1.1.1u")),
        "openssl312" => assert!(version.contains("3.1.2")),
        "wolfssl430" => assert!(version.contains("4.3.0")),
        "wolfssl510" => assert!(version.contains("5.1.0")),
        "wolfssl520" => assert!(version.contains("5.2.0")),
        "wolfssl530" => assert!(version.contains("5.3.0")),
        "wolfssl540" => assert!(version.contains("5.4.0")),
        _ => (),
    };
}
