use crate::put_registry::tls_registry;

#[cfg(feature = "deterministic")]
mod determinism;
mod mutations;
mod term_zoo;
mod terms;

#[test]
fn version_test() {
    let registry = tls_registry();
    let versions = registry.default().versions();

    println!("Default tls PUT components:");
    for (component, version) in versions.iter() {
        println!("    {}: {}", component, version);
    }

    #[allow(unused_variables)]
    let version = versions
        .iter()
        .find(|(c, _)| c == "library")
        .map(|(_, v)| v);

    #[cfg(feature = "openssl101f")]
    assert!(version.expect("missing version string").contains("1.0.1f"));
    #[cfg(feature = "openssl102u")]
    assert!(version.expect("missing version string").contains("1.0.2u"));
    #[cfg(feature = "openssl111k")]
    assert!(version.expect("missing version string").contains("1.1.1k"));
    #[cfg(feature = "openssl111j")]
    assert!(version.expect("missing version string").contains("1.1.1j"));
    #[cfg(feature = "openssl111u")]
    assert!(version.expect("missing version string").contains("1.1.1u"));
    #[cfg(feature = "openssl312")]
    assert!(version.expect("missing version string").contains("3.1.2"));

    #[cfg(feature = "wolfssl510")]
    assert!(version.expect("missing version string").contains("5.1.0"));
    #[cfg(feature = "wolfssl520")]
    assert!(version.expect("missing version string").contains("5.2.0"));
    #[cfg(feature = "wolfssl530")]
    assert!(version.expect("missing version string").contains("5.3.0"));
    #[cfg(feature = "wolfssl540")]
    assert!(version.expect("missing version string").contains("5.4.0"));
    #[cfg(feature = "wolfssl430")]
    assert!(version.expect("missing version string").contains("4.3.0"));
}
