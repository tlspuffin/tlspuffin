use crate::put_registry::TLS_PUT_REGISTRY;

mod mutations;
mod term_zoo;
mod terms;

#[test]
fn version_test() {
    let version = TLS_PUT_REGISTRY.default_factory().version();
    println!("{}", version);
    #[cfg(feature = "openssl101f")]
    assert!(version.contains("1.0.1f"));
    #[cfg(feature = "openssl102f")]
    assert!(version.contains("1.0.1u"));
    #[cfg(feature = "openssl111")]
    assert!(version.contains("1.1.1k"));
    #[cfg(feature = "openssl111j")]
    assert!(version.contains("1.1.1j"));
    #[cfg(feature = "openssl111u")]
    assert!(version.contains("1.1.1u"));
    #[cfg(feature = "openssl312")]
    assert!(version.contains("3.1.2"));

    #[cfg(feature = "wolfssl510")]
    assert!(version.contains("5.1.0"));
    #[cfg(feature = "wolfssl520")]
    assert!(version.contains("5.2.0"));
    #[cfg(feature = "wolfssl530")]
    assert!(version.contains("5.3.0"));
    #[cfg(feature = "wolfssl540")]
    assert!(version.contains("5.4.0"));
    #[cfg(feature = "wolfssl550")]
    assert!(version.contains("5.5.0"));
}
