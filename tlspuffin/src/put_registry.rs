use puffin::put_registry::PutRegistry;

use crate::protocol::TLSProtocolBehavior;

pub mod bindings {
    #![allow(non_snake_case)]
    #![allow(non_camel_case_types)]
    #![allow(non_upper_case_globals)]
    use security_claims::Claim;

    include!(env!("RUST_BINDINGS_FILE"));
}

pub mod registration {
    use std::sync::Mutex;

    use once_cell::sync::Lazy;
    use puffin::put_registry::Factory;

    use crate::protocol::TLSProtocolBehavior;

    pub fn all() -> Vec<Box<dyn Factory<TLSProtocolBehavior>>> {
        PUTS.lock()
            .unwrap()
            .iter()
            .map(|p| match p {
                #[cfg(feature = "rust-put")]
                GlobalFactory::RustFactory(f) => (*f).clone_factory(),
                GlobalFactory::CFactory(f) => (*f).clone_factory(),
            })
            .collect()
    }

    #[allow(unused)]
    macro_rules! registration_rust {
        (
            $id:ident, $name:expr, $harness_version:expr, $library_version:expr, $capabilities:expr
        ) => {
            mod $id {
                use super::GlobalFactory;
                use crate::rust_put::RustFactory;

                pub fn register() -> Option<GlobalFactory> {
                    crate::rust_put::rand::rng_init();
                    crate::rust_put::rand::rng_reseed();

                    Some(GlobalFactory::RustFactory(RustFactory::new(
                        $name,
                        $harness_version,
                        $library_version,
                    )))
                }
            }
        };
    }

    #[allow(unused)]
    macro_rules! registration_c {
        (
            $id:ident, $name:expr, $harness_version:expr, $library_version:expr, $capabilities:expr
        ) => {
            mod $id {
                use super::GlobalFactory;
                use crate::put_registry::bindings::TLS_PUT_INTERFACE;

                pub fn register() -> Option<GlobalFactory> {
                    let interface_ptr = unsafe { $id() };
                    if interface_ptr.is_null() {
                        log::error!("PUT registration failed: {} interface is NULL", &$name);
                        return None;
                    }

                    let interface = unsafe { *interface_ptr.clone() };

                    Some(GlobalFactory::CFactory(crate::put::CPut::new(
                        $name,
                        $harness_version,
                        $library_version,
                        $capabilities,
                        interface,
                    )))
                }

                extern "C" {
                    fn $id() -> *const TLS_PUT_INTERFACE;
                }
            }
        };
    }

    // TODO: remove this enum once Rust PUTs have been removed
    enum GlobalFactory {
        #[cfg(feature = "rust-put")]
        RustFactory(crate::rust_put::RustFactory),
        #[allow(dead_code)]
        CFactory(crate::put::CPut),
    }

    static PUTS: Lazy<Mutex<Vec<GlobalFactory>>> = Lazy::new(|| Mutex::new(register()));

    include!(env!("RUST_PUTS_BUNDLE_FILE"));
}

pub use registration::for_puts;

pub fn tls_registry() -> PutRegistry<TLSProtocolBehavior> {
    let puts: Vec<_> = registration::all()
        .into_iter()
        .chain(std::iter::once(crate::tcp::new_tcp_factory()))
        .map(|f| (f.name(), f))
        .collect();

    let default = puts.first().unwrap().0.clone();

    PutRegistry::new(puts, default)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test_log::test]
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
}
