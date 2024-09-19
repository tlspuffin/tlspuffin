use puffin::put_registry::PutRegistry;
#[cfg(feature = "cputs")]
use tls_harness::C_PUT_TYPE;

use crate::protocol::TLSProtocolBehavior;

pub const OPENSSL_RUST_PUT: &str = "rust-put-openssl";
pub const WOLFSSL_RUST_PUT: &str = "rust-put-wolfssl";
pub const BORINGSSL_RUST_PUT: &str = "rust-put-boringssl";

pub fn tls_registry() -> PutRegistry<TLSProtocolBehavior> {
    #[cfg(feature = "cputs")]
    extern "C" fn callback(put: *const C_PUT_TYPE) {
        if put.is_null() {
            return;
        }

        println!("registering C put")
    }

    #[cfg(feature = "cputs")]
    tls_harness::register(callback);

    let name = {
        cfg_if::cfg_if! {
            if #[cfg(feature = "openssl-binding")] {
                if cfg!(feature = "openssl101f") {
                    "openssl101f"
                } else if cfg!(feature = "openssl102u") {
                    "openssl102u"
                } else if cfg!(feature = "openssl111k") {
                    "openssl111k"
                } else if cfg!(feature = "openssl111j") {
                    "openssl111j"
                } else if cfg!(feature = "openssl111u") {
                    "openssl111u"
                } else if cfg!(feature = "openssl312") {
                    "openssl312"
                } else if cfg!(feature = "libressl333") {
                    "libressl333"
                } else {
                    "openssl-unknown"
                }
            } else if #[cfg(feature = "wolfssl-binding")] {
                if cfg!(feature = "wolfssl540") {
                    "wolfssl540"
                } else if cfg!(feature = "wolfssl530") {
                    "wolfssl530"
                } else if cfg!(feature = "wolfssl520") {
                    "wolfssl520"
                } else if cfg!(feature = "wolfssl510") {
                    "wolfssl510"
                } else if cfg!(feature = "wolfssl430") {
                    "wolfssl430"
                } else if cfg!(feature = "wolfsslmaster") {
                    "wolfssl-master"
                } else {
                    "wolfssl-unknown"
                }
            } else if #[cfg(feature = "boringssl-binding")] {
                if cfg!(feature = "boringssl202311") {
                    "boringssl202311"
                } else if cfg!(feature = "boringssl202403") {
                    "boringssl202403"
                } else if cfg!(feature = "boringsslmaster") {
                    "master"
                } else {
                    "unknown"
                }
            } else {
                puffin::put_registry::TCP_PUT
            }
        }
    };

    PutRegistry::new(
        [
            #[cfg(feature = "openssl-binding")]
            {
                let put = crate::openssl::new_factory(name);
                (put.name(), put)
            },
            #[cfg(feature = "wolfssl-binding")]
            {
                let put = crate::wolfssl::new_factory(name);
                (put.name(), put)
            },
            #[cfg(feature = "boringssl-binding")]
            {
                let put = crate::boringssl::new_factory(name);
                (put.name(), put)
            },
            {
                let put = crate::tcp::new_tcp_factory();
                (put.name(), put)
            },
        ],
        name,
    )
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
