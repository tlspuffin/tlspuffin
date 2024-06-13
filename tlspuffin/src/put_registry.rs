use puffin::put_registry::{PutRegistry, TCP_PUT};
use tls_harness::{CPutHarness, CPutLibrary, C_PUT_TYPE};

use crate::protocol::TLSProtocolBehavior;

pub const OPENSSL_RUST_PUT: &str = "rust-put-openssl";
pub const WOLFSSL_RUST_PUT: &str = "rust-put-wolfssl";
pub const BORINGSSL_RUST_PUT: &str = "rust-put-boringssl";

pub fn tls_registry() -> PutRegistry<TLSProtocolBehavior> {
    let mut puts = vec![
        #[cfg(feature = "openssl-binding")]
        {
            let put = crate::openssl::new_openssl_factory();
            (put.name(), put)
        },
        #[cfg(feature = "wolfssl-binding")]
        {
            let put = crate::wolfssl::new_wolfssl_factory();
            (put.name(), put)
        },
        #[cfg(feature = "boringssl-binding")]
        {
            let put = crate::boringssl::new_boringssl_factory();
            (put.name(), put)
        },
        {
            let put = crate::tcp::new_tcp_factory();
            (put.name(), put)
        },
    ];

    if cfg!(feature = "cputs") {
        tls_harness::register(
            |harness: CPutHarness, library: CPutLibrary, interface: *const C_PUT_TYPE| {
                if interface.is_null() {
                    log::error!("C PUT registration failed: pointer to PUT struct is NULL");
                }

                let put = crate::cput::new_factory(harness, library, unsafe { &*interface });

                puts.push((put.name(), put));
            },
        );
    }

    let default = {
        cfg_if::cfg_if! {
            if #[cfg(feature = "openssl-binding")] {
                OPENSSL_RUST_PUT
            } else if #[cfg(feature = "wolfssl-binding")] {
                WOLFSSL_RUST_PUT
            } else if #[cfg(feature = "boringssl-binding")] {
                BORINGSSL_RUST_PUT
            } else {
                TCP_PUT
            }
        }
    };

    PutRegistry::new(puts, default)
}
