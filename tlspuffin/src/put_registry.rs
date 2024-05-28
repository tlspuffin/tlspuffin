use puffin::put_registry::{PutRegistry, TCP_PUT};
use tls_harness::{CPutHarness, CPutLibrary, C_PUT_TYPE};

use crate::protocol::TLSProtocolBehavior;

pub const OPENSSL_RUST_PUT: &str = "rust-put-openssl";
pub const WOLFSSL_RUST_PUT: &str = "rust-put-wolfssl";
pub const BORINGSSL_RUST_PUT: &str = "rust-put-boringssl";

pub fn tls_registry() -> PutRegistry<TLSProtocolBehavior> {
    let mut puts = vec![
        (TCP_PUT.to_owned(), crate::tcp::new_tcp_factory()),
        #[cfg(feature = "openssl-binding")]
        (
            OPENSSL_RUST_PUT.to_owned(),
            crate::openssl::new_openssl_factory(),
        ),
        #[cfg(feature = "wolfssl-binding")]
        (
            WOLFSSL_RUST_PUT.to_owned(),
            crate::wolfssl::new_wolfssl_factory(),
        ),
        #[cfg(feature = "boringssl-binding")]
        (
            BORINGSSL_RUST_PUT.to_owned(),
            crate::boringssl::new_boringssl_factory(),
        ),
    ];

    if cfg!(feature = "cputs") {
        tls_harness::register(
            |harness: CPutHarness, library: CPutLibrary, interface: *const C_PUT_TYPE| {
                if interface.is_null() {
                    log::error!("C PUT registration failed: pointer to PUT struct is NULL");
                }

                puts.push((
                    library.config_name.to_string(),
                    crate::cput::new_factory(harness, library, unsafe { &*interface }),
                ));
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
