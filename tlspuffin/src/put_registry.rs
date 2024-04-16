use puffin::{put::PutName, put_registry::PutRegistry};
use tls_harness::{CPutHarness, CPutLibrary, C_PUT_TYPE};

use crate::protocol::TLSProtocolBehavior;

pub const OPENSSL111_PUT: PutName = PutName(['O', 'P', 'E', 'N', 'S', 'S', 'L', '1', '1', '1']);
pub const WOLFSSL520_PUT: PutName = PutName(['W', 'O', 'L', 'F', 'S', 'S', 'L', '5', '2', '0']);
pub const BORINGSSL_PUT: PutName = PutName(['B', 'O', 'R', 'I', 'N', 'G', 'S', 'S', 'L', '_']);
pub const TCP_PUT: PutName = PutName(['T', 'C', 'P', '_', '_', '_', '_', '_', '_', '_']);
pub const TLS_C_PUT: PutName = PutName(['T', 'L', 'S', '_', 'C', '_', 'P', 'U', 'T', 'S']);

pub fn tls_registry() -> PutRegistry<TLSProtocolBehavior> {
    let mut puts = vec![
        (String::from("rust-tcp"), crate::tcp::new_tcp_factory()),
        #[cfg(feature = "openssl-binding")]
        (
            String::from("rust-openssl"),
            crate::openssl::new_openssl_factory(),
        ),
        #[cfg(feature = "wolfssl-binding")]
        (
            String::from("rust-wolfssl"),
            crate::wolfssl::new_wolfssl_factory(),
        ),
        #[cfg(feature = "boringssl-binding")]
        (
            String::from("rust-boringssl"),
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
                "rust-openssl"
            } else if #[cfg(feature = "wolfssl-binding")] {
                "rust-wolfssl"
            } else if #[cfg(feature = "boringssl-binding")] {
                "rust-boringssl"
            } else {
                "rust-tcp"
            }
        }
    };

    PutRegistry::new(puts, default)
}
