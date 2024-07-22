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

    let default = {
        cfg_if::cfg_if! {
            if #[cfg(feature = "openssl-binding")] {
                OPENSSL_RUST_PUT
            } else if #[cfg(feature = "wolfssl-binding")] {
                WOLFSSL_RUST_PUT
            } else if #[cfg(feature = "boringssl-binding")] {
                BORINGSSL_RUST_PUT
            } else {
                puffin::put_registry::TCP_PUT
            }
        }
    };

    PutRegistry::new(
        [
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
        ],
        default,
    )
}
