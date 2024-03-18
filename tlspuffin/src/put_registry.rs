use puffin::{
    put::PutName,
    put_registry::{PutId, PutRegistry},
};

use crate::protocol::TLSProtocolBehavior;

#[cfg(feature = "cputs")]
use tls_harness::C_PUT_TYPE;

pub const OPENSSL111_PUT: PutName = PutName(['O', 'P', 'E', 'N', 'S', 'S', 'L', '1', '1', '1']);
pub const WOLFSSL520_PUT: PutName = PutName(['W', 'O', 'L', 'F', 'S', 'S', 'L', '5', '2', '0']);
pub const BORINGSSL_PUT: PutName = PutName(['B', 'O', 'R', 'I', 'N', 'G', 'S', 'S', 'L', '_']);
pub const TCP_PUT: PutName = PutName(['T', 'C', 'P', '_', '_', '_', '_', '_', '_', '_']);

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

    let default: PutId = {
        cfg_if::cfg_if! {
            if #[cfg(feature = "openssl-binding")] {
                crate::openssl::new_openssl_factory().id()
            } else if #[cfg(feature = "wolfssl-binding")] {
                crate::wolfssl::new_wolfssl_factory().id()
            } else if #[cfg(feature = "boringssl-binding")] {
                crate::boringssl::new_boringssl_factory().id()
            } else {
                crate::tcp::new_tcp_factory().id()
            }
        }
    };

    PutRegistry::new(
        vec![
            crate::tcp::new_tcp_factory(),
            #[cfg(feature = "openssl-binding")]
            crate::openssl::new_openssl_factory(),
            #[cfg(feature = "wolfssl-binding")]
            crate::wolfssl::new_wolfssl_factory(),
            #[cfg(feature = "boringssl-binding")]
            crate::boringssl::new_boringssl_factory(),
        ],
        default,
    )
}
