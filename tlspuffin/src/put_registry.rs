use puffin::put_registry::PutRegistry;

use crate::protocol::TLSProtocolBehavior;

pub const OPENSSL_RUST_PUT: &str = "rust-put-openssl";
pub const WOLFSSL_RUST_PUT: &str = "rust-put-wolfssl";
pub const BORINGSSL_RUST_PUT: &str = "rust-put-boringssl";

pub mod macros {
    include!(env!("TLSPUFFIN_MACROS_RS"));
}

pub fn tls_registry() -> PutRegistry<TLSProtocolBehavior> {
    PutRegistry::new(
        tls_harness::tls_puts()
            .into_iter()
            .map(
                |(name, (harness, library, interface))| match harness.name.as_ref() {
                    tls_harness::RUST_PUT_HARNESS => crate::rust_put::new_factory(&name),
                    _ => crate::cput::new_factory(harness, library, interface),
                },
            )
            .chain([crate::tcp::new_tcp_factory()].into_iter()),
    )
}
