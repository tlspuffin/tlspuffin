use puffin::put::{PutDescriptor, PutOptions};
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
            .map(|p| p.clone_factory())
            .collect()
    }

    #[allow(unused)]
    macro_rules! registration_c {
        (
            $id:ident, $name:expr, $harness_version:expr, $library_version:expr, $capabilities:expr
        ) => {
            mod $id {
                use crate::put::CPut;
                use crate::put_registry::bindings::TLS_PUT_INTERFACE;

                pub fn register() -> Option<CPut> {
                    let interface_ptr = unsafe { $id() };
                    if interface_ptr.is_null() {
                        log::error!("PUT registration failed: {} interface is NULL", &$name);
                        return None;
                    }

                    let interface = unsafe { *interface_ptr.clone() };

                    Some(CPut::new(
                        $name,
                        $harness_version,
                        $library_version,
                        $capabilities,
                        interface,
                    ))
                }

                extern "C" {
                    fn $id() -> *const TLS_PUT_INTERFACE;
                }
            }
        };
    }

    static PUTS: Lazy<Mutex<Vec<crate::put::CPut>>> = Lazy::new(|| Mutex::new(register()));

    include!(env!("RUST_PUTS_BUNDLE_FILE"));
}

pub use registration::for_puts;

pub fn tls_registry() -> PutRegistry<TLSProtocolBehavior> {
    let puts: Vec<_> = registration::all()
        .into_iter()
        .chain(std::iter::once(crate::tcp::new_tcp_factory()))
        .map(|f| (f.name(), f))
        .collect();

    let default_name = puts.first().unwrap().0.clone();
    let default_descriptor = PutDescriptor::new(default_name, PutOptions::empty());
    PutRegistry::new(puts, default_descriptor)
}
