use puffin::put::{PutDescriptor, PutOptions};
use puffin::put_registry::PutRegistry;

use crate::protocol::SshProtocolBehavior;

// Rust FFI bindings generated from sshpuffin/include/puffin/ssh.h
pub mod bindings {
    #![allow(non_snake_case)]
    #![allow(non_camel_case_types)]
    #![allow(non_upper_case_globals)]

    include!(env!("RUST_BINDINGS_FILE"));
}

pub mod registration {
    use std::sync::Mutex;

    use once_cell::sync::Lazy;
    use puffin::put_registry::Factory;

    use crate::protocol::SshProtocolBehavior;

    pub fn all() -> Vec<Box<dyn Factory<SshProtocolBehavior>>> {
        PUTS.lock()
            .unwrap()
            .iter()
            .map(|p| p.clone_factory())
            .collect()
    }

    /// Registration macro for C harnesses compiled by puffin-build.
    #[allow(unused)]
    macro_rules! registration_c {
        (
            $id:ident, $name:expr, $harness_version:expr, $library_version:expr, $capabilities:expr
        ) => {
            // PUT ids keep the case of their name (derived names, as in tlspuffin)
            #[allow(non_snake_case)]
            mod $id {
                use crate::put::CPut;
                use crate::put_registry::bindings::SSH_PUT_INTERFACE;

                pub fn register() -> Option<CPut> {
                    let interface_ptr = unsafe { $id() };
                    if interface_ptr.is_null() {
                        log::error!("SSH PUT registration failed: {} interface is NULL", &$name);
                        return None;
                    }

                    let interface = unsafe { *interface_ptr };

                    Some(CPut::new(
                        $name,
                        $harness_version,
                        $library_version,
                        $capabilities,
                        interface,
                    ))
                }

                extern "C" {
                    fn $id() -> *const SSH_PUT_INTERFACE;
                }
            }
        };
    }

    static PUTS: Lazy<Mutex<Vec<crate::put::CPut>>> = Lazy::new(|| Mutex::new(register()));

    include!(env!("RUST_PUTS_BUNDLE_FILE"));
}

pub use registration::{catalogue_states, for_puts};

/// The names of the PUTs of `vendor` (`"libssh"`, `"wolfssh"`) in this binary, in registration
/// (name) order: the PUTs whose library version, `"<vendor> <version>"`, is of that vendor.
pub fn put_names(vendor: &str) -> Vec<String> {
    registration::all()
        .into_iter()
        .filter(|put| {
            put.versions().iter().any(|(component, version)| {
                component == "library" && version.split(' ').next() == Some(vendor)
            })
        })
        .map(|put| put.name())
        .collect()
}

pub fn ssh_registry() -> PutRegistry<SshProtocolBehavior> {
    let puts: Vec<_> = registration::all()
        .into_iter()
        .map(|f| (f.name(), f))
        .collect();

    if puts.is_empty() {
        panic!(
            "No SSH PUT found. \
             Build libssh into the vendor directory first: \
             `just mk_vendor libssh libssh0114` (or use the -asan variant)."
        );
    }

    let default_name = puts.first().unwrap().0.clone();
    PutRegistry::new(puts, PutDescriptor::new(default_name, PutOptions::empty()))
}
