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
            .map(|p| match p {
                GlobalFactory::CFactory(f) => f.clone_factory(),
            })
            .collect()
    }

    /// Registration macro for C harnesses compiled by puffin-build.
    #[allow(unused)]
    macro_rules! registration_c {
        (
            $id:ident, $name:expr, $harness_version:expr, $library_version:expr, $capabilities:expr
        ) => {
            mod $id {
                use super::GlobalFactory;
                use crate::put_registry::bindings::SSH_PUT_INTERFACE;

                pub fn register() -> Option<GlobalFactory> {
                    let interface_ptr = unsafe { $id() };
                    if interface_ptr.is_null() {
                        log::error!("SSH PUT registration failed: {} interface is NULL", &$name);
                        return None;
                    }

                    let interface = unsafe { *interface_ptr };

                    Some(GlobalFactory::CFactory(crate::libssh::CSshPut::new(
                        $name,
                        $harness_version,
                        $library_version,
                        $capabilities,
                        interface,
                    )))
                }

                extern "C" {
                    fn $id() -> *const SSH_PUT_INTERFACE;
                }
            }
        };
    }

    // Unsupported macro – SSH has no Rust PUT variant yet.
    #[allow(unused)]
    macro_rules! registration_rust {
        ($id:ident, $name:expr, $harness_version:expr, $library_version:expr, $capabilities:expr) => {
            compile_error!("Rust PUT not supported for SSH")
        };
    }

    enum GlobalFactory {
        #[allow(dead_code)]
        CFactory(crate::libssh::CSshPut),
    }

    static PUTS: Lazy<Mutex<Vec<GlobalFactory>>> = Lazy::new(|| Mutex::new(register()));

    include!(env!("RUST_PUTS_BUNDLE_FILE"));
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
             `just mk-vendor libssh0104` (or use the -asan variant)."
        );
    }

    let default_name = puts.first().unwrap().0.clone();
    PutRegistry::new(puts, PutDescriptor::new(default_name, PutOptions::empty()))
}
