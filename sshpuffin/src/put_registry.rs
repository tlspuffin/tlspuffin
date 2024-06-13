use puffin::put_registry::PutRegistry;

use crate::protocol::SshProtocolBehavior;

pub const LIBSSH_RUST_PUT: &str = "rust-put-libssh";

pub fn ssh_registry() -> PutRegistry<SshProtocolBehavior> {
    PutRegistry::new([(LIBSSH_RUST_PUT, crate::libssh::new_libssh_factory())])
}
