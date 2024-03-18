use puffin::{put::PutName, put_registry::PutRegistry};

use crate::protocol::SshProtocolBehavior;

pub const LIBSSH_PUT: PutName = PutName(['L', 'I', 'B', 'S', 'S', 'H', '_', '_', '_', '_']);

pub fn ssh_registry() -> PutRegistry<SshProtocolBehavior> {
    PutRegistry::new(
        vec![crate::libssh::new_libssh_factory()],
        crate::libssh::new_libssh_factory().id(),
    )
}
