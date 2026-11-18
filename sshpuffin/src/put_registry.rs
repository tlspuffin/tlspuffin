use puffin::put::{PutDescriptor, PutOptions};
use puffin::put_registry::{Factory, PutRegistry};

use crate::protocol::SshProtocolBehavior;

/// The PUTs of sshpuffin: none yet. The C harnesses of the SSH libraries register theirs here.
pub fn ssh_registry() -> PutRegistry<SshProtocolBehavior> {
    let puts: Vec<(String, Box<dyn Factory<SshProtocolBehavior>>)> = vec![];
    PutRegistry::new(puts, PutDescriptor::new("none", PutOptions::empty()))
}
