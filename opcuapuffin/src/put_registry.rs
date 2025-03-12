use puffin::put_registry::PutRegistry;

use crate::protocol::OPCProtocolBehavior;

pub fn opc_registry() -> PutRegistry<OPCProtocolBehavior> {
    let puts: Vec<_> = registration::all()
        .into_iter()
        //.chain(std::iter::once(crate::tcp::new_tcp_factory()))
        .map(|f| (f.name(), f))
        .collect();

    let default = puts.first().unwrap().0.clone();

    PutRegistry::new(puts, default)
}