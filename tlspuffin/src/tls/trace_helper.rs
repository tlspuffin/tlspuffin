use std::fs::File;

use puffin::libafl::inputs::Input;
use puffin::protocol::ProtocolBehavior;
use puffin::trace::TraceContext;
use puffin::trace_helper::TraceHelper;

use crate::protocol::TLSProtocolBehavior;
use crate::put_registry::tls_registry;

pub trait TraceExecutor<A> {
    fn execute_trace(self) -> TraceContext<TLSProtocolBehavior>;
    fn store_to_seeds(self);
}

impl<A, H: TraceHelper<A, <TLSProtocolBehavior as ProtocolBehavior>::Matcher>> TraceExecutor<A>
    for H
{
    fn execute_trace(self) -> TraceContext<TLSProtocolBehavior> {
        self.build_trace()
            .execute_deterministic(&tls_registry(), Default::default())
            .unwrap()
    }

    fn store_to_seeds(self) {
        let name = self.fn_name();
        let path = format!("../seeds/{}", name);
        std::fs::create_dir_all("../seeds").unwrap();
        File::create(&path).unwrap();
        self.build_trace().to_file(path).unwrap();
    }
}
