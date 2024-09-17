use std::fs::File;

use puffin::{
    agent::AgentName,
    libafl::inputs::Input,
    put::PutOptions,
    trace::{Trace, TraceContext},
};

use crate::{
    protocol::{TLSProtocolBehavior, TLSProtocolTypes},
    put_registry::tls_registry,
};

pub trait TraceHelper<A>: TraceExecutor<A> {
    fn build_named_trace(self) -> (&'static str, Trace<TLSProtocolTypes>);
    fn build_trace(self) -> Trace<TLSProtocolTypes>;
    fn fn_name(&self) -> &'static str;
}

pub trait TraceExecutor<A> {
    fn execute_trace(self) -> TraceContext<TLSProtocolBehavior>;
    fn store_to_seeds(self);
}

impl<A, H: TraceHelper<A>> TraceExecutor<A> for H {
    fn execute_trace(self) -> TraceContext<TLSProtocolBehavior> {
        self.build_trace()
            .execute_deterministic(&tls_registry(), PutOptions::default())
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

impl<F> TraceHelper<(AgentName, AgentName)> for F
where
    F: Fn(AgentName, AgentName) -> Trace<TLSProtocolTypes>,
{
    fn build_named_trace(self) -> (&'static str, Trace<TLSProtocolTypes>) {
        (self.fn_name(), self.build_trace())
    }

    fn build_trace(self) -> Trace<TLSProtocolTypes> {
        let agent_a = AgentName::first();
        let agent_b = agent_a.next();
        (self)(agent_a, agent_b)
    }

    fn fn_name(&self) -> &'static str {
        std::any::type_name::<F>()
    }
}

impl<F> TraceHelper<AgentName> for F
where
    F: Fn(AgentName) -> Trace<TLSProtocolTypes>,
{
    fn build_named_trace(self) -> (&'static str, Trace<TLSProtocolTypes>) {
        (self.fn_name(), self.build_trace())
    }

    fn build_trace(self) -> Trace<TLSProtocolTypes> {
        let agent_a = AgentName::first();

        (self)(agent_a)
    }

    fn fn_name(&self) -> &'static str {
        std::any::type_name::<F>()
    }
}
