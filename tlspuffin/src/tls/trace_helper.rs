use puffin::{
    agent::AgentName,
    put_registry::PutDescriptor,
    trace::{Trace, TraceContext, TraceExecutor},
};

use crate::{protocol::TLSProtocolBehavior, put_registry::tls_registry, query::TlsQueryMatcher};

pub trait TraceHelper<A>: TraceHelperExecutor<A> {
    fn build_named_trace(self) -> (&'static str, Trace<TlsQueryMatcher>);
    fn build_trace(self) -> Trace<TlsQueryMatcher>;
    fn fn_name(&self) -> &'static str;
}

pub trait TraceHelperExecutor<A> {
    fn execute_trace(self) -> TraceContext<TLSProtocolBehavior>;
    fn execute_with<S: AsRef<str> + ?Sized>(self, put: &S) -> TraceContext<TLSProtocolBehavior>;
}

impl<A, H: TraceHelper<A>> TraceHelperExecutor<A> for H {
    fn execute_trace(self) -> TraceContext<TLSProtocolBehavior> {
        self.execute_with(&tls_registry().default().name())
    }

    fn execute_with<S: AsRef<str> + ?Sized>(self, put: &S) -> TraceContext<TLSProtocolBehavior> {
        let put_registry = tls_registry();
        let put = PutDescriptor {
            factory: put.as_ref().to_owned(),
            options: Default::default(),
        };
        let mut context = TraceContext::builder(&put_registry)
            .set_default_put(put)
            .build();

        context.execute(&self.build_trace()).unwrap();
        context
    }
}

impl<F> TraceHelper<(AgentName, AgentName)> for F
where
    F: Fn(AgentName, AgentName) -> Trace<TlsQueryMatcher>,
{
    fn build_named_trace(self) -> (&'static str, Trace<TlsQueryMatcher>) {
        (self.fn_name(), self.build_trace())
    }

    fn build_trace(self) -> Trace<TlsQueryMatcher> {
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
    F: Fn(AgentName) -> Trace<TlsQueryMatcher>,
{
    fn build_named_trace(self) -> (&'static str, Trace<TlsQueryMatcher>) {
        (self.fn_name(), self.build_trace())
    }

    fn build_trace(self) -> Trace<TlsQueryMatcher> {
        let agent_a = AgentName::first();

        (self)(agent_a)
    }

    fn fn_name(&self) -> &'static str {
        std::any::type_name::<F>()
    }
}
