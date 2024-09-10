use crate::agent::AgentName;
use crate::algebra::Matcher;
use crate::trace::Trace;

pub trait TraceHelper<A, M>
where
    M: Matcher,
{
    fn build_named_trace(self) -> (&'static str, Trace<M>);
    fn build_trace(self) -> Trace<M>;
    fn fn_name(&self) -> &'static str;
}

impl<M, F> TraceHelper<(AgentName, AgentName), M> for F
where
    F: Fn(AgentName, AgentName) -> Trace<M>,
    M: Matcher,
{
    fn build_named_trace(self) -> (&'static str, Trace<M>) {
        (self.fn_name(), self.build_trace())
    }

    fn build_trace(self) -> Trace<M> {
        let agent_a = AgentName::first();
        let agent_b = agent_a.next();
        (self)(agent_a, agent_b)
    }

    fn fn_name(&self) -> &'static str {
        std::any::type_name::<F>()
    }
}

impl<M, F> TraceHelper<AgentName, M> for F
where
    F: Fn(AgentName) -> Trace<M>,
    M: Matcher,
{
    fn build_named_trace(self) -> (&'static str, Trace<M>) {
        (self.fn_name(), self.build_trace())
    }

    fn build_trace(self) -> Trace<M> {
        let agent_a = AgentName::first();

        (self)(agent_a)
    }

    fn fn_name(&self) -> &'static str {
        std::any::type_name::<F>()
    }
}
