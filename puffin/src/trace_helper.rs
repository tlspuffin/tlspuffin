use crate::agent::AgentName;
use crate::protocol::ProtocolTypes;
use crate::trace::Trace;

pub trait TraceHelper<A, PT>
where
    PT: ProtocolTypes,
{
    fn build_named_trace(self) -> (&'static str, Trace<PT>);
    fn build_trace(self) -> Trace<PT>;
    fn fn_name(&self) -> &'static str;
}

impl<PT, F> TraceHelper<(AgentName, AgentName), PT> for F
where
    F: Fn(AgentName, AgentName) -> Trace<PT>,
    PT: ProtocolTypes,
{
    fn build_named_trace(self) -> (&'static str, Trace<PT>) {
        (self.fn_name(), self.build_trace())
    }

    fn build_trace(self) -> Trace<PT> {
        let agent_a = AgentName::first();
        let agent_b = agent_a.next();
        (self)(agent_a, agent_b)
    }

    fn fn_name(&self) -> &'static str {
        std::any::type_name::<F>()
    }
}

impl<PT, F> TraceHelper<AgentName, PT> for F
where
    F: Fn(AgentName) -> Trace<PT>,
    PT: ProtocolTypes,
{
    fn build_named_trace(self) -> (&'static str, Trace<PT>) {
        (self.fn_name(), self.build_trace())
    }

    fn build_trace(self) -> Trace<PT> {
        let agent_a = AgentName::first();

        (self)(agent_a)
    }

    fn fn_name(&self) -> &'static str {
        std::any::type_name::<F>()
    }
}

/// Builds a seed corpus as a `Vec<(Trace, &'static str)>` from a list of
/// `seed_fn: condition` pairs. Each seed function must implement
/// [`TraceHelper`] (blanket-implemented for the
/// usual `Fn(AgentName) -> Trace` / `Fn(AgentName, AgentName) -> Trace` seed
/// signatures). A seed is included only when its condition evaluates to `true`,
/// which lets callers gate seeds on PUT capabilities. Protocol-agnostic — usable
/// from any crate as `puffin::corpus!`.
#[macro_export]
macro_rules! corpus {
    () => {
        vec![]
    };

    ( $( $func:ident : $cond:expr ),* $(,)? ) => {
        {
            use $crate::trace_helper::TraceHelper;
            let mut corpus = vec![];

            $(
                if $cond {
                    corpus.push(($func.build_trace(), $func.fn_name()));
                }
            )*

            corpus
        }
    };
}
