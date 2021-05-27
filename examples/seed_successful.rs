use tlspuffin::{fuzzer::seeds::seed_successful, trace::TraceContext, agent::AgentName};

fn main() {
    let mut ctx = TraceContext::new();
    let client = AgentName::first();
    let server = client.next();
    let trace = seed_successful(client, server);

    trace.spawn_agents(&mut ctx);
    trace.execute(&mut ctx);
}
