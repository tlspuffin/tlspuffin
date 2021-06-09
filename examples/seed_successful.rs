use tlspuffin::{agent::AgentName, fuzzer::seeds::seed_successful, trace::TraceContext};

fn main() {
    let mut ctx = TraceContext::new();
    let client = AgentName::first();
    let server = client.next();
    let trace = seed_successful(client, server);

    trace.spawn_agents(&mut ctx).unwrap();
    trace.execute(&mut ctx).unwrap();
}
