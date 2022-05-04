use tlspuffin::{
    agent::AgentName, fuzzer::seeds::seed_successful, tests::put_type, trace::TraceContext,
};

fn main() {
    let mut ctx = TraceContext::new();
    let client = AgentName::first();
    let server = client.next();
    let trace = seed_successful(client, server, put_type);

    trace.execute(&mut ctx).unwrap();
}
