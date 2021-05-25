use tlspuffin::fuzzer::seeds::seed_successful;
use tlspuffin::trace::TraceContext;

fn main() {
    let mut ctx = TraceContext::new();
    seed_successful(&mut ctx);
}