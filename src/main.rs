mod trace;
mod variable;

use crate::trace::{ClientHelloSendStep, TraceContext};
use crate::variable::{RandomVariableValue, Variable, VariableData, ClientVersionData, SessionIDData, RandomData};
fn main() {
    let mut ctx = TraceContext::new();
    let trace = trace::Trace {
        steps: vec![
            Box::new(ClientHelloSendStep::new(vec![])),
            Box::new(ClientHelloSendStep::new(vec![])),
        ],
    };

    ctx.add_variable(Box::new(ClientVersionData::random_value()));
    ctx.add_variable(Box::new(SessionIDData::random_value()));
    ctx.add_variable(Box::new(RandomData::random_value()));
    trace.execute(&ctx)
}
