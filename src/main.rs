mod trace;
mod variable;
mod agent;
mod util;

use crate::trace::{ClientHelloSendStep, TraceContext};
use crate::variable::{VariableData, ClientVersionData, SessionIDData, RandomData, ExtensionData};


fn main() {
    let mut ctx = TraceContext::new();
    let trace = trace::Trace {
        steps: vec![
            Box::new(ClientHelloSendStep::new()),
            Box::new(ClientHelloSendStep::new()),
        ],
    };

    ctx.add_variable(Box::new(ClientVersionData::random_value()));
    ctx.add_variable(Box::new(SessionIDData::random_value()));
    ctx.add_variable(Box::new(RandomData::random_value()));
    ctx.add_variable(Box::new(ExtensionData::random_value()));
    ctx.add_variable(Box::new(ExtensionData::random_value()));
    ctx.add_variable(Box::new(ExtensionData::random_value()));
    trace.execute(&ctx)
}
