#[macro_use]
extern crate log;
extern crate pretty_env_logger;

use std::thread;
use core::time;

mod agent;
mod debug;
mod io;
mod openssl_server;
mod trace;
mod variable;
mod tests;

use crate::trace::{TraceContext, ClientHelloSendAction, ServerHelloExpectAction, Step};
use crate::tests::test_utils::setup_client_hello_variables;

fn main() {
    pretty_env_logger::init();
    //pretty_env_logger::formatted_builder().target(Target::Stdout).filter_level(LevelFilter::Trace).init();

    info!("{}", openssl_server::openssl_version());

    loop {
        let mut ctx = TraceContext::new();
        let openssl_server_agent = ctx.new_openssl_agent(true);
        let honest_agent = ctx.new_agent();

        let client_hello = ClientHelloSendAction::new();
        let server_hello = ServerHelloExpectAction::new();
        let mut trace = trace::Trace {
            steps: vec![
                Step {
                    agent: honest_agent,
                    action: &client_hello,
                },
                Step {
                    agent: openssl_server_agent,
                    action: &server_hello,
                },
            ],
        };

        info!("{}", trace);

        setup_client_hello_variables(&mut ctx, honest_agent);
        trace.execute(&mut ctx);

        // Slow down the fuzzing
        thread::sleep(time::Duration::from_millis(500));
    }
}
