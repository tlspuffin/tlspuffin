#[macro_use]
extern crate log;

use core::time;
use std::io::Write;
use std::thread;

use env_logger::{fmt, Builder, Env};
use log::Level;

use crate::fuzzer::start_fuzzing;
use crate::trace::TraceContext;

mod agent;
mod debug;
mod fuzzer;
mod io;
mod openssl_binding;
mod term;
mod tests;
mod trace;
mod variable_data;

fn main() {
    fn init_logger() {
        let env = Env::default().filter("RUST_LOG");

        Builder::from_env(env)
            .format(|buf, record| {
                let mut style = buf.style();
                match record.level() {
                    Level::Error => {
                        style.set_color(fmt::Color::Red).set_bold(true);
                    }
                    Level::Warn => {
                        style.set_color(fmt::Color::Yellow).set_bold(true);
                    }
                    Level::Info => {
                        style.set_color(fmt::Color::Blue).set_bold(true);
                    }
                    Level::Debug => {}
                    Level::Trace => {}
                };

                let timestamp = buf.timestamp();

                writeln!(buf, "{} {}", timestamp, style.value(record.args()))
            })
            .init();
    }

    init_logger();
    //pretty_env_logger::formatted_builder().target(Target::Stdout).filter_level(LevelFilter::Trace).init();

    info!("{}", openssl_binding::openssl_version());

    start_fuzzing();

    loop {
        let mut ctx = TraceContext::new();
        /*
        let openssl_server_agent = ctx.new_openssl_agent(true);
        let honest_agent = ctx.new_agent();

        let client_hello = ClientHelloSendAction::new();
        let server_hello = ServerHelloExpectAction::new();
        let mut trace = trace::Trace {
            steps: vec![
                Step {
                    agent: honest_agent,
                    action: &client_hello,
                    send_to: openssl_server_agent,
                },
                Step {
                    agent: openssl_server_agent,
                    action: &server_hello,
                    send_to: AgentName::none(),
                },
            ],
        };*/
        let mut trace = trace::Trace { steps: vec![] };

        info!("{}", trace);

        trace.execute(&mut ctx);

        // Slow down the fuzzing
        thread::sleep(time::Duration::from_millis(500));
    }
}
