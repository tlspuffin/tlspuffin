#[macro_use]
extern crate log;
extern crate pretty_env_logger;

use std::io::ErrorKind;

use crate::agent::Agent;
use crate::debug::debug_message;
use crate::trace::{TraceContext, Step, ClientHelloSendAction, ServerHelloExpectAction};
use crate::variable::{
    CipherSuiteData, ClientVersionData, CompressionData, ExtensionData, RandomData, SessionIDData,
    VariableData,
};

mod agent;
mod debug;
mod io;
mod openssl_server;
mod trace;
mod variable;

fn main() {
    pretty_env_logger::init();
    //pretty_env_logger::formatted_builder().target(Target::Stdout).filter_level(LevelFilter::Trace).init();

    info!("{}", openssl_server::openssl_version());



    loop {
        let mut ctx = TraceContext::new();
        let openssl_agent = ctx.new_openssl_agent();
        let fuzz_agent = ctx.new_agent();

        // TODO link this to openssl agent?
        // ctx.new_openssl_agent() ?
        //let mut stream = openssl_server::create_openssl_server(openssl_agent.stream, &cert, &pkey);

        let client_hello = ClientHelloSendAction::new();
        let server_hello = ServerHelloExpectAction::new();
        let mut trace = trace::Trace {
            steps: vec![
                Step {
                    from: fuzz_agent,
                    to: openssl_agent,
                    action: &client_hello
                },
                Step {
                    from: openssl_agent,
                    to: fuzz_agent,
                    action: &server_hello
                },
            ],
        };

        ctx.add_variable(Box::new(ClientVersionData::random_value()));
        ctx.add_variable(Box::new(SessionIDData::random_value()));
        ctx.add_variable(Box::new(RandomData::random_value()));

        // A random extension
        ctx.add_variable(Box::new(ExtensionData::random_value()));

        // Some static extensions
        ctx.add_variable(Box::new(ExtensionData::static_extension(
            ExtensionData::key_share(),
        )));
        ctx.add_variable(Box::new(ExtensionData::static_extension(
            ExtensionData::supported_versions(),
        )));
        ctx.add_variable(Box::new(ExtensionData::static_extension(
            ExtensionData::supported_groups(),
        )));
        ctx.add_variable(Box::new(ExtensionData::static_extension(
            ExtensionData::server_name("maxammann.org"),
        )));
        ctx.add_variable(Box::new(ExtensionData::static_extension(
            ExtensionData::signature_algorithms(),
        )));

        ctx.add_variable(Box::new(CipherSuiteData::random_value()));
        ctx.add_variable(Box::new(CipherSuiteData::random_value()));
        ctx.add_variable(Box::new(CipherSuiteData::random_value()));
        ctx.add_variable(Box::new(CompressionData::random_value()));

        trace.execute(&mut ctx);
    }
}
