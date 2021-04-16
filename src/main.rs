mod agent;
mod openssl_server;
mod trace;
mod debug;
mod variable;
use crate::trace::{ClientHelloSendStep, TraceContext};
use crate::debug::debug_message_raw;
use crate::variable::{
    CipherSuiteData, ClientVersionData, CompressionData, ExtensionData, RandomData, SessionIDData,
    VariableData,
};
use std::io::ErrorKind;
use pretty_env_logger::env_logger::{Target};
use log::LevelFilter;

extern crate pretty_env_logger;
#[macro_use] extern crate log;

fn main() {

    //pretty_env_logger::init();
    pretty_env_logger::formatted_builder()
        .target(Target::Stdout)
        .filter_level(LevelFilter::Trace)
        .init();

    info!("{}", openssl_server::openssl_version());

    while true {
        let mut ctx = TraceContext::new();
        let trace = trace::Trace {
            steps: vec![Box::new(ClientHelloSendStep::new())],
        };

        ctx.add_variable(Box::new(ClientVersionData::random_value()));
        ctx.add_variable(Box::new(SessionIDData::random_value()));
        ctx.add_variable(Box::new(RandomData::random_value()));
        // ctx.add_variable(Box::new(ExtensionData::random_value()));
        // ctx.add_variable(Box::new(ExtensionData::random_value()));
        // ctx.add_variable(Box::new(ExtensionData::random_value()));
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
        let buffer = trace.execute(&ctx);

        let mut stream = openssl_server::create_openssl_server();
        stream.get_mut().extend_incoming(&buffer);

        match stream.accept() {
            Ok(_) => {
                println!("Handshake is done");
                break;
            }
            Err(error) => {
                let outgoing = stream.get_mut().take_outgoing();
                let buffer = outgoing.as_ref();
                debug_message_raw(buffer);

                if let Some(io_error) = error.io_error() {
                    match io_error.kind() {
                        ErrorKind::WouldBlock => {
                            // Not actually an error, we just reached the end of the stream
                        }
                        _ => {
                            warn!("{}", io_error);
                        }
                    }
                }

                if let Some(ssl_error) = error.ssl_error() {
                    warn!("{}", ssl_error);
                }
            }
        }
    }
}
