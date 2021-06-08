#[macro_use]
extern crate log;

use std::fs::File;
use std::io::{BufWriter, Read};
use std::process::{Command, Stdio};
use std::{env, io::Write, path::PathBuf};

use clap::{crate_authors, crate_name, crate_version, value_t, App, SubCommand};
use env_logger::{fmt, Builder, Env};
use log::Level;

use fuzzer::seeds::*;

use crate::fuzzer::start;

mod agent;
mod debug;
mod fuzzer;
mod io;
mod openssl_binding;
mod term;
mod tests;
mod tls;
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

    let matches = App::new(crate_name!())
        .version(crate_version!())
        .author(crate_authors!())
        .about("Fuzzes OpenSSL on a symbolic level")
        .args_from_usage("-n, --num-cores=[n] 'Sets the amount of cores to use to fuzz'")
        .subcommands(vec![
            SubCommand::with_name("seed").about("Generates seeds to ./corpus"),
            SubCommand::with_name("plot")
                .about("Plots a trace stored in a file")
                .args_from_usage("<input> 'The file which stores a trace'")
                .args_from_usage("<format> 'The format of the plot, can be svg or pdf'")
                .args_from_usage("<output> 'The file to which the trace should be written'"),
        ])
        .get_matches();

    info!("{}", openssl_binding::openssl_version());

    println!(
        "Workdir: {:?}",
        env::current_dir().unwrap().to_string_lossy().to_string()
    );

    if let Some(_matches) = matches.subcommand_matches("seed") {
        let client = agent::AgentName::first();
        let server = client.next();

        let traces: Vec<fn(agent::AgentName, agent::AgentName) -> trace::Trace> = vec![
            seed_successful,
            seed_successful12,
            seed_client_attacker,
            seed_client_attacker12,
            seed_cve_2021_3449,
        ];

        for (i, trace_fn) in traces.iter().enumerate() {
            let mut file = File::create(format!("corpus/{}.trace", i)).unwrap();
            let buffer = postcard::to_allocvec(&trace_fn(client, server)).unwrap();
            file.write_all(&buffer).unwrap();
            info!("Generated seeds to ./corpus")
        }
    } else if let Some(matches) = matches.subcommand_matches("plot") {
        let output = matches.value_of("output").unwrap();
        let input = matches.value_of("input").unwrap();
        let format = matches.value_of("format").unwrap();
        println!("{}", output);
        let mut output_file = File::create(output).unwrap();

        let mut input_file = File::open(input).unwrap();
        let mut buffer = Vec::new();
        input_file.read_to_end(&mut buffer).unwrap();
        let trace = postcard::from_bytes::<crate::trace::Trace>(&buffer).unwrap();

        let child = Command::new("dot")
            .args(&["-o", output, "-T", format])
            .stdin(Stdio::piped())
            .spawn()
            .expect("failed to execute dot");

        let mut dot_stdin = child.stdin.unwrap();
        let mut writer = BufWriter::new(&mut dot_stdin);
        writer.write(trace.dot_graph().as_bytes().as_ref());
    } else {
        let num_cores = value_t!(matches, "num-cores", usize).unwrap_or(1);

        info!("Running on {} cores", num_cores);
        start(
            num_cores,
            &[PathBuf::from("./corpus")],
            PathBuf::from("./crashes"),
            1337,
        );
    }
}
