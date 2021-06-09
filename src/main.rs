#[macro_use]
extern crate log;

use std::fs::File;
use std::io::{Read};

use std::{env, io::Write, path::PathBuf};

use clap::{crate_authors, crate_name, crate_version, value_t, App, SubCommand};
use env_logger::{fmt, Builder, Env};
use log::Level;

use fuzzer::seeds::*;

use crate::fuzzer::start;
use crate::graphviz::write_graphviz;

mod agent;
mod debug;
mod fuzzer;
mod graphviz;
mod io;
mod openssl_binding;
mod term;
mod tests;
mod tls;
mod trace;
mod variable_data;
mod error;

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
                .args_from_usage("<output_prefix> 'The file to which the trace should be written'"),
        ])
        .get_matches();

    info!("{}", openssl_binding::openssl_version());

    if let Some(_matches) = matches.subcommand_matches("seed") {
        let client = agent::AgentName::first();
        let server = client.next();

        let traces: Vec<(
            fn(agent::AgentName, agent::AgentName) -> trace::Trace,
            &'static str,
        )> = vec![
            (seed_successful, "seed_successful"),
            (seed_successful12, "seed_successful12"),
            (seed_client_attacker, "seed_client_attacker"),
            (seed_client_attacker12, "seed_client_attacker12"),
            (seed_cve_2021_3449, "seed_cve_2021_3449"),
        ];

        for (trace_fn, name) in traces {
            let mut file = File::create(format!("./corpus/{}.trace", name)).unwrap();
            let buffer = postcard::to_allocvec(&trace_fn(client, server)).unwrap();
            file.write_all(&buffer).unwrap();
            println!("Generated seed traces into the directory ./corpus")
        }
    } else if let Some(matches) = matches.subcommand_matches("plot") {
        // Parse arguments
        let output_prefix = matches.value_of("output_prefix").unwrap();
        let input = matches.value_of("input").unwrap();
        let format = matches.value_of("format").unwrap();
        let mut input_file = File::open(input).unwrap();

        // Read trace file
        let mut buffer = Vec::new();
        input_file.read_to_end(&mut buffer).unwrap();
        let trace = postcard::from_bytes::<trace::Trace>(&buffer).unwrap();

        // All-in-one tree
        write_graphviz(
            format!("{}_{}.{}", output_prefix, "all", format).as_str(),
            format,
            &trace.dot_graph().as_str(),
        )
        .expect("Failed to generate graph.");

        for (i, subgraph) in trace.dot_subgraphs(true).iter().enumerate() {
            let wrapped_subgraph = format!("strict digraph \"\" {{ splines=true; {} }}", subgraph);
            write_graphviz(
                format!("{}_{}.{}", output_prefix, i, format).as_str(),
                format,
                wrapped_subgraph.as_str(),
            )
            .expect("Failed to generate graph.");
        }

        println!("Created plots")
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
