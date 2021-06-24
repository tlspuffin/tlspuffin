#[macro_use]
extern crate log;

use std::fs::File;
use std::io::Read;
use std::process::Command;
use std::{env, fs, io::Write, path::PathBuf};

use clap::{crate_authors, crate_name, crate_version, value_t, App, SubCommand};
use log::{Level, LevelFilter};
use log4rs::append::console::ConsoleAppender;
use log4rs::append::file::FileAppender;
use log4rs::config::runtime::ConfigErrors;
use log4rs::config::{Appender, InitError, Logger, RawConfig, Root};
use log4rs::encode::json::JsonEncoder;
use log4rs::encode::pattern::PatternEncoder;
use log4rs::{Config, Handle};

use agent::AgentName;
use fuzzer::seeds::*;
use trace::{Trace, TraceContext};

use crate::fuzzer::start;
use crate::graphviz::write_graphviz;
use chrono::Utc;

mod agent;
mod debug;
mod error;
mod fuzzer;
mod graphviz;
mod io;
mod openssl_binding;
mod term;
mod tests;
mod tls;
mod trace;
mod variable_data;

fn main() {
    fn create_config(log_path: &PathBuf) -> Config {
        let stdout = ConsoleAppender::builder()
            .encoder(Box::new(PatternEncoder::new(
                "{h({d(%Y-%m-%dT%H:%M:%S%Z)}\t{m}{n})}",
            )))
            .build();
        let file_appender = FileAppender::builder()
            .encoder(Box::new(JsonEncoder::new()))
            .build(&log_path)
            .unwrap();

        Config::builder()
            .appender(Appender::builder().build("stdout", Box::new(stdout)))
            .appender(Appender::builder().build("file", Box::new(file_appender)))
            .build(
                Root::builder()
                    .appenders(vec!["stdout", "file"])
                    .build(LevelFilter::Info),
            )
            .unwrap()
    }

    let handle = log4rs::init_config(create_config(&PathBuf::from("tlspuffin-log.json"))).unwrap();

    let matches = App::new(crate_name!())
        .version(crate_version!())
        .author(crate_authors!())
        .about("Fuzzes OpenSSL on a symbolic level")
        .args_from_usage("-n, --num-cores=[n] 'Sets the amount of cores to use to fuzz'")
        .subcommands(vec![
            SubCommand::with_name("experiment").about("Starts a new experiment and writes the results out")
                .args_from_usage("-t, --title=[t] 'Title of the experiment'")
                .args_from_usage("-d, --description=[d] 'Decryption of the experiment'")
            ,
            SubCommand::with_name("seed").about("Generates seeds to ./corpus"),
            SubCommand::with_name("plot")
                .about("Plots a trace stored in a file")
                .args_from_usage("<input> 'The file which stores a trace'")
                .args_from_usage("<format> 'The format of the plot, can be svg or pdf'")
                .args_from_usage("<output_prefix> 'The file to which the trace should be written'")
                .args_from_usage("--multiple 'Whether we want to output multiple views, additionally to the combined view'")
                .args_from_usage("--tree 'Whether want to use tree mode in the combined view'"),
            SubCommand::with_name("execute")
                .about("Executes a trace stored in a file")
                .args_from_usage("<input> 'The file which stores a trace'")
        ])
        .get_matches();

    let num_cores = value_t!(matches, "num-cores", usize).unwrap_or(1);

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
        let is_multiple = matches.is_present("multiple");
        let is_tree = matches.is_present("tree");

        let mut input_file = File::open(input).unwrap();

        // Read trace file
        let mut buffer = Vec::new();
        input_file.read_to_end(&mut buffer).unwrap();
        let trace = postcard::from_bytes::<trace::Trace>(&buffer).unwrap();

        // All-in-one tree
        write_graphviz(
            format!("{}_{}.{}", output_prefix, "all", format).as_str(),
            format,
            &trace.dot_graph(is_tree).as_str(),
        )
        .expect("Failed to generate graph.");

        if is_multiple {
            for (i, subgraph) in trace.dot_subgraphs(true).iter().enumerate() {
                let wrapped_subgraph =
                    format!("strict digraph \"\" {{ splines=true; {} }}", subgraph);
                write_graphviz(
                    format!("{}_{}.{}", output_prefix, i, format).as_str(),
                    format,
                    wrapped_subgraph.as_str(),
                )
                .expect("Failed to generate graph.");
            }
        }

        println!("Created plots")
    } else if let Some(matches) = matches.subcommand_matches("execute") {
        // Parse arguments
        let input = matches.value_of("input").unwrap();

        let mut input_file = File::open(input).unwrap();

        // Read trace file
        let mut buffer = Vec::new();
        input_file.read_to_end(&mut buffer).unwrap();
        let trace = postcard::from_bytes::<trace::Trace>(&buffer).unwrap();

        let mut ctx = TraceContext::new();
        trace.spawn_agents(&mut ctx).unwrap();
        trace.execute(&mut ctx).unwrap();
    } else if let Some(matches) = matches.subcommand_matches("experiment") {
        let title = value_t!(matches, "title", String).unwrap();
        let description = value_t!(matches, "description", String).unwrap();
        let root = PathBuf::new().join("experiments").join(&title);

        if root.as_path().exists() {
            panic!("Experiment already exists. Consider creating a new experiment.")
        }
        fs::create_dir_all(&root).unwrap();

        handle.set_config(create_config(&root.join("tlspuffin-log.json")));

        let git_ref = {
            let output = Command::new("git")
                .args(&["rev-parse", "HEAD"])
                .output()
                .unwrap();
            String::from_utf8(output.stdout).unwrap()
        };

        {
            let mut file = File::create(root.join("README.md")).unwrap();

            let full_description = format!(
                "# Experiment: {title}\n\
                * OpenSSL: {openssl_version}\n\
                * Date: {date}\n\
                * Git Ref: {git_ref}\n\
                * Log: [tlspuffin-log.json](./tlspuffin-log.json)\n\n\
                {description}\n",
                title = &title,
                openssl_version = openssl_binding::openssl_version(),
                date = Utc::now().to_rfc3339(),
                git_ref = git_ref,
                description = description
            );
            file.write_all(full_description.as_bytes()).unwrap();
        }

        start(
            num_cores,
            &[PathBuf::from("./corpus")],
            &root.join("crashes"),
            1337,
        );
    } else {
        start(
            num_cores,
            &[PathBuf::from("./corpus")],
            &PathBuf::from("./crashes"),
            1337,
        );
    }
}
