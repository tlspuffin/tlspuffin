#![allow(unused_doc_comments)]

#[macro_use]
extern crate log;

use std::fs::File;
use std::io::Read;
use std::{env, fs, io::Write, path::PathBuf};

use clap::{crate_authors, crate_name, crate_version, value_t, App, SubCommand};
use log::LevelFilter;
use log4rs::append::console::ConsoleAppender;
use log4rs::append::file::FileAppender;
use log4rs::config::{Appender, Root};
use log4rs::encode::json::JsonEncoder;
use log4rs::encode::pattern::PatternEncoder;
use log4rs::Config;

use fuzzer::seeds::create_corpus;
use trace::TraceContext;

use crate::experiment::*;
use crate::fuzzer::start;
use crate::graphviz::write_graphviz;

mod agent;
mod debug;
mod error;
mod experiment;
mod fuzzer;
mod graphviz;
mod io;
mod openssl_binding;
mod term;
mod tests;
mod tls;
mod trace;
mod variable_data;
mod violation;

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
        .args_from_usage("-c, --cores=[n] 'Sets the cores to use during fuzzing'")
        .args_from_usage("-s, --seed=[n] '(experimental) provide a seed for all clients'")
        .args_from_usage("-p, --port=[n] 'Port of the broker'")
        .args_from_usage("-i, --max-iters=[i] 'Maximum iterations to do'")
        .subcommands(vec![
            SubCommand::with_name("quick-experiment").about("Starts a new experiment and writes the results out")
                .args_from_usage("--disk-corpus 'Use a on disk corpus'"),
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

    let core_definition = value_t!(matches, "cores", String).unwrap_or_else(|_| "0".to_string());
    let port = value_t!(matches, "port", u16).unwrap_or(1337);
    let static_seed = value_t!(matches, "seed", u64).ok();
    let max_iters = value_t!(matches, "max-iters", u64).ok();

    info!("{}", openssl_binding::openssl_version());

    if let Some(_matches) = matches.subcommand_matches("seed") {
        for (trace, name) in create_corpus() {
            let mut file = File::create(format!("./corpus/{}.trace", name)).unwrap();
            let buffer = postcard::to_allocvec(&trace).unwrap();
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
            trace.dot_graph(is_tree).as_str(),
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
        trace.execute(&mut ctx).unwrap();
    } else if let Some(matches) = matches.subcommand_matches("experiment") {
        let title = value_t!(matches, "title", String).unwrap();
        let description = value_t!(matches, "description", String).unwrap();
        let experiments_root = PathBuf::new().join("experiments");
        let experiment_path = experiments_root.join(format_title(Some(&title), None));
        if experiment_path.as_path().exists() {
            panic!("Experiment already exists. Consider creating a new experiment.")
        }
        fs::create_dir_all(&experiment_path).unwrap();

        handle.set_config(create_config(&experiment_path.join("tlspuffin-log.json")));

        write_experiment_markdown(&experiment_path, title, description).unwrap();
        start(
            core_definition,
            experiment_path.join("stats.json"),
            experiment_path.join("corpus"),
            PathBuf::from("./corpus"),
            experiment_path.join("crashes"),
            port,
            static_seed,
            max_iters,
        );
    } else if let Some(_matches) = matches.subcommand_matches("quick-experiment") {
        let description = "No Description, because this is a quick experiment.";
        let experiments_root = PathBuf::from("experiments");

        let title = format_title(None, None);

        let mut experiment_path = experiments_root.join(&title);

        let mut i = 1;
        while experiment_path.as_path().exists() {
            let title = format_title(None, Some(i));
            experiment_path = experiments_root.join(title);
            i += 1;
        }

        fs::create_dir_all(&experiment_path).unwrap();

        handle.set_config(create_config(&experiment_path.join("tlspuffin-log.json")));

        write_experiment_markdown(&experiment_path, title, description).unwrap();
        start(
            core_definition,
            experiment_path.join("stats.json"),
            experiment_path.join("corpus"),
            PathBuf::from("./corpus"),
            experiment_path.join("crashes"),
            port,
            static_seed,
            max_iters,
        );
    } else {
        start(
            core_definition,
            PathBuf::from("stats.json"),
            PathBuf::from("disk-corpus"),
            PathBuf::from("corpus"),
            PathBuf::from("crashes"),
            port,
            static_seed,
            max_iters,
        );
    }
}
