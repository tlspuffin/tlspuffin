#![allow(unused_doc_comments)]
#[macro_use]
extern crate log;
use crate::experiment::*;
use crate::fuzzer::start;
use crate::graphviz::write_graphviz;
use clap::{arg, crate_authors, crate_name, crate_version, Command};
use fuzzer::seeds::create_corpus;
use log::LevelFilter;
use log4rs::append::console::ConsoleAppender;
use log4rs::append::file::FileAppender;
use log4rs::config::{Appender, Root};
use log4rs::encode::json::JsonEncoder;
use log4rs::encode::pattern::PatternEncoder;
use log4rs::Config;
use std::fs::File;
use std::io::Read;
use std::{env, fs, io::Write, path::PathBuf};
use trace::TraceContext;

mod agent;
mod concretize;
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
#[cfg(feature = "wolfssl")]
mod wolfssl_binding;
#[cfg(feature = "wolfssl")]
mod wolfssl_bio;

fn create_app() -> Command<'static> {
    Command::new(crate_name!())
        .version(crate_version!())
        .author(crate_authors!())
        .about("Fuzzes OpenSSL on a symbolic level")
        .arg(arg!(-c --cores [spec] "Sets the cores to use during fuzzing"))
        .arg(arg!(-s --seed [n] "(experimental) provide a seed for all clients"))
        .arg(arg!(-p --port [n] "Port of the broker"))
        .arg(arg!(-i --"max-iters" [i] "Maximum iterations to do"))
        .arg(arg!(--"disk-corpus" "Use a on disk corpus"))
        .arg(arg!(--minimizer "Use a minimizer"))
        .subcommands(vec![
            Command::new("quick-experiment").about("Starts a new experiment and writes the results out"),
            Command::new("experiment").about("Starts a new experiment and writes the results out")
                .arg(arg!(-t --title [t] "Title of the experiment"))
                         .arg(arg!(-d --description [d] "Descritpion of the experiment"))
            ,
            Command::new("seed").about("Generates seeds to ./corpus"),
            Command::new("plot")
                .about("Plots a trace stored in a file")
                .arg(arg!(<input> "The file which stores a trace"))
                .arg(arg!(<format> "The format of the plot, can be svg or pdf"))
                .arg(arg!(<output_prefix> "The file to which the trace should be written"))
                .arg(arg!(--multiple "Whether we want to output multiple views, additionally to the combined view"))
                .arg(arg!(--tree "Whether want to use tree mode in the combined view")),
            Command::new("execute")
                .about("Executes a trace stored in a file")
                .arg(arg!(<input> "The file which stores a trace"))
        ])
}

fn create_config(log_path: &PathBuf) -> Config {
    let stdout = ConsoleAppender::builder()
        .encoder(Box::new(PatternEncoder::new(
            "{h({d(%Y-%m-%dT%H:%M:%S%Z)}\t{m}{n})}",
        )))
        .build();
    let file_appender = FileAppender::builder()
        .encoder(Box::new(JsonEncoder::new()))
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

fn main() {
    let handle = log4rs::init_config(create_config(&PathBuf::from("tlspuffin-log.json"))).unwrap();

    let matches = create_app().get_matches();

    let core_definition = matches.value_of("cores").unwrap_or("0");
    let port: u16 = matches.value_of_t("port").unwrap_or(1337);
    let static_seed: Option<u64> = matches.value_of_t("seed").ok();
    let max_iters: Option<u64> = matches.value_of_t("max-iters").ok();
    let disk_corpus = matches.is_present("disk-corpus");
    let minimizer = matches.is_present("minimizer");

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
    } else {
        let experiment_path = if let Some(matches) = matches.subcommand_matches("experiment") {
            let title = matches.value_of("title").unwrap();
            let description = matches.value_of("description").unwrap();
            let experiments_root = PathBuf::new().join("experiments");
            let experiment_path = experiments_root.join(format_title(Some(title), None));
            if experiment_path.as_path().exists() {
                panic!("Experiment already exists. Consider creating a new experiment.")
            }
            fs::create_dir_all(&experiment_path).unwrap();

            handle.set_config(create_config(&experiment_path.join("tlspuffin-log.json")));

            write_experiment_markdown(&experiment_path, title, description).unwrap();
            experiment_path
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
            experiment_path
        } else {
            PathBuf::from(".")
        };

        start(
            core_definition,
            experiment_path.join("stats.json"),
            if disk_corpus {
                Some(experiment_path.join("disk-corpus"))
            } else {
                None
            },
            PathBuf::from("./corpus"),
            experiment_path.join("crashes"),
            port,
            static_seed,
            max_iters,
            minimizer,
        );
    }
}
