use std::{
    env, fs,
    fs::File,
    io::{Read, Write},
    path::PathBuf,
    process::ExitCode,
};

use clap::{arg, crate_authors, crate_name, crate_version, Command};
use log::{error, info, SetLoggerError};
use log4rs::Handle;

use crate::{
    algebra::set_deserialize_signature,
    experiment::*,
    fuzzer::{
        sanitizer::asan::{asan_info, setup_asan_env},
        start, FuzzerConfig,
    },
    graphviz::write_graphviz,
    log::create_stdout_config,
    protocol::ProtocolBehavior,
    put_registry::PutRegistry,
    trace::{Trace, TraceContext},
};

fn create_app() -> Command<'static> {
    Command::new(crate_name!())
        .version(crate_version!())
        .author(crate_authors!())
        .about("Fuzzes OpenSSL on a symbolic level")
        .arg(arg!(-c --cores [spec] "Sets the cores to use during fuzzing"))
        .arg(arg!(-s --seed [n] "(experimental) provide a seed for all clients"))
        .arg(arg!(-p --port [n] "Port of the broker"))
        .arg(arg!(-i --"max-iters" [i] "Maximum iterations to do"))
        .arg(arg!(--minimizer "Use a minimizer"))
        .arg(arg!(--monitor "Use a monitor"))
        .arg(arg!(--"no-launcher" "Do not use the convenient launcher"))
        .subcommands(vec![
            Command::new("quick-experiment").about("Starts a new experiment and writes the results out"),
            Command::new("experiment").about("Starts a new experiment and writes the results out")
                .arg(arg!(-t --title <t> "Title of the experiment"))
                         .arg(arg!(-d --description <d> "Descritpion of the experiment"))
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

pub fn main<PB: ProtocolBehavior + Clone + 'static>(
    put_registry: &'static PutRegistry<PB>,
) -> ExitCode {
    let handle = match log4rs::init_config(create_stdout_config()) {
        Ok(handle) => handle,
        Err(err) => {
            error!("Failed to init logging: {:?}", err);
            return ExitCode::FAILURE;
        }
    };

    let matches = create_app().get_matches();

    let core_definition = matches.value_of("cores").unwrap_or("0");
    let port: u16 = matches.value_of_t("port").unwrap_or(1337);
    let static_seed: Option<u64> = matches.value_of_t("seed").ok();
    let max_iters: Option<u64> = matches.value_of_t("max-iters").ok();
    let minimizer = matches.is_present("minimizer");
    let monitor = matches.is_present("monitor");
    let no_launcher = matches.is_present("no-launcher");

    info!("Version: {}", crate::GIT_REF);
    info!("Put Versions:");
    for version in put_registry.version_strings() {
        info!("{}", version);
    }

    asan_info();
    setup_asan_env();

    set_deserialize_signature(PB::signature());

    if let Some(_matches) = matches.subcommand_matches("seed") {
        if let Err(err) = seed(put_registry) {
            error!("Failed to create seeds on disk: {:?}", err);
            return ExitCode::FAILURE;
        }
    } else if let Some(matches) = matches.subcommand_matches("plot") {
        // Parse arguments
        let output_prefix: &str = matches.value_of("output_prefix").unwrap();
        let input = matches.value_of("input").unwrap();
        let format = matches.value_of("format").unwrap();
        let is_multiple = matches.is_present("multiple");
        let is_tree = matches.is_present("tree");

        if let Err(err) = plot::<PB>(input, format, output_prefix, is_multiple, is_tree) {
            error!("Failed to plot trace: {:?}", err);
            return ExitCode::FAILURE;
        }
    } else if let Some(matches) = matches.subcommand_matches("execute") {
        // Parse arguments
        let input = matches.value_of("input").unwrap();

        if let Err(err) = execute(input, put_registry) {
            error!("Failed to execute trace: {:?}", err);
            return ExitCode::FAILURE;
        }
    } else {
        let experiment_path = if let Some(matches) = matches.subcommand_matches("experiment") {
            let title = matches.value_of("title").unwrap();
            let description = matches.value_of("description").unwrap();
            let experiments_root = PathBuf::new().join("experiments");
            let experiment_path = experiments_root.join(format_title(Some(title), None));
            if experiment_path.as_path().exists() {
                panic!("Experiment already exists. Consider creating a new experiment.")
            }

            if let Err(err) =
                write_experiment_markdown(&experiment_path, title, description, put_registry)
            {
                error!("Failed to write readme: {:?}", err);
                return ExitCode::FAILURE;
            }

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

            if let Err(err) =
                write_experiment_markdown(&experiment_path, title, description, put_registry)
            {
                error!("Failed to write readme: {:?}", err);
                return ExitCode::FAILURE;
            }
            experiment_path
        } else {
            PathBuf::from(".")
        };

        if let Err(err) = fs::create_dir_all(&experiment_path) {
            error!("Failed to create directories: {:?}", err);
            return ExitCode::FAILURE;
        }

        let config = FuzzerConfig {
            initial_corpus_dir: experiment_path.join("seeds"),
            static_seed,
            max_iters,
            core_definition: core_definition.to_string(),
            corpus_dir: experiment_path.join("corpus"),
            objective_dir: experiment_path.join("objective"),
            broker_port: port,
            monitor_file: experiment_path.join("stats.json"),
            log_file: experiment_path.join("log.json"),
            minimizer,
            mutation_stage_config: Default::default(),
            mutation_config: Default::default(),
            monitor,
            no_launcher,
        };

        if let Err(err) = start::<PB>(config, handle) {
            match err {
                libafl::Error::ShuttingDown => {
                    // ignore
                }
                _ => {
                    panic!("{}", err)
                }
            }
        }
    }

    ExitCode::SUCCESS
}

fn plot<PB: ProtocolBehavior>(
    input: &str,
    format: &str,
    output_prefix: &str,
    is_multiple: bool,
    is_tree: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut input_file = File::open(input)?;

    // Read trace file
    let mut buffer = Vec::new();
    input_file.read_to_end(&mut buffer)?;
    let trace = postcard::from_bytes::<Trace<PB::QueryMatcher>>(&buffer)?;

    // All-in-one tree
    write_graphviz(
        format!("{}_{}.{}", output_prefix, "all", format).as_str(),
        format,
        trace.dot_graph(is_tree).as_str(),
    )
    .expect("Failed to generate graph.");

    if is_multiple {
        for (i, subgraph) in trace.dot_subgraphs(true).iter().enumerate() {
            let wrapped_subgraph = format!("strict digraph \"\" {{ splines=true; {} }}", subgraph);
            write_graphviz(
                format!("{}_{}.{}", output_prefix, i, format).as_str(),
                format,
                wrapped_subgraph.as_str(),
            )
            .expect("Failed to generate graph.");
        }
    }

    info!("Created plots");
    Ok(())
}

fn seed<PB: ProtocolBehavior>(
    put_registry: &PutRegistry<PB>,
) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all("./seeds")?;
    for (trace, name) in PB::create_corpus() {
        let mut file = File::create(format!("./seeds/{}.trace", name))?;
        let buffer = postcard::to_allocvec(&trace)?;
        file.write_all(&buffer)?;
        info!("Generated seed traces into the directory ./corpus")
    }
    Ok(())
}

fn execute<PB: ProtocolBehavior>(
    input: &str,
    put_registry: &'static PutRegistry<PB>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut input_file = File::open(input)?;

    // Read trace file
    let mut buffer = Vec::new();
    input_file.read_to_end(&mut buffer)?;
    let trace = postcard::from_bytes::<Trace<PB::QueryMatcher>>(&buffer)?;

    info!("Agents: {:?}", &trace.descriptors);

    let mut ctx = TraceContext::new(put_registry);
    trace.execute(&mut ctx)?;
    Ok(())
}
