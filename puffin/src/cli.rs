use std::{
    env, fs,
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::ExitCode,
};

use clap::{
    arg, crate_authors, crate_name, crate_version, parser::ValuesRef, value_parser, Command,
};
use libafl::inputs::Input;
use log::{error, info, LevelFilter};

use crate::{
    algebra::set_deserialize_signature,
    codec::Codec,
    execution::forked_execution,
    experiment::*,
    fuzzer::{
        harness::{default_put_options, set_default_put_options},
        sanitizer::asan::{asan_info, setup_asan_env},
        start, FuzzerConfig,
    },
    graphviz::write_graphviz,
    log::create_stderr_config,
    protocol::{ProtocolBehavior, ProtocolMessage},
    put::PutOptions,
    put_registry::PutRegistry,
    trace::{Action, Trace, TraceContext},
};

fn create_app() -> Command {
    Command::new(crate_name!())
        .version(crate::MAYBE_GIT_REF.unwrap_or( crate_version!()))
        .author(crate_authors!())
        .about("Fuzzes OpenSSL on a symbolic level")
        .arg(arg!(-c --cores [spec] "Sets the cores to use during fuzzing"))
        .arg(arg!(-s --seed [n] "(experimental) provide a seed for all clients")
            .value_parser(value_parser!(u64)))
        .arg(arg!(-p --port [n] "Port of the broker")
            .value_parser(value_parser!(u16).range(1..)))
        .arg(arg!(-i --"max-iters" [i] "Maximum iterations to do")
            .value_parser(value_parser!(u64).range(0..)))
        .arg(arg!(--minimizer "Use a minimizer"))
        .arg(arg!(--monitor "Use a monitor"))
        .arg(arg!(--"put-use-clear" "Use clearing functionality instead of recreating puts"))
        .arg(arg!(--"no-launcher" "Do not use the convenient launcher"))
        .subcommands(vec![
            Command::new("quick-experiment").about("Starts a new experiment and writes the results out"),
            Command::new("experiment").about("Starts a new experiment and writes the results out")
                .arg(arg!(-t --title <t> "Title of the experiment"))
                         .arg(arg!(-d --description <d> "Descritpion of the experiment"))
            ,
            Command::new("seed").about("Generates seeds to ./seeds"),
            Command::new("plot")
                .about("Plots a trace stored in a file")
                .arg(arg!(<input> "The file which stores a trace"))
                .arg(arg!(<format> "The format of the plot, can be svg or pdf"))
                .arg(arg!(<output_prefix> "The file to which the trace should be written"))
                .arg(arg!(--multiple "Whether we want to output multiple views, additionally to the combined view"))
                .arg(arg!(--tree "Whether want to use tree mode in the combined view")),
            Command::new("execute")
                .about("Executes a trace stored in a file.")
                .arg(arg!(<inputs> "The file which stores a trace").num_args(1..))
                .arg(arg!(-n --number <n> "Amount of files to execute starting at index.").value_parser(value_parser!(usize)))
                .arg(arg!(-i --index <i> "Index of file to execute.").value_parser(value_parser!(usize)))
                .arg(arg!(-s --sort "Sort files in ascending order by the creation date before executing")),
            Command::new("binary-attack")
                .about("Serializes a trace as much as possible and output its")
                .arg(arg!(<input> "The file which stores a trace"))
                .arg(arg!(<output> "The file to write serialized data to")),
            Command::new("tcp")
                .about("Executes a trace against a TCP client/server")
                .arg(arg!(<input> "The file which stores a trace"))
                .arg(arg!(-c --cwd [p] "The current working directory for the binary"))
                .arg(arg!(-b --binary [p] "The program to start"))
                .arg(arg!(-a --args [a] "The args of the program"))
                .arg(arg!(-t --host [h] "The host to connect to, or the server host"))
                .arg(arg!(-p --port [n] "The client port to connect to, or the server port")
                    .value_parser(value_parser!(u16).range(1..)))
        ])
}

pub fn main<PB: ProtocolBehavior + Clone + 'static>(
    put_registry: &'static PutRegistry<PB>,
) -> ExitCode {
    let handle = match log4rs::init_config(create_stderr_config(LevelFilter::Info)) {
        Ok(handle) => handle,
        Err(err) => {
            error!("Failed to init logging: {:?}", err);
            return ExitCode::FAILURE;
        }
    };

    let matches = create_app().get_matches();

    let first_core = "0".to_string();
    let core_definition = matches.get_one("cores").unwrap_or(&first_core);
    let port: u16 = *matches.get_one::<u16>("port").unwrap_or(&1337u16);
    let static_seed: Option<u64> = matches.get_one("seed").copied();
    let max_iters: Option<u64> = matches.get_one("max-iters").copied();
    let minimizer = matches.get_flag("minimizer");
    let monitor = matches.get_flag("monitor");
    let no_launcher = matches.get_flag("no-launcher");
    let put_use_clear = matches.get_flag("put-use-clear");

    info!("Git Version: {}", crate::GIT_REF);
    info!("Put Versions:");
    for version in put_registry.version_strings() {
        info!("{}", version);
    }

    asan_info();
    setup_asan_env();

    // Initialize global state

    if set_deserialize_signature(PB::signature()).is_err() {
        error!("Failed to initialize deserialization");
    }

    let mut options: Vec<(String, String)> = Vec::new();
    if put_use_clear {
        options.push(("use_clear".to_string(), put_use_clear.to_string()))
    }
    if set_default_put_options(PutOptions::new(options)).is_err() {
        error!("Failed to initialize default put options");
    }

    if let Some(_matches) = matches.subcommand_matches("seed") {
        if let Err(err) = seed(put_registry) {
            error!("Failed to create seeds on disk: {:?}", err);
            return ExitCode::FAILURE;
        }
    } else if let Some(matches) = matches.subcommand_matches("plot") {
        // Parse arguments
        let output_prefix: &String = matches.get_one("output_prefix").unwrap();
        let input: &String = matches.get_one("input").unwrap();
        let format: &String = matches.get_one("format").unwrap();
        let is_multiple = matches.get_flag("multiple");
        let is_tree = matches.get_flag("tree");

        if let Err(err) = plot::<PB>(input, format, output_prefix, is_multiple, is_tree) {
            error!("Failed to plot trace: {:?}", err);
            return ExitCode::FAILURE;
        }
    } else if let Some(matches) = matches.subcommand_matches("execute") {
        let inputs: ValuesRef<String> = matches.get_many("inputs").unwrap();
        let index: usize = *matches.get_one("index").unwrap_or(&0);
        let n: usize = *matches.get_one("number").unwrap_or(&inputs.len());

        let mut paths = inputs
            .flat_map(|input| {
                let input = PathBuf::from(input);

                if input.is_dir() {
                    fs::read_dir(input)
                        .expect("failed to read directory")
                        .map(|entry| entry.expect("failed to read path in directory").path())
                        .filter(|path| {
                            !path.file_name().unwrap().to_str().unwrap().starts_with(".")
                        })
                        .collect()
                } else {
                    vec![input]
                }
            })
            .collect::<Vec<_>>();

        paths.sort_by_key(|path| {
            fs::metadata(path)
                .unwrap_or_else(|_| panic!("missing trace file {}", path.display()))
                .modified()
                .unwrap()
        });

        let lookup_paths = if index < paths.len() {
            if index + n < paths.len() {
                &paths[index..index + n]
            } else {
                &paths[index..]
            }
        } else {
            // empty
            &paths[0..0]
        };

        info!("execute: found {} inputs", paths.len());
        info!(
            "execute: running on subset [{}..{}] ({} inputs)",
            index,
            index + n,
            lookup_paths.len()
        );

        for path in lookup_paths {
            info!("Executing: {}", path.display());
            execute(path, put_registry);
        }

        if !lookup_paths.is_empty() {
            println!(
                "{}",
                fs::metadata(&lookup_paths[0])
                    .unwrap_or_else(|_| panic!("missing trace file {}", lookup_paths[0].display()))
                    .modified()
                    .unwrap()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_millis()
            )
        }

        return ExitCode::SUCCESS;
    } else if let Some(matches) = matches.subcommand_matches("binary-attack") {
        let input: &String = matches.get_one("input").unwrap();
        let output: &String = matches.get_one("output").unwrap();

        if let Err(err) = binary_attack(input, output, put_registry) {
            error!("Failed to create trace output: {:?}", err);
            return ExitCode::FAILURE;
        }
    } else if let Some(matches) = matches.subcommand_matches("tcp") {
        let input: &String = matches.get_one("input").unwrap();
        let prog: Option<&String> = matches.get_one("binary");
        let args: Option<&String> = matches.get_one("args");
        let cwd: Option<&String> = matches.get_one("cwd");
        let default_host = "127.0.0.1".to_string();
        let host: &String = matches.get_one("host").unwrap_or(&default_host);
        let port = matches
            .get_one::<u16>("port")
            .unwrap_or(&44338u16)
            .to_string();

        let trace = Trace::<PB::Matcher>::from_file(input).unwrap();

        let mut options = vec![("port", port.as_str()), ("host", &host)];

        if let Some(prog) = prog {
            options.push(("prog", &prog))
        }

        if let Some(args) = args {
            options.push(("args", &args))
        }

        if let Some(cwd) = cwd {
            options.push(("cwd", &cwd))
        }

        let put = PutDescriptor {
            name: PutName(['T', 'C', 'P', '_', '_', '_', '_', '_', '_', '_']),
            options: PutOptions::from_slice_vec(options),
        };

        let server = trace.descriptors[0].name;
        let mut context = trace
            .execute_with_non_default_puts(&put_registry, &[(server, put)])
            .unwrap();

        let server = AgentName::first();
        let shutdown = context.find_agent_mut(server).unwrap().put_mut().shutdown();
        info!("{}", shutdown);

        return ExitCode::SUCCESS;
    } else {
        let experiment_path = if let Some(matches) = matches.subcommand_matches("experiment") {
            let title: &String = matches.get_one("title").unwrap();
            let description: &String = matches.get_one("description").unwrap();
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
            initial_corpus_dir: PathBuf::from("./seeds"),
            static_seed,
            max_iters,
            core_definition: core_definition.to_string(),
            corpus_dir: experiment_path.join("corpus"),
            objective_dir: experiment_path.join("objective"),
            broker_port: port,
            monitor_file: experiment_path.join("stats.json"),
            log_file: experiment_path.join("tlspuffin.log"),
            minimizer,
            mutation_stage_config: Default::default(),
            mutation_config: Default::default(),
            monitor,
            no_launcher,
        };

        if let Err(err) = start::<PB>(config, handle) {
            match err {
                libafl::Error::ShuttingDown => {
                    log::info!("\nFuzzing stopped by user. Good Bye.")
                }
                _ => {
                    panic!("Fuzzing failed {err:?}")
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
    let trace = postcard::from_bytes::<Trace<PB::Matcher>>(&buffer)?;

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
    _put_registry: &PutRegistry<PB>,
) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all("./seeds")?;
    for (trace, name) in PB::create_corpus() {
        trace.to_file(format!("./seeds/{}.trace", name))?;
    }

    info!("Generated seed traces into the directory ./seeds");
    Ok(())
}

use crate::{
    agent::AgentName,
    put::{PutDescriptor, PutName},
};

fn execute<PB: ProtocolBehavior, P: AsRef<Path>>(input: P, put_registry: &'static PutRegistry<PB>) {
    let trace = match Trace::<PB::Matcher>::from_file(input.as_ref()) {
        Ok(t) => t,
        Err(_) => {
            error!("Invalid trace file {}", input.as_ref().display());
            return;
        }
    };

    info!("Agents: {:?}", &trace.descriptors);

    // When generating coverage a crash means that no coverage is stored
    // By executing in a fork, even when that process crashes, the other executed code will still yield coverage
    let status = forked_execution(
        move || {
            let mut ctx = TraceContext::new(put_registry, default_put_options().clone());
            if let Err(err) = trace.execute(&mut ctx) {
                error!(
                    "Failed to execute trace {}: {:?}",
                    input.as_ref().display(),
                    err
                );
                std::process::exit(1);
            }
        },
        None,
    );

    match status {
        Ok(s) => info!("execution finished with status {s:?}"),
        Err(reason) => panic!("failed to execute trace: {reason}"),
    }
}

fn binary_attack<PB: ProtocolBehavior>(
    input: &str,
    output: &str,
    put_registry: &'static PutRegistry<PB>,
) -> Result<(), Box<dyn std::error::Error>> {
    let trace = Trace::<PB::Matcher>::from_file(input)?;
    let ctx = TraceContext::new(put_registry, default_put_options().clone());

    info!("Agents: {:?}", &trace.descriptors);

    let mut f = File::create(output).expect("Unable to create file");

    for step in trace.steps {
        match step.action {
            Action::Input(input) => {
                if let Ok(evaluated) = input.recipe.evaluate(&ctx) {
                    if let Some(msg) = evaluated.as_ref().downcast_ref::<PB::ProtocolMessage>() {
                        let mut data: Vec<u8> = Vec::new();
                        msg.create_opaque().encode(&mut data);
                        f.write_all(&data).expect("Unable to write data");
                    } else if let Some(opaque_message) = evaluated
                        .as_ref()
                        .downcast_ref::<PB::OpaqueProtocolMessage>()
                    {
                        let mut data: Vec<u8> = Vec::new();
                        opaque_message.encode(&mut data);
                        f.write_all(&data).expect("Unable to write data");
                    } else {
                        error!("Recipe is not a `ProtocolMessage` or `OpaqueProtocolMessage`!")
                    }
                }
            }
            Action::Output(_) => {}
        }
    }
    Ok(())
}
