use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::{env, fs};

use clap::parser::ValuesRef;
use clap::{arg, crate_authors, crate_name, crate_version, value_parser, Command};
use libafl::inputs::Input;
use libafl_bolts::prelude::Cores;

use crate::agent::AgentName;
use crate::algebra::TermType;
use crate::execution::{ForkedRunner, Runner, TraceRunner};
use crate::experiment::{format_title, write_experiment_markdown};
use crate::fuzzer::sanitizer::asan::{asan_info, setup_asan_env};
use crate::fuzzer::{start, FuzzerConfig};
use crate::graphviz::write_graphviz;
use crate::log::config_default;
use crate::protocol::ProtocolBehavior;
use crate::put::PutDescriptor;
use crate::put_registry::{PutRegistry, TCP_PUT};
use crate::trace::{Action, Spawner, Trace, TraceContext};

fn create_app<S>(title: S) -> Command
where
    S: AsRef<str>,
{
    Command::new(crate_name!())
        .version(crate::MAYBE_GIT_REF.unwrap_or( crate_version!()))
        .author(crate_authors!())
        .about(title.as_ref().to_owned())
        .arg(arg!(-c --cores [spec] "Sets the cores to use during fuzzing"))
        .arg(arg!(-s --seed [n] "(experimental) provide a seed for all clients")
            .value_parser(value_parser!(u64)))
        .arg(arg!(-p --port [n] "Port of the broker")
            .value_parser(value_parser!(u16).range(1..)))
        .arg(arg!(-i --"max-iters" [i] "Maximum iterations to do")
            .value_parser(value_parser!(u64).range(0..)))
        .arg(arg!(--minimizer "Use a minimizer"))
        .arg(arg!(--tui "Display fuzzing logs using the interactive terminal UI"))
        .arg(arg!(--"put-use-clear" "Use clearing functionality instead of recreating puts"))
        .arg(arg!(--"no-launcher" "Do not use the convenient launcher"))
        .arg(arg!(--"wo-bit" "Disable bit-level mutations"))
        .arg(arg!(--"wo-dy" "Disable DY mutations"))
        .subcommands(vec![
            Command::new("quick-experiment").about("Starts a new experiment and writes the results out"),
            Command::new("experiment").about("Starts a new experiment and writes the results out")
                .arg(arg!(-t --title <t> "Title of the experiment"))
                .arg(arg!(-d --description [d] "Description of the experiment"))
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
                .about("Executes a trace stored in a file. The exit code describes if more files are available for execution.")
                .arg(arg!(<inputs> "The file which stores a trace").num_args(1..))
                .arg(arg!(-n --number <n> "Amount of files to execute starting at index.").value_parser(value_parser!(usize)))
                .arg(arg!(-i --index <i> "Index of file to execute.").value_parser(value_parser!(usize)))
                .arg(arg!(-s --sort "Sort files in ascending order by the creation date before executing")),
            Command::new("execute-traces")
                .about("Executes traces stored in files.")
                .arg(arg!(<inputs> "The file which stores a trace").num_args(1..)),
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

pub fn main<S, PB>(title: S, put_registry: PutRegistry<PB>) -> ExitCode
where
    S: AsRef<str>,
    PB: ProtocolBehavior + Clone,
{
    let handle = match log4rs::init_config(config_default()) {
        Ok(handle) => handle,
        Err(err) => {
            eprintln!("error: failed to initialize logging: {err:?}");
            return ExitCode::FAILURE;
        }
    };

    let matches = create_app(title).get_matches();

    let first_core = "0".to_string();
    let core_definition = matches.get_one("cores").unwrap_or(&first_core);
    let num_cores = Cores::from_cmdline(core_definition.as_str())
        .unwrap()
        .ids
        .len();
    let port: u16 = *matches.get_one::<u16>("port").unwrap_or(&1337u16);
    let static_seed: Option<u64> = matches.get_one("seed").copied();
    let max_iters: Option<u64> = matches.get_one("max-iters").copied();
    let minimizer = matches.get_flag("minimizer");
    let tui = matches.get_flag("tui");
    let no_launcher = matches.get_flag("no-launcher");
    let put_use_clear = matches.get_flag("put-use-clear");
    let without_bit_level = matches.get_flag("wo-bit");
    let without_dy_mutations = matches.get_flag("wo-dy");

    log::info!("Git Version: {}", crate::GIT_REF);
    log::info!("Put Versions:");

    for (id, put) in put_registry.puts() {
        log::info!("({:?}) {}:", put.kind(), id);
        for (component, version) in put.versions() {
            log::info!("    {}: {}", component, version);
        }
    }

    asan_info();
    setup_asan_env();

    // Initialize global state

    let mut options: Vec<(String, String)> = Vec::new();
    if put_use_clear {
        options.push(("use_clear".to_string(), put_use_clear.to_string()));
    }

    let default_put = PutDescriptor::new(put_registry.default().name(), options);

    if let Some(_matches) = matches.subcommand_matches("seed") {
        if let Err(err) = seed(&put_registry) {
            log::error!("Failed to create seeds on disk: {:?}", err);
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
            log::error!("Failed to plot trace: {:?}", err);
            return ExitCode::FAILURE;
        }
    } else if let Some(matches) = matches.subcommand_matches("execute") {
        let inputs: ValuesRef<String> = matches.get_many("inputs").unwrap();
        let index: usize = *matches.get_one("index").unwrap_or(&0);

        let mut paths = inputs
            .flat_map(|input| {
                let input = PathBuf::from(input);

                if input.is_dir() {
                    fs::read_dir(input)
                        .expect("failed to read directory")
                        .map(|entry| entry.expect("failed to read path in directory").path())
                        .filter(|path| {
                            !path.file_name().unwrap().to_str().unwrap().starts_with('.')
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

        let n: usize = *matches.get_one("number").unwrap_or(&paths.len());

        let mut end_reached = false;

        let lookup_paths = if index < paths.len() {
            if index + n < paths.len() {
                &paths[index..index + n]
            } else {
                end_reached = true;
                &paths[index..]
            }
        } else {
            end_reached = true;
            // empty
            &paths[0..0]
        };

        log::info!("execute: found {} inputs", paths.len());
        log::info!(
            "execute: running on subset [{}..{}] ({} inputs)",
            index,
            index + n,
            lookup_paths.len()
        );

        let runner = Runner::new(
            put_registry.clone(),
            Spawner::new(put_registry).with_default(default_put),
        );

        for path in lookup_paths {
            log::info!("Executing: {}", path.display());
            execute(&runner, path);
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
            );
        }

        if end_reached {
            return ExitCode::FAILURE;
        } else {
            return ExitCode::SUCCESS;
        }
    } else if let Some(matches) = matches.subcommand_matches("execute-traces") {
        let inputs: ValuesRef<String> = matches.get_many("inputs").unwrap();

        let mut paths = inputs
            .flat_map(|input| {
                let input = PathBuf::from(input);

                if input.is_dir() {
                    fs::read_dir(input)
                        .expect("failed to read directory")
                        .map(|entry| entry.expect("failed to read path in directory").path())
                        .filter(|path| {
                            !path.file_name().unwrap().to_str().unwrap().starts_with('.')
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

        log::info!("execute: found {} inputs", paths.len());

        let runner = Runner::new(
            put_registry.clone(),
            Spawner::new(put_registry).with_default(default_put),
        );

        for path in paths {
            log::info!("Executing: {}", path.display());
            execute(&runner, path);
        }

        return ExitCode::SUCCESS;
    } else if let Some(matches) = matches.subcommand_matches("binary-attack") {
        let input: &String = matches.get_one("input").unwrap();
        let output: &String = matches.get_one("output").unwrap();

        if let Err(err) = binary_attack(input, output, &put_registry, default_put) {
            log::error!("Failed to create trace output: {:?}", err);
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

        let trace = Trace::<PB::ProtocolTypes>::from_file(input).unwrap();

        let mut options = vec![("port", port.as_str()), ("host", host)];

        if let Some(prog) = prog {
            options.push(("prog", prog));
        }

        if let Some(args) = args {
            options.push(("args", args));
        }

        if let Some(cwd) = cwd {
            options.push(("cwd", cwd));
        }

        let server = trace.descriptors[0].name;
        let put = PutDescriptor::new(TCP_PUT, options);
        let runner = Runner::new(
            put_registry.clone(),
            Spawner::new(put_registry).with_mapping(&[(server, put)]),
        );
        let mut context = runner.execute(trace).unwrap();

        let server = AgentName::first();
        let shutdown = context.find_agent_mut(server).unwrap().shutdown();
        log::info!("{}", shutdown);

        return ExitCode::SUCCESS;
    } else {
        let experiment_path = if let Some(matches) = matches.subcommand_matches("experiment") {
            let git_ref = "_".to_string();
            let title: &str = matches.get_one::<String>("title").unwrap_or(&git_ref);
            let experiments_root = PathBuf::new().join("experiments");
            let format_t = format_title(
                Some(title),
                None,
                &put_registry,
                without_bit_level,
                without_dy_mutations,
                put_use_clear,
                minimizer,
                num_cores,
            );
            let experiment_path = experiments_root.join(format_t.clone());
            assert!(
                !experiment_path.as_path().exists(),
                "Experiment already exists. Consider creating a new experiment."
            );

            let base_dec = format_t;
            let description: &String = matches.get_one("description").unwrap_or(&base_dec);
            if let Err(err) = write_experiment_markdown(
                &experiment_path,
                title,
                description,
                &put_registry,
                matches,
                port,
            ) {
                log::error!("Failed to write readme: {:?}", err);
                return ExitCode::FAILURE;
            }

            experiment_path
        } else if let Some(_matches) = matches.subcommand_matches("quick-experiment") {
            let description = "No Description, because this is a quick experiment.";
            let experiments_root = PathBuf::from("experiments");

            let title = format_title(
                None,
                None,
                &put_registry,
                without_bit_level,
                without_dy_mutations,
                put_use_clear,
                minimizer,
                num_cores,
            );

            let mut experiment_path = experiments_root.join(&title);

            let mut i = 1;
            while experiment_path.as_path().exists() {
                let title = format_title(
                    None,
                    Some(i),
                    &put_registry,
                    without_bit_level,
                    without_dy_mutations,
                    put_use_clear,
                    minimizer,
                    num_cores,
                );
                experiment_path = experiments_root.join(title);
                i += 1;
            }

            if let Err(err) = write_experiment_markdown(
                &experiment_path,
                title,
                description,
                &put_registry,
                &matches,
                port,
            ) {
                log::error!("Failed to write readme: {:?}", err);
                return ExitCode::FAILURE;
            }
            experiment_path
        } else {
            PathBuf::from(".")
        };

        if let Err(err) = fs::create_dir_all(&experiment_path) {
            log::error!("Failed to create directories: {:?}", err);
            return ExitCode::FAILURE;
        }

        let mut config = FuzzerConfig {
            initial_corpus_dir: PathBuf::from("./seeds"),
            static_seed,
            max_iters,
            core_definition: core_definition.to_string(),
            corpus_dir: experiment_path.join("corpus"),
            objective_dir: experiment_path.join("objective"),
            broker_port: port,
            stats_file: experiment_path.join("stats.json"),
            log_file: experiment_path.join("tlspuffin.log"),
            minimizer,
            mutation_stage_config: Default::default(),
            mutation_config: Default::default(),
            tui,
            no_launcher,
        };

        if without_bit_level {
            config.mutation_config.with_bit_level = false;
        }
        if without_dy_mutations {
            config.mutation_config.with_dy = false;
        }

        if let Err(err) = start::<PB>(&put_registry, config, handle) {
            match err {
                libafl::Error::ShuttingDown => {
                    log::info!("\nFuzzing stopped by user. Good Bye.");
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
    let trace = postcard::from_bytes::<Trace<PB::ProtocolTypes>>(&buffer)?;

    // All-in-one tree
    write_graphviz(
        format!("{}_{}.{}", output_prefix, "all", format).as_str(),
        format,
        trace.dot_graph(is_tree).as_str(),
    )
    .expect("Failed to generate graph.");

    if is_multiple {
        for (i, subgraph) in trace.dot_subgraphs(true).iter().enumerate() {
            let wrapped_subgraph = format!("strict digraph \"\" {{ splines=true; {subgraph} }}");
            write_graphviz(
                format!("{output_prefix}_{i}.{format}").as_str(),
                format,
                wrapped_subgraph.as_str(),
            )
            .expect("Failed to generate graph.");
        }
    }

    log::info!("Created plots");
    Ok(())
}

fn seed<PB: ProtocolBehavior>(
    _put_registry: &PutRegistry<PB>,
) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all("./seeds")?;
    for (trace, name) in PB::create_corpus() {
        trace.to_file(format!("./seeds/{name}.trace"))?;
    }

    log::info!("Generated seed traces into the directory ./seeds");
    Ok(())
}

fn execute<PB: ProtocolBehavior, P: AsRef<Path>>(runner: &Runner<PB>, input: P) {
    let trace = if let Ok(t) = Trace::<PB::ProtocolTypes>::from_file(input.as_ref()) {
        t
    } else {
        log::error!("Invalid trace file {}", input.as_ref().display());
        return;
    };

    log::info!("Agents: {:?}", &trace.descriptors);

    // When generating coverage a crash means that no coverage is stored
    // By executing in a fork, even when that process crashes, the other executed code will still
    // yield coverage
    let status = ForkedRunner::new(runner).execute(trace);

    match status {
        Ok(s) => log::info!("execution finished with status {s:?}"),
        Err(reason) => panic!("failed to execute trace: {reason}"),
    }
}

fn binary_attack<PB: ProtocolBehavior>(
    input: &str,
    output: &str,
    put_registry: &PutRegistry<PB>,
    default_put: impl Into<PutDescriptor>,
) -> Result<(), Box<dyn std::error::Error>> {
    let spawner = Spawner::new(put_registry.clone()).with_default(default_put);
    let ctx = TraceContext::new(spawner);
    let trace = Trace::<PB::ProtocolTypes>::from_file(input)?;

    log::info!("Agents: {:?}", &trace.descriptors);

    let mut f = File::create(output).expect("Unable to create file");

    for step in trace.steps {
        match step.action {
            Action::Input(input) => {
                if let Ok(evaluated) = input.recipe.evaluate(&ctx) {
                    f.write_all(&evaluated).expect("Unable to write data");
                } else {
                    log::error!("Recipe is not a `ProtocolMessage` or `OpaqueProtocolMessage`!");
                }
            }
            Action::Output(_) => {}
        }
    }
    Ok(())
}
