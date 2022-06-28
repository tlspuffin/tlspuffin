use std::{
    env,
    ffi::{CStr, CString},
    fs,
    fs::File,
    io::{Read, Write},
    path::PathBuf,
    ptr,
};

use clap::{arg, crate_authors, crate_name, crate_version, Command};
use log::{info, LevelFilter};
use log4rs::{
    append::{console::ConsoleAppender, file::FileAppender},
    config::{Appender, Root},
    encode::{json::JsonEncoder, pattern::PatternEncoder},
    Config,
};
use tlspuffin::{
    experiment::*,
    fuzzer::{start, FuzzerConfig},
    graphviz::write_graphviz,
    log::create_stdout_config,
    put_registry::PUT_REGISTRY,
    tls::seeds::create_corpus,
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

unsafe extern "C" fn iter(
    info: *mut libc::dl_phdr_info,
    _size: libc::size_t,
    _data: *mut libc::c_void,
) -> libc::c_int {
    let library_name = CStr::from_ptr((*info).dlpi_name).to_str().unwrap();
    if library_name.contains("libasan") {
        1
    } else {
        0
    }
}

extern "C" {
    fn __asan_default_options() -> *mut libc::c_char;
}

fn asan_info() {
    unsafe {
        if libc::dl_iterate_phdr(Some(iter), ptr::null_mut()) > 0 {
            info!("Running with ASAN support.",)
        } else {
            info!("Running WITHOUT ASAN support.")
        }

        info!(
            "ASAN env options: {}",
            env::var("ASAN_OPTIONS").unwrap_or_default(),
        );

        info!(
            "ASAN default options: {}",
            CStr::from_ptr(__asan_default_options()).to_str().unwrap()
        );

        info!("Appending default options to env options..");
        env::set_var(
            "ASAN_OPTIONS",
            format!(
                "{}:{}",
                env::var("ASAN_OPTIONS").unwrap_or_default(),
                CStr::from_ptr(__asan_default_options()).to_str().unwrap(),
            ),
        );
    }
}

fn main() {
    let log_handle = log4rs::init_config(create_stdout_config()).unwrap();

    let matches = create_app().get_matches();

    let core_definition = matches.value_of("cores").unwrap_or("0");
    let port: u16 = matches.value_of_t("port").unwrap_or(1337);
    let static_seed: Option<u64> = matches.value_of_t("seed").ok();
    let max_iters: Option<u64> = matches.value_of_t("max-iters").ok();
    let minimizer = matches.is_present("minimizer");
    let monitor = matches.is_present("monitor");

    info!("Version: {}", tlspuffin::GIT_REF);
    info!("Put Versions:");
    for version in PUT_REGISTRY.version_strings() {
        info!("{}", version);
    }

    asan_info();

    if let Some(_matches) = matches.subcommand_matches("seed") {
        fs::create_dir_all("./seeds").unwrap();
        for (trace, name) in create_corpus() {
            let mut file = File::create(format!("./seeds/{}.trace", name)).unwrap();
            let buffer = postcard::to_allocvec(&trace).unwrap();
            file.write_all(&buffer).unwrap();
            info!("Generated seed traces into the directory ./corpus")
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
        let trace = postcard::from_bytes::<Trace>(&buffer).unwrap();

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

        info!("Created plots")
    } else if let Some(matches) = matches.subcommand_matches("execute") {
        // Parse arguments
        let input = matches.value_of("input").unwrap();

        let mut input_file = File::open(input).unwrap();

        // Read trace file
        let mut buffer = Vec::new();
        input_file.read_to_end(&mut buffer).unwrap();
        let trace = postcard::from_bytes::<Trace>(&buffer).unwrap();

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

            write_experiment_markdown(&experiment_path, title, description).unwrap();
            experiment_path
        } else {
            PathBuf::from(".")
        };

        fs::create_dir_all(&experiment_path).unwrap();

        start(
            FuzzerConfig {
                initial_corpus_dir: experiment_path.join("seeds"),
                static_seed,
                max_iters,
                core_definition: core_definition.to_string(),
                corpus_dir: experiment_path.join("corpus"),
                objective_dir: experiment_path.join("objective"),
                broker_port: port,
                monitor_file: experiment_path.join("stats.json"),
                minimizer,
                mutation_stage_config: Default::default(),
                mutation_config: Default::default(),
                monitor,
            },
            log_handle,
        );
    }
}
