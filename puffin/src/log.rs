use std::env;
use std::path::Path;
use std::str::FromStr;

use log::LevelFilter;
use log4rs::append::console::ConsoleAppender;
use log4rs::append::rolling_file::policy::compound::roll::fixed_window::FixedWindowRoller;
use log4rs::append::rolling_file::policy::compound::trigger::size::SizeTrigger;
use log4rs::append::rolling_file::policy::compound::CompoundPolicy;
use log4rs::append::rolling_file::RollingFileAppender;
use log4rs::config::{load_config_file, Appender, Logger, Root};
use log4rs::encode::pattern::PatternEncoder;
use log4rs::filter::threshold::ThresholdFilter;
use log4rs::Config;

pub fn config_default(base_directory: &Path) -> Config {
    Config::builder()
        .appender(appender_stderr("stderr"))
        .appender(appender_tofile(
            "tofile",
            base_directory.join("stats_puffin_main_broker.log"),
        ))
        .build(
            Root::builder()
                .appender("stderr")
                .appender("tofile")
                .build(log_level()),
        )
        .unwrap()
}

pub fn load_fuzzing_client() -> Config {
    load_config_file("client_log_config.yml", Default::default()).unwrap()
}

fn appender_stderr<S>(name: S) -> Appender
where
    S: AsRef<str>,
{
    Appender::builder().build(
        name.as_ref(),
        Box::new(
            ConsoleAppender::builder()
                .target(log4rs::append::console::Target::Stderr)
                .encoder(Box::new(PatternEncoder::new(
                    "{h({d(%Y-%m-%dT%H:%M:%S%Z)}\t{m}{n})}",
                )))
                .build(),
        ),
    )
}

fn appender_tofile<S, P>(name: S, log_path: P) -> Appender
where
    S: AsRef<str>,
    P: AsRef<Path>,
{
    let window_size = 20; // log0, log1, log2, .., log19
    let fixed_window_roller = FixedWindowRoller::builder()
        .build("log{}", window_size)
        .unwrap();
    let size_limit = 100 * 1024 * 1024; // 100MB as max log file size to roll
    let size_trigger = SizeTrigger::new(size_limit);
    let compound_policy =
        CompoundPolicy::new(Box::new(size_trigger), Box::new(fixed_window_roller));

    Appender::builder().build(
        name.as_ref(),
        Box::new(
            RollingFileAppender::builder()
                .encoder(Box::new(PatternEncoder::new("{d}\t{l}\t{m}{n}")))
                .build(log_path, Box::new(compound_policy))
                .unwrap(),
        ),
    )
}

fn log_level() -> LevelFilter {
    // TODO allow fined-grain configuration of the log level
    //
    // At least for:
    //   - libafl* during fuzzing
    //   - tlspuffin's packages
    //   - tlspuffin's packages during fuzzing (libafl client)
    //
    // [MM] Maybe also allow package-level control like env_logger?
    env::var("RUST_LOG")
        .ok()
        .and_then(|level| LevelFilter::from_str(&level).ok())
        .unwrap_or(LevelFilter::Info)
}

/// Size at which the log files of a fuzzing run are rolled, for all its clients together
pub const RUN_LOG_SIZE: u64 = 10 * 1024 * 1024; // 10 MB

/// Size at which each client of a run with `clients` clients rolls its own log files: together, as
/// much as one client's files before
pub fn client_log_size(clients: usize) -> u64 {
    RUN_LOG_SIZE / clients.max(1) as u64
}

/// Log configuration of a fuzzing client of an experiment
///
/// `base_directory` is the client's own folder (`log/client-<id>/`, the id the launcher gives it,
/// from 1, as in the stats): each client writes and rolls its own files. When the clients shared
/// the files, each one rolled them on its own and kept writing to a file another client had rolled
/// away: those lines were lost.
pub fn set_experiment_fuzzing_client(
    base_directory: &Path,
    level_filter: LevelFilter,
    max_log_size: u64,
) -> Config {
    // Common encoder
    let encoder = Box::new(PatternEncoder::new("{d}\t{l}\t{m}{n}"));

    // Console appender
    let stdout = ConsoleAppender::builder().build();

    // Helper to build a rolling file appender
    let build_rolling_appender = |path: &str, pattern: &str, filter: Option<LevelFilter>| {
        let trigger = Box::new(SizeTrigger::new(max_log_size));
        let roller = Box::new(
            FixedWindowRoller::builder()
                .base(1)
                .build(base_directory.join(pattern).to_str().unwrap(), 20)
                .unwrap(),
        );

        let policy = Box::new(CompoundPolicy::new(trigger, roller));
        let rfa = RollingFileAppender::builder()
            .encoder(encoder.clone())
            .build(base_directory.join(path), policy)
            .unwrap();
        if let Some(filter) = filter {
            Appender::builder()
                .filter(Box::new(ThresholdFilter::new(filter)))
                .build(path, Box::new(rfa))
        } else {
            Appender::builder().build(path, Box::new(rfa))
        }
    };

    let fuzzer_log = build_rolling_appender("fuzzer.log", "fuzzer.{}.gz", None);
    let harness_log = build_rolling_appender("harness.log", "harness.{}.gz", None);
    let info_log = build_rolling_appender("info.log", "info.{}.gz", Some(LevelFilter::Info));
    let warn_log = build_rolling_appender("warn.log", "warn.{}.gz", Some(LevelFilter::Warn));
    let error_log = build_rolling_appender("error.log", "error.{}.gz", Some(LevelFilter::Error));

    let config = Config::builder()
        // appenders
        .appender(Appender::builder().build("stdout", Box::new(stdout)))
        .appender(fuzzer_log)
        .appender(harness_log)
        .appender(info_log)
        .appender(warn_log)
        .appender(error_log);

    let mut root_appenders = vec!["info.log", "warn.log", "error.log"];
    // Specific appenders and loggers for verbose modes (when RUST_LOG is set strictly more verbose
    // than INFO)
    let config = if level_filter >= LevelFilter::Debug {
        root_appenders.push("debug.log");
        let debug_log =
            build_rolling_appender("debug.log", "debug.{}.gz", Some(LevelFilter::Debug));
        config.appender(debug_log).logger(
            Logger::builder()
                .appenders(vec!["debug.log"])
                .additive(true)
                .build("debug", LevelFilter::Debug),
        )
    } else {
        config
    };

    let config = if level_filter >= LevelFilter::Trace {
        root_appenders.push("trace.log");
        let trace_log =
            build_rolling_appender("trace.log", "trace.{}.gz", Some(LevelFilter::Trace));
        config.appender(trace_log).logger(
            Logger::builder()
                .appenders(vec!["trace.log"])
                .additive(true)
                .build("trace", LevelFilter::Trace),
        )
    } else {
        config
    };

    // loggers
    config
        .logger(Logger::builder()
            .appenders(vec!["harness.log"])
            .additive(true)
            .build("puffin::harness", level_filter)) // Change to `Trace` for full verbosity
        .logger(Logger::builder()
            .appenders(vec!["fuzzer.log"])
            .additive(true)
            .build("puffin::fuzzer", level_filter))
        // Root logger
        .build(
            Root::builder()
                .appenders(root_appenders)
                .build(log_level()),
        )
        .unwrap()
}

#[cfg(test)]
mod tests {
    use log::{Level, Record};

    use super::*;

    #[test]
    fn client_log_size_shares_the_run_size() {
        assert_eq!(client_log_size(1), RUN_LOG_SIZE);
        assert_eq!(client_log_size(8), RUN_LOG_SIZE / 8);
        assert_eq!(client_log_size(0), RUN_LOG_SIZE);
    }

    /// Each client writes and rolls its log files in its own folder
    #[test]
    fn client_logs_roll_in_their_folder() {
        let log_folder =
            std::env::temp_dir().join(format!("puffin-client-logs-{}", std::process::id()));
        let client_folder = log_folder.join("client-3");
        let config = set_experiment_fuzzing_client(&client_folder, LevelFilter::Info, 1024);
        let error_log = config
            .appenders()
            .iter()
            .find(|appender| appender.name() == "error.log")
            .unwrap();
        let line = "x".repeat(100);
        // 32 lines roll the file several times; the one after them opens a new live file (a roll
        // removes it until the next line)
        for _ in 0..33 {
            error_log
                .appender()
                .append(
                    &Record::builder()
                        .args(format_args!("{line}"))
                        .level(Level::Error)
                        .build(),
                )
                .unwrap();
        }

        assert!(client_folder.join("error.log").exists());
        assert!(client_folder.join("error.1.gz").exists());
        assert!(!log_folder.join("error.log").exists());
        assert!(!log_folder.join("error.1.gz").exists());
        std::fs::remove_dir_all(&log_folder).unwrap();
    }
}
