use std::env;
use std::path::Path;
use std::str::FromStr;

use log::LevelFilter;
use log4rs::append::console::ConsoleAppender;
use log4rs::append::rolling_file::policy::compound::roll::fixed_window::FixedWindowRoller;
use log4rs::append::rolling_file::policy::compound::trigger::size::SizeTrigger;
use log4rs::append::rolling_file::policy::compound::CompoundPolicy;
use log4rs::append::rolling_file::RollingFileAppender;
use log4rs::config::{load_config_file, Appender, Root};
use log4rs::encode::pattern::PatternEncoder;
use log4rs::Config;

pub fn config_default() -> Config {
    Config::builder()
        .appender(appender_stderr("stderr"))
        .appender(appender_tofile("tofile", "log/stderr.log"))
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
    let size_limit = 100 * 1024 * 1024; // 5MB as max log file size to roll
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
        .unwrap_or(LevelFilter::Warn)
}
