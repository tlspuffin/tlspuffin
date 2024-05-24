use std::{env, path::Path, str::FromStr};

use log::LevelFilter;
use log4rs::{
    self,
    append::{console::ConsoleAppender, file::FileAppender},
    config::{Appender, Logger, Root},
    encode::pattern::PatternEncoder,
    Config,
};

pub fn config_default() -> log4rs::Config {
    Config::builder()
        .appender(appender_stderr("stderr"))
        .build(Root::builder().appender("stderr").build(log_level()))
        .unwrap()
}

pub fn config_fuzzing<P>(path: P) -> log4rs::Config
where
    P: AsRef<Path>,
{
    Config::builder()
        .appender(appender_stderr("stderr"))
        .appender(appender_tofile("tofile", path))
        .logger(
            Logger::builder()
                .appender("tofile")
                .additive(false)
                .build("libafl", log_level()),
        )
        .build(Root::builder().appender("stderr").build(log_level()))
        .unwrap()
}

pub fn config_fuzzing_client<P>(path: P) -> log4rs::Config
where
    P: AsRef<Path>,
{
    let level = if log_level() > log::LevelFilter::Warn {
        log::LevelFilter::Warn
    } else {
        log_level()
    };

    Config::builder()
        .appender(appender_stderr("stderr"))
        .appender(appender_tofile("tofile", path))
        .build(Root::builder().appender("tofile").build(level))
        .unwrap()
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
    Appender::builder().build(
        name.as_ref(),
        Box::new(
            FileAppender::builder()
                .encoder(Box::new(PatternEncoder::new("{d}\t{l}\t{m}{n}")))
                .build(log_path)
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
