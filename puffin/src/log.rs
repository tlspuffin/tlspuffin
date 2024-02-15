use std::{env, path::PathBuf, str::FromStr};

use log::LevelFilter;
use log4rs::{
    append::{console::ConsoleAppender, file::FileAppender, Append},
    config::{Appender, Root},
    encode::pattern::PatternEncoder,
    Config,
};

fn create_config(
    default_level: LevelFilter,
    appender_name: &'static str,
    appender: Box<dyn Append>,
) -> Config {
    let level = env::var("RUST_LOG")
        .ok()
        .and_then(|level| LevelFilter::from_str(&level).ok())
        .unwrap_or(default_level);

    Config::builder()
        .appender(Appender::builder().build(appender_name, appender))
        .build(Root::builder().appender(appender_name).build(level))
        .unwrap()
}

pub fn create_stderr_config(default_level: LevelFilter) -> Config {
    let stderr = ConsoleAppender::builder()
        .target(log4rs::append::console::Target::Stderr)
        .encoder(Box::new(PatternEncoder::new(
            "{h({d(%Y-%m-%dT%H:%M:%S%Z)}\t{m}{n})}",
        )))
        .build();

    create_config(default_level, "stderr", Box::new(stderr))
}

pub fn create_file_config(default_level: LevelFilter, log_path: &PathBuf) -> Config {
    let file_appender = FileAppender::builder()
        .encoder(Box::new(PatternEncoder::new("{d}\t{l}\t{m}{n}")))
        .build(log_path)
        .unwrap();

    create_config(default_level, "file", Box::new(file_appender))
}
