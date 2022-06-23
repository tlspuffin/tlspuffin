use std::path::PathBuf;

use log::LevelFilter;
use log4rs::{
    append::{console::ConsoleAppender, file::FileAppender},
    config::{Appender, Root},
    encode::{json::JsonEncoder, pattern::PatternEncoder},
    Config,
};

pub fn create_stdout_config() -> Config {
    let stdout = ConsoleAppender::builder()
        .encoder(Box::new(PatternEncoder::new(
            "{h({d(%Y-%m-%dT%H:%M:%S%Z)}\t{m}{n})}",
        )))
        .build();
    Config::builder()
        .appender(Appender::builder().build("stdout", Box::new(stdout)))
        .build(
            Root::builder()
                .appenders(vec!["stdout"])
                .build(LevelFilter::Info),
        )
        .unwrap()
}

pub fn create_file_config(log_path: &PathBuf) -> Config {
    let file_appender = FileAppender::builder()
        .encoder(Box::new(JsonEncoder::new()))
        .build(&log_path)
        .unwrap();

    Config::builder()
        .appender(Appender::builder().build("file", Box::new(file_appender)))
        .build(
            Root::builder()
                .appenders(vec!["file"])
                .build(LevelFilter::Info),
        )
        .unwrap()
}
