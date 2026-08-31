use std::fmt::Display;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::{fs, io};

use chrono::Local;
use clap::ArgMatches;
use itertools::Itertools;
use libafl_bolts::bolts_prelude::Cores;
use puffin_build::puffin;

use crate::fuzzer::config::{FuzzerConfig, MutationStageConfig};
use crate::fuzzer::mutations::MutationConfig;
use crate::protocol::ProtocolBehavior;
use crate::put_registry::PutRegistry;

#[must_use]
pub fn format_title<PB: ProtocolBehavior>(
    title: Option<&str>,
    index: Option<usize>,
    put_registry: &PutRegistry<PB>,
    fuzzer_config: &FuzzerConfig,
) -> String {
    let FuzzerConfig {
        mutation_config,
        mutation_stage_config,
        core_definition,
        put_options,
        minimizer,
        ..
    } = fuzzer_config;
    let MutationStageConfig {
        with_truncation, ..
    } = mutation_stage_config;
    let MutationConfig {
        with_bit_level,
        with_dy,
        with_focus,
        ..
    } = mutation_config;
    let num_cores = Cores::from_cmdline(core_definition.as_str())
        .unwrap()
        .ids
        .len();

    let date = Local::now().format("%Y-%m-%d");
    let hour = Local::now().format("%H-%M-%S");
    let with_bit_level = if *with_bit_level { "_with-bit" } else { "" };
    let without_dy_mutations = if !*with_dy { "_wo-dy" } else { "" };
    let without_focus = if !*with_focus { "_wo-focus" } else { "" };
    let with_truncation = if *with_truncation { "_with-trunc" } else { "" };
    let minimizer = if *minimizer { "_with_minimizer" } else { "" };
    let option_string = format!(
        "_put-options-{}",
        put_options
            .iter()
            .map(|(key, val)| format!("{}:{}", key, val))
            .join("-")
    );
    let with_put_options = if !put_options.is_empty() {
        option_string.as_str()
    } else {
        ""
    };
    let default_put: &str = &put_registry
        .default()
        .versions()
        .last()
        .unwrap()
        .1
        .split_whitespace()
        .join("-");
    format!(
        "{date}\
        --{default_put}-{num_cores}c{with_bit_level}{without_dy_mutations}{without_focus}{with_truncation}{minimizer}{with_put_options}\
        {title}--{hour}--{index}",
        date = date,
        title = title.unwrap_or(&puffin::git_ref().unwrap_or_default()),
        index = index.unwrap_or(0)
    )
}

pub fn write_experiment_markdown<PB: ProtocolBehavior>(
    directory: &Path,
    title: impl Display,
    description_text: impl Display,
    put_registry: &PutRegistry<PB>,
    commands: &ArgMatches,
    port: u16,
) -> Result<String, io::Error> {
    let full_description = format!(
        "# Experiment: {title}\n\
                * PUT Versions: {put_versions}\n\
                * Default PUT: {default_put}\n\
                * Date: {date}\n\
                * Git Ref: {git_ref}\n\
                * Git Commit: {git_msg}\n\
                * Launched with: {command:?}\n\
                * Port: {port}\n\
                * Log: [tlspuffin.log](./tlspuffin.log)\n\n\
                {description}\n",
        title = &title,
        default_put = &put_registry
            .default()
            .versions()
            .last()
            .unwrap()
            .1
            .split_whitespace()
            .join("-"),
        put_versions = put_registry
            .puts()
            .map(|(n, p)| format!(
                "{} ({})",
                n,
                p.versions()
                    .into_iter()
                    .map(|(c, v)| format!("{c} ({v})"))
                    .join(" ")
            ))
            .join(", "),
        date = Local::now().to_rfc3339(),
        git_ref = puffin::git_ref().as_deref().unwrap_or("unknown"),
        git_msg = puffin::git_msg().as_deref().unwrap_or("unknown"),
        command = commands,
        description = description_text
    );

    fs::create_dir_all(directory)?;

    let mut file = File::create(directory.join("README.md")).unwrap();

    file.write_all(full_description.as_bytes()).unwrap();
    Ok(full_description)
}
