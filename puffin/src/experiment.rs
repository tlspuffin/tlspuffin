use std::fmt::Display;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::{fs, io};

use chrono::Local;
use clap::ArgMatches;
use itertools::Itertools;
use puffin_build::puffin;

use crate::protocol::ProtocolBehavior;
use crate::put_registry::PutRegistry;

#[must_use]
pub fn format_title<PB: ProtocolBehavior>(
    title: Option<&str>,
    index: Option<usize>,
    put_registry: &PutRegistry<PB>,
    without_bit_level: bool,
    without_dy_mutations: bool,
    put_use_clear: bool,
    minimizer: bool,
    num_cores: usize,
) -> String {
    let date = Local::now().format("%Y-%m-%d");
    let hour = Local::now().format("%H-%M-%S");
    let without_bit_level = if without_bit_level { "_wo-bit" } else { "" };
    let without_dy_mutations = if without_dy_mutations { "_wo-dy" } else { "" };
    let put_use_clear = if put_use_clear { "_put-use-clear" } else { "" };
    let minimizer = if minimizer { "_minimizer" } else { "" };
    let default_put: &str = &put_registry
        .default()
        .versions()
        .last()
        .unwrap()
        .1
        .trim()
        .split_whitespace()
        .join("-");
    format!(
        "{date}\
        --{default_put}-{num_cores}c{without_bit_level}{without_dy_mutations}{put_use_clear}{minimizer}__\
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
                * Date: {date}\n\
                * Git Ref: {git_ref}\n\
                * Git Commit: {git_msg}\n\
                * Launched with: {command:?}\n\
                * Port: {port}\n\
                * Log: [tlspuffin.log](./tlspuffin.log)\n\n\
                {description}\n",
        title = &title,
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
