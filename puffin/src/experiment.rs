use std::{fmt::Display, fs, fs::File, io, io::Write, path::Path};

use chrono::Local;
use clap::ArgMatches;

use crate::{protocol::ProtocolBehavior, put_registry::PutRegistry, GIT_MSG, GIT_REF};

pub fn format_title(title: Option<&str>, index: Option<usize>) -> String {
    let date = Local::now().format("%Y-%m-%d-%H%M%S");
    format!(
        "{date}-{title}-{index}",
        date = date,
        title = title.unwrap_or(GIT_REF),
        index = index.unwrap_or(0)
    )
}

pub fn write_experiment_markdown<PB: ProtocolBehavior>(
    directory: &Path,
    title: impl Display,
    description_text: impl Display,
    put_registry: &PutRegistry<PB>,
    commands: &ArgMatches
) -> Result<String, io::Error> {
    let full_description = format!(
        "# Experiment: {title}\n\
                * PUT Versions: {put_versions}\n\
                * Date: {date}\n\
                * Git Ref: {git_ref}\n\
                * Git Commit: {git_msg}\n\
                * Launched with: {command:?}\n\
                * Log: [tlspuffin.log](./tlspuffin.log)\n\n\
                {description}\n",
        title = &title,
        put_versions = put_registry.version_strings().join(", "),
        date = Local::now().to_rfc3339(),
        git_ref = GIT_REF,
        git_msg = GIT_MSG,
        command=commands,
        description = description_text
    );

    fs::create_dir_all(directory)?;

    let mut file = File::create(directory.join("README.md")).unwrap();

    file.write_all(full_description.as_bytes()).unwrap();
    Ok(full_description)
}
