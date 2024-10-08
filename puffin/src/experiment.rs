use std::fmt::Display;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::{fs, io};

use chrono::Local;
use itertools::Itertools;

use crate::protocol::ProtocolBehavior;
use crate::put_registry::PutRegistry;
use crate::{GIT_MSG, GIT_REF};

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
) -> Result<String, io::Error> {
    let full_description = format!(
        "# Experiment: {title}\n\
                * PUT Versions: {put_versions}\n\
                * Date: {date}\n\
                * Git Ref: {git_ref}\n\
                * Git Commit: {git_msg}\n\
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
                    .map(|(c, v)| format!("{} ({})", c, v))
                    .join(" ")
            ))
            .join(", "),
        date = Local::now().to_rfc3339(),
        git_ref = GIT_REF,
        git_msg = GIT_MSG,
        description = description_text
    );

    fs::create_dir_all(directory)?;

    let mut file = File::create(directory.join("README.md")).unwrap();

    file.write_all(full_description.as_bytes()).unwrap();
    Ok(full_description)
}
