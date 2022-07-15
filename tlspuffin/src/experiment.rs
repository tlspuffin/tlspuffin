use std::{env, fmt::Display, fs, fs::File, io, io::Write, path::Path};
use std::ops::Add;
use itertools::Itertools;

use chrono::Local;
use serde::de::Unexpected::Str;

use crate::{put_registry::PUT_REGISTRY, GIT_MSG, GIT_REF, put_registry};

pub fn format_title(title: Option<&str>, index: Option<usize>) -> String {
    let date = Local::now().format("%Y-%m-%d-%H%M%S");
    format!(
        "{date}-{title}-{index}",
        date = date,
        title = title.unwrap_or(GIT_REF),
        index = index.unwrap_or(0)
    )
}

pub fn write_experiment_markdown(
    directory: &Path,
    title: impl Display,
    description_text: impl Display,
) -> Result<String, io::Error> {
    let mut cargo_features = String::new().push_str("TODO"); // TODO: Failed to find a way to access the list of features used to build this binary
        let full_description = format!(
            "# Experiment: {title}\n\
                * Enabled PUTs: {put_versions}\n\
                * Current PUT: {current_put:#?}\n\
                * Date: {date}\n\
                * Git Ref: {git_ref}\n\
                * Git Commit: {git_msg}\n\
                * Log: [tlspuffin-log.json](./tlspuffin-log.json)\n\
                * Enabled cargo features: {:?}\n\n
                {description}\n",
            cargo_features,
            title = &title,
            put_versions = PUT_REGISTRY.version_strings().join(", "),
            date = Local::now().to_rfc3339(),
            git_ref = GIT_REF,
            git_msg = GIT_MSG,
            description = description_text,
            current_put = put_registry::current_put()
        );

        fs::create_dir_all(directory)?;

        let mut file = File::create(directory.join("README.md")).unwrap();

        file.write_all(full_description.as_bytes()).unwrap();
        Ok(full_description)
}