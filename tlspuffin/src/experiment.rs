use std::{fmt::Display, fs, fs::File, io, io::Write, path::Path, process::Command};

use chrono::Local;

use crate::put_registry::PUT_REGISTRY;

pub fn format_title(title: Option<&str>, index: Option<usize>) -> String {
    let date = Local::now().format("%Y-%m-%d-%H%M%S");
    format!(
        "{date}-{title}-{index}",
        date = date,
        title = title
            .map(|title| title.to_string())
            .unwrap_or_else(|| get_git_ref().unwrap()),
        index = index.unwrap_or(0)
    )
}

pub fn get_git_ref() -> Result<String, io::Error> {
    let output = Command::new("git").args(&["rev-parse", "HEAD"]).output()?;
    Ok(String::from_utf8(output.stdout)
        .unwrap_or_else(|_| "unknown".to_string())
        .trim()
        .to_string())
}

pub fn get_git_msg() -> Result<String, io::Error> {
    let output = Command::new("git")
        .args(&["log", "-1", "--pretty=%B"])
        .output()?;
    Ok(String::from_utf8(output.stdout)
        .unwrap_or_else(|_| "unknown".to_string())
        .trim()
        .to_string())
}

pub fn write_experiment_markdown(
    directory: &Path,
    title: impl Display,
    description_text: impl Display,
) -> Result<String, io::Error> {
    let git_ref = get_git_ref()?;
    let git_msg = get_git_msg()?;
    let full_description = format!(
        "# Experiment: {title}\n\
                * PUT Versions: {put_versions}\n\
                * Date: {date}\n\
                * Git Ref: {git_ref}\n\
                * Git Commit: {git_msg}\n\
                * Log: [tlspuffin-log.json](./tlspuffin-log.json)\n\n\
                {description}\n",
        title = &title,
        put_versions = PUT_REGISTRY.versions(),
        date = Local::now().to_rfc3339(),
        git_ref = git_ref,
        git_msg = git_msg,
        description = description_text
    );

    fs::create_dir_all(directory)?;

    let mut file = File::create(directory.join("README.md")).unwrap();

    file.write_all(full_description.as_bytes()).unwrap();
    Ok(full_description)
}
