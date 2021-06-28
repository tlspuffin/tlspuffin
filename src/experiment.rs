use std::fmt::Display;
use std::fs::File;
use std::io;
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;
use std::string::FromUtf8Error;

use chrono::Utc;

use crate::openssl_binding;

pub fn get_git_ref() -> Result<String, io::Error> {
    let output = Command::new("git").args(&["rev-parse", "HEAD"]).output()?;
    Ok(String::from_utf8(output.stdout).unwrap_or("unknown".to_string()).trim().to_string())
}

pub fn get_git_msg() -> Result<String, io::Error> {
    let output = Command::new("git").args(&["log", "-i", "--pretty=%B"]).output()?;
    Ok(String::from_utf8(output.stdout).unwrap_or("unknown".to_string()).trim().to_string())
}

pub fn write_experiment_markdown(
    directory: &PathBuf,
    title: impl Display,
    description_text: impl Display,
) -> Result<String, io::Error> {
    let git_ref = get_git_ref()?;
    let git_msg = get_git_msg()?;
    let full_description = format!(
        "# Experiment: {title}\n\
                * OpenSSL: {openssl_version}\n\
                * Date: {date}\n\
                * Git Ref: {git_ref}\n\
                * Git Commit: {git_msg}\n\
                * Log: [tlspuffin-log.json](./tlspuffin-log.json)\n\n\
                {description}\n",
        title = &title,
        openssl_version = openssl_binding::openssl_version(),
        date = Utc::now().to_rfc3339(),
        git_ref = git_ref,
        git_msg = git_msg,
        description = description_text
    );

    let mut file = File::create(directory.join("README.md")).unwrap();

    file.write_all(full_description.as_bytes()).unwrap();
    Ok(full_description)
}
