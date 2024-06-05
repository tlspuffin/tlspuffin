use std::process::Command;

pub fn version() -> String {
    String::from(env!("CARGO_PKG_VERSION"))
}

pub fn full_version() -> String {
    let git_ref_str = git_ref()
        .map(|r| format!("+git.{r:.12}"))
        .unwrap_or_default();

    format!("{version}{git_ref_str}", version = version())
}

pub fn project_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("invalid CARGO_MANIFEST_DIR")
        .to_path_buf()
}

pub fn git_ref() -> Option<String> {
    Command::new("git")
        .arg("-C")
        .arg(project_dir())
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .and_then(|output| {
            if output.status.success() {
                Some(output)
            } else {
                None
            }
        })
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|git_ref| git_ref.trim().to_string())
}

pub fn git_msg() -> Option<String> {
    Command::new("git")
        .arg("-C")
        .arg(project_dir())
        .args(["log", "-1", "--pretty=%B"])
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|git_msg| git_msg.trim().to_string())
}
