use std::process::{Command, ExitStatus};

pub fn get_git_ref() -> String {
    Command::new("git")
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
        .map(|git_ref| git_ref[..6].to_string())
        .unwrap_or_else(|| "unknown".to_string())
        .trim()
        .to_string()
}

pub fn get_git_msg() -> String {
    Command::new("git")
        .args(["log", "-1", "--pretty=%B"])
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .unwrap_or_else(|| "unknown".to_string())
        .trim()
        .to_string()
}

fn main() {
    println!("cargo:rustc-env=GIT_REF={}", get_git_ref());
    println!("cargo:rustc-env=GIT_MSG={}", get_git_msg());
}
