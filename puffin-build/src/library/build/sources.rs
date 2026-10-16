use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::{Deserialize, Serialize};

use crate::utils::git;
use crate::{Error, Result};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Sources {
    Git {
        #[serde(flatten)]
        tree: git::Tree,
        version: String,
    },
    Url {
        url: String,
        hash: Option<String>,
        version: String,
    },
}

impl Sources {
    pub fn download(&self, dest_dir: impl AsRef<Path>) -> Result<PathBuf> {
        std::fs::create_dir_all(&dest_dir).map_err(|e| Error::SourcesDownloadFailed {
            sources: self.clone(),
            reason: e,
        })?;

        match self {
            Sources::Git { tree, .. } => git::archive(tree.clone()).to_dir(dest_dir),
            Sources::Url { url, hash, .. } => download_url(url, hash.as_deref(), dest_dir.as_ref()),
        }
        .map_err(|e| Error::SourcesDownloadFailed {
            sources: self.clone(),
            reason: e,
        })
    }

    pub fn version(&self) -> String {
        match self {
            Sources::Git { version, .. } | Sources::Url { version, .. } => version.clone(),
        }
    }
}

impl AsRef<Sources> for Sources {
    fn as_ref(&self) -> &Sources {
        self
    }
}

/// Download an archive from `url` into `dest_dir` and return the path of the archive.
///
/// If `hash` is provided (hex-encoded SHA-256, optionally prefixed by `sha256:`), the download is
/// verified against it. The archive itself is extracted by the builder (CMake `ExternalProject`).
fn download_url(url: &str, hash: Option<&str>, dest_dir: &Path) -> io::Result<PathBuf> {
    let file_name = url
        .rsplit('/')
        .next()
        .filter(|name| !name.is_empty())
        .ok_or_else(|| io::Error::other(format!("cannot infer a file name from url: {url}")))?;
    let archive_file = dest_dir.join(file_name);

    let status = Command::new("curl")
        .args([
            "--fail",
            "--silent",
            "--show-error",
            "--location",
            "--retry",
            "3",
        ])
        .arg("--output")
        .arg(&archive_file)
        .arg(url)
        .status()?;

    if !status.success() {
        return Err(io::Error::other(format!("failed to download: url={url}")));
    }

    if let Some(expected) = hash {
        let expected = expected.strip_prefix("sha256:").unwrap_or(expected);
        let actual = sha256_of(&archive_file)?;

        if !actual.eq_ignore_ascii_case(expected) {
            return Err(io::Error::other(format!(
                "hash mismatch for {url}: expected sha256={expected}, got sha256={actual}"
            )));
        }
    }

    Ok(archive_file)
}

fn sha256_of(file: &Path) -> io::Result<String> {
    // NOTE `sha256sum` is not available on every platform (e.g. macOS ships `shasum`)
    let output = [("sha256sum", &[][..]), ("shasum", &["-a", "256"][..])]
        .into_iter()
        .find_map(|(program, args)| {
            Command::new(program)
                .args(args)
                .arg(file)
                .output()
                .ok()
                .filter(|output| output.status.success())
        })
        .ok_or_else(|| io::Error::other("neither `sha256sum` nor `shasum` could be run"))?;

    String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .next()
        .map(str::to_owned)
        .ok_or_else(|| io::Error::other("unexpected output from sha256 tool"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const HELLO_SHA256: &str = "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03";

    #[test]
    fn sha256_matches_known_digest() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("hello.txt");
        std::fs::write(&file, "hello\n").unwrap();

        assert_eq!(sha256_of(&file).unwrap(), HELLO_SHA256);
    }

    #[test]
    fn download_verifies_hash() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("hello.txt");
        std::fs::write(&src, "hello\n").unwrap();
        let url = format!("file://{}", src.display());

        let dest = tempfile::tempdir().unwrap();
        let ok = download_url(&url, Some(&format!("sha256:{HELLO_SHA256}")), dest.path());
        assert!(ok.is_ok(), "{ok:?}");

        let bad = download_url(&url, Some(&"0".repeat(64)), dest.path());
        assert!(bad.unwrap_err().to_string().contains("hash mismatch"));
    }
}
