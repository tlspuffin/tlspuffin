use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};
use std::{fmt, io};

use serde::{Deserialize, Serialize};

pub fn archive(tree: impl Into<Tree>) -> GitArchive {
    GitArchive::new(tree)
}

pub fn clone(tree: impl Into<Tree>) -> GitClone {
    GitClone::new(tree)
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Tree {
    repo: Repo,
    #[serde(flatten)]
    #[serde(skip_serializing_if = "Head::is_default")]
    head: Head,
}

impl Tree {
    pub fn new(repo: impl Into<Repo>, head: impl Into<Head>) -> Self {
        Self {
            repo: repo.into(),
            head: head.into(),
        }
    }
}

impl From<Repo> for Tree {
    fn from(repo: Repo) -> Self {
        Self {
            repo,
            head: Head::Default,
        }
    }
}

impl From<&str> for Tree {
    fn from(repo: &str) -> Self {
        Self::from(Into::<Repo>::into(repo))
    }
}

impl fmt::Display for Tree {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}_{}", self.repo, self.head)
    }
}

#[derive(Debug, Default, PartialEq, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Head {
    #[default]
    Default,
    Branch(String),
    Commit(String),
}

impl Head {
    pub fn branch(name: impl AsRef<str>) -> Self {
        Self::Branch(name.as_ref().to_owned())
    }

    pub fn commit(hash: impl AsRef<str>) -> Self {
        Self::Commit(hash.as_ref().to_owned())
    }

    pub fn is_default(&self) -> bool {
        matches!(self, Self::Default)
    }
}

impl fmt::Display for Head {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Head::Default => f.write_str("default"),
            Head::Branch(b) => f.write_str(b),
            Head::Commit(c) => f.write_str(c),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Repo(String);

impl Repo {
    pub fn new(s: impl AsRef<str>) -> Self {
        Repo(s.as_ref().to_owned())
    }

    pub fn at(&self, head: impl Into<Head>) -> Tree {
        Tree::new(self.clone(), head)
    }

    pub fn at_commit(&self, id: impl Into<String>) -> Tree {
        Tree::new(self.clone(), Head::Commit(id.into()))
    }

    pub fn at_branch(&mut self, name: impl Into<String>) -> Tree {
        Tree::new(self.clone(), Head::Branch(name.into()))
    }

    pub fn at_default(&mut self) -> Tree {
        Tree::new(self.clone(), Head::Default)
    }
}

impl From<&str> for Repo {
    fn from(value: &str) -> Self {
        Self(value.into())
    }
}

impl fmt::Display for Repo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone)]
pub struct GitArchive {
    pub tree: Tree,
    format: String,
}

impl GitArchive {
    fn new(tree: impl Into<Tree>) -> Self {
        Self {
            tree: tree.into(),
            format: String::from("tar.gz"),
        }
    }

    pub fn to_dir(&self, path: impl AsRef<Path>) -> io::Result<PathBuf> {
        // NOTE using git-archive directly would be more efficient but is not supported by GitHub
        //
        // Running `git archive --remote=...` would allow us to efficiently download an archive
        // matching the requested head. Instead, we perform a shallow clone and then archive the
        // result.
        //
        // see also: https://docs.github.com/en/repositories/working-with-files/using-files/downloading-source-code-archives
        // see also: https://github.com/isaacs/github/issues/554

        let archive_file = path
            .as_ref()
            .join(format!("git.{}.{}", self.tree.head, self.format));
        let download_dir = tempfile::tempdir()?;

        clone(self.tree.clone()).shallow().to_dir(&download_dir)?;

        let mut cmd = Command::new("git");
        cmd.arg("-C").arg(download_dir.path()).arg("archive");
        cmd.arg(format!("--format={}", self.format));
        cmd.arg(format!("--output={}", archive_file.display()));
        cmd.arg("HEAD");

        cmd.status()?
            .success()
            .then_some(archive_file)
            .ok_or(io::Error::new(
                io::ErrorKind::Other,
                format!("failed git archive: tree={:?}", self.tree),
            ))
    }
}

#[derive(Debug, Clone)]
pub struct GitClone {
    pub tree: Tree,
    shallow: bool,
}

impl GitClone {
    pub fn new(tree: impl Into<Tree>) -> Self {
        Self {
            tree: tree.into(),
            shallow: false,
        }
    }

    pub fn shallow(&mut self) -> &mut Self {
        self.shallow = true;
        self
    }

    pub fn full(&mut self) -> &mut Self {
        self.shallow = false;
        self
    }

    pub fn to_dir(&self, path: impl AsRef<Path>) -> io::Result<()> {
        let status = match self.tree.head {
            Head::Default => self.do_clone_branch(Option::<&str>::None, path.as_ref()),
            Head::Branch(ref name) => self.do_clone_branch(Some(name), path.as_ref()),
            Head::Commit(ref id) => self.do_clone_commit(id, path.as_ref()),
        };

        status?.success().then_some(()).ok_or(io::Error::new(
            io::ErrorKind::Other,
            format!("failed git clone: tree={:?}", self.tree),
        ))
    }

    fn do_clone_branch(
        &self,
        maybe_name: Option<impl AsRef<OsStr>>,
        to: impl AsRef<OsStr>,
    ) -> io::Result<ExitStatus> {
        let mut cmd = Command::new("git");
        cmd.arg("clone");

        if let Some(name) = maybe_name {
            cmd.arg("--branch");
            cmd.arg(name.as_ref());
        }

        if self.shallow {
            cmd.arg("--depth=1");
        }

        cmd.arg(&self.tree.repo.0).arg(to.as_ref()).status()
    }

    fn do_clone_commit(
        &self,
        commit_id: impl AsRef<OsStr>,
        to: impl AsRef<OsStr>,
    ) -> io::Result<ExitStatus> {
        let mut cmd = Command::new("git");
        cmd.arg("clone");

        if self.shallow {
            cmd.arg("--filter=tree:0");
        }

        cmd.arg(&self.tree.repo.0).arg(to.as_ref()).status()?;

        Command::new("git")
            .current_dir(to.as_ref())
            .arg("checkout")
            .arg(commit_id)
            .status()
    }
}
