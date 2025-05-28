use std::fmt::Debug;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::{env, fmt, fs, io};

use crate::error::{Error, Result};
use crate::library::Library;
use crate::{library, puffin};

pub fn from_env() -> VendorDir {
    VendorDir::from_env()
}

#[derive(Debug, Clone)]
pub struct VendorDir {
    path: PathBuf,
}

impl Default for VendorDir {
    fn default() -> Self {
        Self::from_env()
    }
}

impl fmt::Display for VendorDir {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.path.fmt(f)
    }
}

impl VendorDir {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        VendorDir { path: path.into() }
    }

    pub fn from_env() -> Self {
        let path = env::var("VENDOR_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| puffin::project_dir().join("vendor"));

        VendorDir::new(path)
    }
}

impl VendorDir {
    pub fn path(&self) -> &Path {
        self.path.as_path()
    }

    pub fn all(&self) -> Vec<Library> {
        let Ok(dir_entry) = self.path.read_dir() else {
            return vec![];
        };

        dir_entry
            .filter_map(|x| x.ok())
            .map(|x| x.path())
            .filter(|x| x.is_dir())
            .map(|x| x.file_name().unwrap().to_str().unwrap().to_string())
            .filter(|name| !name.starts_with("."))
            .filter_map(|name| self.library_dir(&name).ok())
            .filter_map(|library_dir| library_dir.library())
            .collect()
    }

    pub fn path_for(&self, name: impl AsRef<str>) -> PathBuf {
        self.path.join(name.as_ref())
    }

    pub fn library_dir(&self, name: impl AsRef<str>) -> Result<LibraryDir> {
        Ok(LibraryDir {
            vendor_dir: self,
            path: self.path_for(&name),
            lock: self.lock(&name)?,
        })
    }

    fn lock(&self, name: impl AsRef<str>) -> Result<nix::fcntl::Flock<File>> {
        let lock_dir = self.path.join(".lock");
        let lock_file = lock_dir.join(format!("vendor_lock_{}", name.as_ref()));

        std::fs::create_dir_all(lock_dir).map_err(|e| Error::VendorDirUnavailable {
            dir: self.clone(),
            reason: e,
        })?;

        nix::fcntl::Flock::lock(
            File::create(&lock_file).map_err(|e| Error::VendorDirUnavailable {
                dir: self.clone(),
                reason: e,
            })?,
            nix::fcntl::FlockArg::LockExclusiveNonblock,
        )
        .or_else(|(f, _)| {
            log::info!("waiting for lock on vendor config '{}'", name.as_ref());
            nix::fcntl::Flock::lock(f, nix::fcntl::FlockArg::LockExclusive)
        })
        .map_err(|(_, e)| Error::VendorDirUnavailable {
            dir: self.clone(),
            reason: io::Error::new(io::ErrorKind::Other, e),
        })
    }
}

#[derive(Debug)]
pub struct LibraryDir<'a> {
    vendor_dir: &'a VendorDir,
    path: PathBuf,

    #[allow(dead_code)]
    lock: nix::fcntl::Flock<File>,
}

impl<'a> LibraryDir<'a> {
    pub fn path(&self) -> &Path {
        self.path.as_path()
    }

    pub fn name(&self) -> String {
        self.path.file_name().unwrap().to_str().unwrap().to_string()
    }

    pub fn library(&self) -> Option<Library> {
        self.load_config()
            .zip(self.load_metadata())
            .map(|(config, metadata)| {
                Library::new(self.name(), config, metadata, self.vendor_dir.clone())
            })
    }

    pub fn contains(&self, config: &library::Config) -> bool {
        self.load_metadata().is_some() && self.load_config().as_ref() == Some(config)
    }

    pub fn remove(&self) -> Result<()> {
        std::fs::create_dir_all(self.path()).map_err(|e| Error::VendorDirUnavailable {
            dir: self.vendor_dir.clone(),
            reason: e,
        })?;

        std::fs::remove_dir_all(self.path()).map_err(|e| Error::VendorDirUnavailable {
            dir: self.vendor_dir.clone(),
            reason: e,
        })?;

        Ok(())
    }

    pub fn make(&self, config: impl AsRef<library::Config>, cput: bool) -> Result<PathBuf> {
        if self.contains(config.as_ref()) {
            return Ok(self.path.clone());
        }

        // NOTE ensure intermediate folders exist and there is no artifact from a previous build
        self.remove()?;

        config.as_ref().build(self.path(), cput).map(|_| {
            std::fs::write(
                self.config_file(),
                toml::to_string(config.as_ref()).unwrap(),
            )
            .ok();
            self.path().to_path_buf()
        })
    }

    fn load_metadata(&self) -> Option<library::Metadata> {
        if !self.metadata_file().try_exists().unwrap_or(false) {
            return None;
        }

        fs::read_to_string(self.metadata_file())
            .ok()
            .and_then(|content| toml::from_str::<library::Metadata>(&content).ok())
    }

    fn load_config(&self) -> Option<library::Config> {
        if !self.config_file().try_exists().unwrap_or(false) {
            return None;
        }

        fs::read_to_string(self.config_file())
            .ok()
            .and_then(|content| toml::from_str::<library::Config>(&content).ok())
    }

    fn config_file(&self) -> PathBuf {
        self.path.join(".vendor_config")
    }

    fn metadata_file(&self) -> PathBuf {
        self.path.join(".metadata")
    }
}
