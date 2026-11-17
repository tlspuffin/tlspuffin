use std::fmt::Debug;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::{env, fmt, fs, io};

use crate::catalogue::LibraryState;
use crate::error::{Error, Result};
use crate::library::Library;
use crate::{catalogue, library, puffin};

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

    pub fn library_dir(&self, name: impl AsRef<str>) -> Result<LibraryDir<'_>> {
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
            reason: io::Error::other(e),
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

    pub fn make(&self, config: &library::Config, cput: bool) -> Result<PathBuf> {
        // the state of the catalogue entries is computed before the build: a build fails anyway
        // when the catalogue is invalid, and the state then records exactly what the build
        // applied
        let state = config
            .catalogue_state()
            .map_err(|e| Error::LibraryBuilderFailed {
                builder: config.builder().clone(),
                sources: self.path().join("src"),
                options: config.options().clone(),
                reason: io::Error::other(e),
            })?;

        // the same configuration, built with what the catalogue gives it now: nothing to do (a
        // library built before a patch or an entry it uses changed is built again)
        if self.contains(config) && same_state(self.load_state().as_ref(), state.as_ref()) {
            return Ok(self.path.clone());
        }

        // NOTE ensure intermediate folders exist and there is no artifact from a previous build
        self.remove()?;

        config.build(self.path(), cput)?;
        let unavailable = |reason| Error::VendorDirUnavailable {
            dir: self.vendor_dir.clone(),
            reason,
        };
        if let Some(state) = state {
            std::fs::write(self.path.join(catalogue::STATE_FILE), state.to_toml())
                .map_err(unavailable)?;
        }
        std::fs::write(self.config_file(), toml::to_string(config).unwrap())
            .map_err(unavailable)?;
        Ok(self.path().to_path_buf())
    }

    /// The catalogue state the build recorded (see [`catalogue::STATE_FILE`]).
    fn load_state(&self) -> Option<LibraryState> {
        let content = fs::read_to_string(self.path.join(catalogue::STATE_FILE)).ok()?;
        LibraryState::from_toml(&content).ok()
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

/// Whether a build recorded the catalogue state it would get now: the state of each entry and what
/// the build took from it (build hashes, patches), its derivation, vendor and version. The hash of
/// the whole catalogue is not compared: a change to another entry does not make the build stale.
fn same_state(recorded: Option<&LibraryState>, now: Option<&LibraryState>) -> bool {
    match (recorded, now) {
        (None, None) => true,
        (Some(r), Some(n)) => {
            r.vendor == n.vendor
                && r.version == n.version
                && r.derived == n.derived
                && r.entries == n.entries
                && r.library_patches == n.library_patches
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::catalogue::{EntryState, Status};

    fn state(hash: &str) -> LibraryState {
        LibraryState {
            vendor: "lib".into(),
            version: "1.0.0".into(),
            catalogue: "whole-catalogue".into(),
            derived: None,
            entries: BTreeMap::from([(
                "BUG-A".to_string(),
                EntryState {
                    state: Status::Active,
                    hash: hash.into(),
                    patches: vec![],
                },
            )]),
            library_patches: BTreeMap::new(),
        }
    }

    #[test]
    fn a_build_is_stale_when_what_it_took_from_the_catalogue_changed() {
        assert!(same_state(Some(&state("h1")), Some(&state("h1"))));
        // another entry of the catalogue changed: the whole catalogue's hash only
        let mut other = state("h1");
        other.catalogue = "another-catalogue".into();
        assert!(same_state(Some(&state("h1")), Some(&other)));
        // an entry it uses changed (its affected versions, options or patches)
        assert!(!same_state(Some(&state("h1")), Some(&state("h2"))));
        // built before the catalogue state was recorded
        assert!(!same_state(None, Some(&state("h1"))));
        // a vendor without catalogue
        assert!(same_state(None, None));
        // a patch of presets.toml for its version changed (the claims instrumentation), or was
        // added
        let mut patched = state("h1");
        patched
            .library_patches
            .insert("patches/claims.patch".into(), "p1".into());
        assert!(!same_state(Some(&state("h1")), Some(&patched)));
        let mut changed = patched.clone();
        changed
            .library_patches
            .insert("patches/claims.patch".into(), "p2".into());
        assert!(!same_state(Some(&patched), Some(&changed)));
        assert!(same_state(Some(&patched), Some(&patched.clone())));
    }

    #[test]
    fn the_state_of_a_build_records_the_patches_of_its_version() {
        // wolfSSL 5.5.2 takes the claims instrumentation of presets.toml, 5.4.0 none
        let state = |name: &str| {
            crate::library::Config::resolve("wolfssl", name)
                .unwrap()
                .catalogue_state()
                .unwrap()
                .unwrap()
        };
        let with = state("wolfssl552-asan");
        assert_eq!(
            with.library_patches.keys().cloned().collect::<Vec<_>>(),
            vec!["patches/claims-AllowClaim-552.patch".to_string()]
        );
        assert_eq!(with.library_patches.values().next().unwrap().len(), 64);
        assert!(state("wolfssl540-asan").library_patches.is_empty());
        // a state written before the field reads as without patches: stale, rebuilt once
        let mut before = with.clone();
        before.library_patches.clear();
        let text = before.to_toml();
        assert!(!text.contains("library_patches"), "{text}");
        let read: LibraryState = toml::from_str(&text).unwrap();
        assert!(!same_state(Some(&read), Some(&with)));
    }
}
